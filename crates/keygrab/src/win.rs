//! Cienka warstwa WinAPI: założenie i zdjęcie haka `WH_KEYBOARD_LL`, funkcja haka, odczyt okna
//! na pierwszym planie. Decyzje podejmuje `logic`. To jedyny moduł crate'a z `unsafe`.
//!
//! Stan jest w jednym `static` za `Mutex`. Funkcja haka bierze go przez `try_lock` i gdy
//! blokada jest zajęta (a trzyma ją tylko `start` albo `stop`, przez chwilę), przepuszcza
//! zdarzenie do systemu, więc nigdy na nic nie czeka. `stop` bierze zwykłą blokadę: poczeka
//! najwyżej na jedno trwające wywołanie haka, a po jej zdjęciu stanu już nie ma, więc `sink`
//! nie zostanie więcej wołany.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GA_ROOT, GetAncestor, GetForegroundWindow, HC_ACTION, KBDLLHOOKSTRUCT,
    SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL,
};

use crate::logic::{Action, Logic, RawKey};
use crate::{Combo, Error, Event, Released, Sink};

/// Wywołanie dłuższe niż to uznajemy za zagrożone usunięciem haka przez system (limit
/// `LowLevelHooksTimeout`, domyślnie ok. 300 ms).
const SLOW_CALL: Duration = Duration::from_millis(250);

struct Hooked {
    logic: Logic,
    sink: Sink,
    /// Okno najwyższego poziomu (HWND jako liczba, żeby stan był `Send`).
    window: isize,
}

static STATE: Mutex<Option<Hooked>> = Mutex::new(None);
/// Uchwyt haka (HHOOK); osobno od `STATE`, żeby `CallNextHookEx` nie wymagało blokady.
static HOOK: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
/// Odbicie `Logic::capturing` dla `active()`, czytane bez blokady.
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

pub fn start(window: isize, release: Option<Combo>, sink: Sink) -> Result<(), Error> {
    let mut guard = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    if guard.is_some() {
        return Err(Error::AlreadyActive);
    }
    // SAFETY: GetAncestor przyjmuje dowolną wartość HWND i dla nieprawidłowego uchwytu zwraca
    // NULL, nie ma żadnych wymagań wobec pamięci.
    let root = unsafe { GetAncestor(window as HWND, GA_ROOT) };
    let window = if root.is_null() {
        window
    } else {
        root as isize
    };
    // SAFETY: NULL jako nazwa modułu oznacza plik wykonywalny procesu; funkcja nie czyta
    // żadnej pamięci wywołującego i nie zmienia liczników odwołań modułu.
    let module = unsafe { GetModuleHandleW(null()) };
    // Stan musi istnieć przed założeniem haka, bo hak może zadziałać zaraz po jego założeniu.
    *guard = Some(Hooked {
        logic: Logic::new(release),
        sink,
        window,
    });
    // SAFETY: `hook_proc` ma sygnaturę HOOKPROC (`extern "system"`, trzy argumenty, LRESULT) i
    // żyje przez cały czas działania procesu; `module` to uchwyt modułu procesu, a dla haka
    // WH_KEYBOARD_LL parametr wątku musi być 0 (hak globalny, wołany w tym wątku).
    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), module, 0) };
    if hook.is_null() {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        *guard = None;
        return Err(Error::HookFailed(code));
    }
    HOOK.store(hook, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    Ok(())
}

pub fn stop() {
    let taken = {
        let mut guard = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        ACTIVE.store(false, Ordering::Release);
        let hook = HOOK.swap(null_mut(), Ordering::AcqRel);
        if !hook.is_null() {
            // SAFETY: `hook` to uchwyt zwrócony przez SetWindowsHookExW i zdjęty z `HOOK` dokładnie
            // raz (swap), więc nie zdejmujemy go dwa razy. Gdy system usunął hak sam, funkcja
            // zwraca błąd, który tu świadomie ignorujemy (stop ma być idempotentne).
            let _ = unsafe { UnhookWindowsHookEx(hook) };
        }
        guard.take()
    };
    // Odbiorca jest zwalniany poza blokadą.
    drop(taken);
}

/// Funkcja haka. Musi wracać natychmiast: bez blokowania, bez alokacji, bez czekania na blokadę.
unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // Przy `code < 0` system wymaga przekazania dalej bez przetwarzania.
    // SAFETY: dla `code == HC_ACTION` system przekazuje w `lparam` wskaźnik na ważną strukturę
    // KBDLLHOOKSTRUCT (wywołanie `handle` spełnia jej wymóg); NULL odrzuca warunek.
    if code == HC_ACTION as i32 && lparam != 0 && unsafe { handle(lparam) } {
        return 1;
    }
    // SAFETY: argumenty są dokładnie tymi, które dostaliśmy od systemu; uchwyt haka bywa NULL
    // (po `stop`), a dokumentacja mówi, że CallNextHookEx go ignoruje.
    unsafe { CallNextHookEx(HOOK.load(Ordering::Acquire), code, wparam, lparam) }
}

/// Zwraca true, gdy zdarzenie ma zostać zatrzymane.
///
/// # Safety
/// `lparam` musi być wskaźnikiem na ważną strukturę `KBDLLHOOKSTRUCT`, żyjącą przez czas wywołania.
unsafe fn handle(lparam: LPARAM) -> bool {
    // SAFETY: wymóg przejęty od wywołującego (patrz `# Safety`); kopiujemy z struktury pola i nie
    // trzymamy referencji dłużej.
    let info = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
    let raw = RawKey {
        vk: info.vkCode,
        scancode: info.scanCode,
        flags: info.flags,
    };
    let mut guard = match STATE.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        // `start` albo `stop` właśnie trwa: nie czekamy.
        Err(TryLockError::WouldBlock) => return false,
    };
    let Some(hooked) = guard.as_mut() else {
        return false;
    };
    if !hooked.logic.capturing() {
        return false;
    }
    let started = Instant::now();
    // SAFETY: GetForegroundWindow nie ma argumentów ani wymagań; wynik porównujemy tylko jako
    // liczbę (okno mogło zniknąć, ale nie dereferencjujemy uchwytu).
    let foreground = unsafe { GetForegroundWindow() } as isize == hooked.window;
    let Hooked { logic, sink, .. } = hooked;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut emit = |e: Event| sink(e);
        let action = logic.handle(raw, foreground, &mut emit);
        // Wywołanie, które trwało blisko limitu systemowego, mogło kosztować nas hak: zwalniamy
        // klawisze i zgłaszamy utratę, wywołujący zdecyduje o ponownym założeniu.
        if logic.capturing() && started.elapsed() > SLOW_CALL {
            logic.release_all(Released::HookLost, &mut emit);
            return Action::Pass;
        }
        action
    }));
    let action = match outcome {
        Ok(a) => a,
        Err(_) => {
            // Panika w odbiorcy nie może przejść przez granicę `extern "system"`.
            logic.disarm();
            Action::Pass
        }
    };
    if !logic.capturing() {
        ACTIVE.store(false, Ordering::Release);
    }
    action == Action::Swallow
}
