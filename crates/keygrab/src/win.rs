//! Cienka warstwa WinAPI: założenie i zdjęcie haka `WH_KEYBOARD_LL`, funkcja haka, odczyt okna
//! na pierwszym planie. Decyzje podejmuje `logic`. To jedyny moduł crate'a z `unsafe`.
//!
//! Hak żyje we własnym wątku z własną pętlą komunikatów. System woła funkcję haka w wątku, który
//! hak założył, i po cichu usuwa hak, gdy ta nie odpowie w limicie czasu (`LowLevelHooksTimeout`).
//! W wątku głównym aplikacji (okno i WebView2) wystarczyłoby do tego jedno przycięcie interfejsu;
//! klawisze systemowe wracają wtedy do systemu, a okno wysyła je do sesji zwykłą drogą, więc
//! działają po obu stronach naraz. Wątek haka nie robi nic poza odbieraniem komunikatów.
//!
//! Stan jest w jednym `static` za `Mutex`. Funkcja haka bierze go przez `try_lock` i gdy
//! blokada jest zajęta (a trzyma ją tylko `start` albo `stop`, przez chwilę), przepuszcza
//! zdarzenie do systemu, więc nigdy na nic nie czeka. `stop` kończy wątek haka i czeka na niego,
//! dopiero potem usuwa stan, więc po jego powrocie `sink` nie zostanie więcej wołany.
//!
//! Usunięcia haka przez system WinAPI nie zgłasza, więc `Released::HookLost` nie jest emitowane.
//! Gdyby mimo osobnego wątku do tego doszło, klawisze wracają do okna aplikacji i frontend wysyła
//! je do sesji zwykłą drogą; ponowne włączenie trybu (`start` po `stop`) zakłada hak od nowa.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Mutex, PoisonError, TryLockError};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{MAPVK_VK_TO_VSC_EX, MapVirtualKeyW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GA_ROOT, GetAncestor, GetForegroundWindow, GetMessageW, HC_ACTION,
    KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW,
    SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_QUIT, WM_USER,
};

use crate::logic::{Action, FLAG_EXTENDED, Logic, RawKey};
use crate::{Combo, Error, Event, Sink, Stats};

struct Hooked {
    logic: Logic,
    sink: Sink,
    /// Okno najwyższego poziomu (HWND jako liczba, żeby stan był `Send`).
    window: isize,
    stats: Stats,
}

static STATE: Mutex<Option<Hooked>> = Mutex::new(None);
/// Uchwyt haka (HHOOK); osobno od `STATE`, żeby `CallNextHookEx` nie wymagało blokady.
static HOOK: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
/// Odbicie `Logic::capturing` dla `active()`, czytane bez blokady.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Wątek haka: identyfikator dla `PostThreadMessageW` i uchwyt do czekania na koniec. Ta blokada
/// porządkuje `start` i `stop`; funkcja haka jej nie dotyka.
static THREAD: Mutex<Option<(u32, JoinHandle<()>)>> = Mutex::new(None);

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

pub fn start(window: isize, release: Option<Combo>, sink: Sink) -> Result<(), Error> {
    let mut thread = THREAD.lock().unwrap_or_else(PoisonError::into_inner);
    if thread.is_some() {
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
    // Stan musi istnieć przed założeniem haka, bo hak może zadziałać zaraz po jego założeniu.
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Hooked {
        logic: Logic::new(release),
        sink,
        window,
        stats: Stats::default(),
    });
    let (ready_tx, ready_rx) = sync_channel(1);
    let started = match std::thread::Builder::new()
        .name("keygrab".into())
        .spawn(move || hook_thread(ready_tx))
    {
        // Wątek zgłasza wynik założenia haka; czekamy na niego, żeby błąd wrócił do wywołującego.
        Ok(handle) => match ready_rx.recv() {
            Ok(Ok(id)) => Ok((id, handle)),
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = handle.join();
                Err(Error::HookFailed(0))
            }
        },
        Err(e) => Err(Error::HookFailed(e.raw_os_error().unwrap_or(0))),
    };
    match started {
        Ok(running) => {
            *thread = Some(running);
            ACTIVE.store(true, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            clear_state();
            Err(e)
        }
    }
}

pub fn stop() -> Option<Stats> {
    let mut thread = THREAD.lock().unwrap_or_else(PoisonError::into_inner);
    ACTIVE.store(false, Ordering::Release);
    if let Some((id, handle)) = thread.take() {
        // Wątek, który już się skończył (błąd pętli komunikatów), nie dostaje komunikatu: jego
        // identyfikator mógł przejść na inny wątek.
        // SAFETY: PostThreadMessageW nie ma wymagań wobec pamięci; kolejka komunikatów wątku
        // istnieje, bo wątek tworzy ją przed zgłoszeniem gotowości.
        if handle.is_finished() || unsafe { PostThreadMessageW(id, WM_QUIT, 0, 0) } != 0 {
            // Wątek zdejmuje hak sam, wychodząc z pętli; czekanie kończy się po co najwyżej
            // jednym trwającym wywołaniu haka.
            let _ = handle.join();
        }
        // Komunikat nie doszedł (pełna kolejka): wątek zostaje, a hak zdejmujemy niżej.
    }
    unhook();
    drop(thread);
    clear_state()
}

/// Zdejmuje hak, jeśli jeszcze istnieje.
fn unhook() {
    let hook = HOOK.swap(null_mut(), Ordering::AcqRel);
    if !hook.is_null() {
        // SAFETY: `hook` to uchwyt zwrócony przez SetWindowsHookExW i zdjęty z `HOOK` dokładnie
        // raz (swap), więc nie zdejmujemy go dwa razy. Gdy system usunął hak sam, funkcja
        // zwraca błąd, który tu świadomie ignorujemy (stop ma być idempotentne).
        let _ = unsafe { UnhookWindowsHookEx(hook) };
    }
}

/// Usuwa stan i zwraca jego liczniki; odbiorca jest zwalniany poza blokadą.
fn clear_state() -> Option<Stats> {
    let taken = STATE.lock().unwrap_or_else(PoisonError::into_inner).take();
    taken.map(|hooked| hooked.stats)
}

/// Wątek haka: zakłada hak, zgłasza wynik przez `ready` i odbiera komunikaty do `WM_QUIT`.
/// System woła `hook_proc` z wnętrza `GetMessageW`, więc pętla nie musi niczego rozsyłać.
fn hook_thread(ready: SyncSender<Result<u32, Error>>) {
    let mut msg = MSG::default();
    // SAFETY: `msg` to ważna, wyłączna struktura MSG. Wywołanie niczego nie zdejmuje z kolejki;
    // służy temu, żeby system utworzył kolejkę komunikatów wątku przed zgłoszeniem gotowości
    // (bez niej PostThreadMessageW z `stop` by się nie powiodło).
    unsafe { PeekMessageW(&mut msg, null_mut(), WM_USER, WM_USER, PM_NOREMOVE) };
    // SAFETY: NULL jako nazwa modułu oznacza plik wykonywalny procesu; funkcja nie czyta
    // żadnej pamięci wywołującego i nie zmienia liczników odwołań modułu.
    let module = unsafe { GetModuleHandleW(null()) };
    // SAFETY: `hook_proc` ma sygnaturę HOOKPROC (`extern "system"`, trzy argumenty, LRESULT) i
    // żyje przez cały czas działania procesu; `module` to uchwyt modułu procesu, a dla haka
    // WH_KEYBOARD_LL parametr wątku musi być 0 (hak globalny, wołany w tym wątku).
    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), module, 0) };
    if hook.is_null() {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let _ = ready.send(Err(Error::HookFailed(code)));
        return;
    }
    HOOK.store(hook, Ordering::Release);
    // SAFETY: funkcja bez argumentów i bez wymagań.
    let id = unsafe { GetCurrentThreadId() };
    if ready.send(Ok(id)).is_ok() {
        // SAFETY: `msg` to ważna, wyłączna struktura MSG; NULL jako okno oznacza wszystkie
        // komunikaty wątku. Wynik 0 to WM_QUIT, a -1 błąd: oba kończą pętlę.
        while unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) } > 0 {}
    }
    unhook();
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
    let mut raw = RawKey {
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
    hooked.stats.calls += 1;
    if raw.flags & LLKHF_INJECTED != 0 {
        hooked.stats.injected += 1;
    }
    if raw.flags & FLAG_EXTENDED != 0 {
        hooked.stats.extended += 1;
    }
    if raw.scancode == 0 {
        // Zdarzenie wstrzyknięte samym kodem wirtualnym: scancode bierzemy z układu klawiatury,
        // inaczej klawisz szedłby do systemu zamiast do sesji.
        hooked.stats.no_scancode += 1;
        // SAFETY: MapVirtualKeyW przyjmuje dowolne liczby i nie ma wymagań wobec pamięci.
        raw = raw.with_mapped_scancode(unsafe { MapVirtualKeyW(raw.vk, MAPVK_VK_TO_VSC_EX) });
    }
    // SAFETY: GetForegroundWindow nie ma argumentów ani wymagań; wynik porównujemy tylko jako
    // liczbę (okno mogło zniknąć, ale nie dereferencjujemy uchwytu).
    let foreground = unsafe { GetForegroundWindow() } as isize == hooked.window;
    let Hooked {
        logic, sink, stats, ..
    } = hooked;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut emit = |e: Event| sink(e);
        logic.handle(raw, foreground, &mut emit)
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
    match action {
        Action::Swallow => stats.swallowed += 1,
        Action::Pass => stats.passed += 1,
    }
    action == Action::Swallow
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::time::Duration;

    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, SendInput,
        VK_F13,
    };

    use super::*;
    use crate::Key;

    /// Scancode klawisza F13 (zestaw 1): na maszynie testowej nic na niego nie reaguje.
    const F13: u8 = 0x64;

    /// Wstrzykuje jedno zdarzenie klawisza. Zwraca false, gdy system go nie przyjął (sesja bez
    /// pulpitu interaktywnego).
    fn inject(vk: u16, scan: u16, flags: u32) -> bool {
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        // SAFETY: wskaźnik wskazuje jedną ważną strukturę INPUT, a rozmiar jest jej rozmiarem.
        unsafe { SendInput(1, &input, size_of::<INPUT>() as i32) == 1 }
    }

    /// Wypisuje wynik prosto na stderr, z pominięciem przechwytywania wyjścia testów: z samego
    /// "ok" nie widać, czy hak został sprawdzony, czy test się pominął.
    fn report(text: &str) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "keygrab: {text}");
    }

    /// Hak na prawdziwym systemie: wstrzyknięte klawisze mają zostać zatrzymane i trafić do
    /// odbiorcy, także te bez scancodu (sam kod wirtualny).
    #[test]
    fn injected_keys_are_swallowed_and_forwarded() {
        let (tx, rx) = channel();
        // Okno na pierwszym planie w chwili testu; bez żadnego okna po obu stronach porównania
        // jest NULL.
        // SAFETY: funkcja bez argumentów i bez wymagań.
        let window = unsafe { GetForegroundWindow() } as isize;
        start(
            window,
            None,
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
        )
        .expect("hak klawiatury");
        if !inject(0, u16::from(F13), KEYEVENTF_SCANCODE) {
            stop();
            report("test haka pominięty: system nie przyjął wstrzykniętego klawisza");
            return;
        }
        let wait = Duration::from_secs(5);
        let key = |down| {
            Some(Event::Key(Key {
                scancode: F13,
                extended: false,
                down,
            }))
        };
        assert_eq!(rx.recv_timeout(wait).ok(), key(true));
        assert!(inject(
            0,
            u16::from(F13),
            KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
        ));
        assert_eq!(rx.recv_timeout(wait).ok(), key(false));
        // Sam kod wirtualny, bez scancodu.
        assert!(inject(VK_F13, 0, 0));
        assert_eq!(rx.recv_timeout(wait).ok(), key(true));
        assert!(inject(VK_F13, 0, KEYEVENTF_KEYUP));
        assert_eq!(rx.recv_timeout(wait).ok(), key(false));
        let stats = stop().expect("liczniki haka");
        assert!(stats.calls >= 4, "{stats:?}");
        assert!(stats.swallowed >= 4, "{stats:?}");
        assert!(stats.injected >= 4, "{stats:?}");
        report(&format!("hak sprawdzony na prawdziwym systemie: {stats:?}"));

        // Prawy Shift: system oznacza go jako klawisz rozszerzony, a do sesji ma trafić bez tego
        // znacznika. Osobne założenie haka, żeby liczniki dotyczyły tylko tego klawisza.
        let (tx, rx) = channel();
        start(
            window,
            None,
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
        )
        .expect("hak klawiatury");
        let shift = |down| {
            Some(Event::Key(Key {
                scancode: 0x36,
                extended: false,
                down,
            }))
        };
        assert!(inject(0, 0x36, KEYEVENTF_SCANCODE));
        assert_eq!(rx.recv_timeout(wait).ok(), shift(true));
        assert!(inject(0, 0x36, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP));
        assert_eq!(rx.recv_timeout(wait).ok(), shift(false));
        let stats = stop().expect("liczniki haka");
        report(&format!("prawy Shift na prawdziwym systemie: {stats:?}"));
    }
}
