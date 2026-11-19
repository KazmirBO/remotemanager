//! Przechwytywanie klawiszy systemowych (Win, Alt+Tab itp.) przez sesję RDP.
//!
//! Linux: przejęcie klawiatury przez GDK na głównym oknie, tylko na Waylandzie, gdzie wstrzymuje to
//! skróty kompozytora i jest związane z fokusem powierzchni. Na X11 przejęcie zostaje aktywne po
//! kliknięciu innego okna, a GDK nie zgłasza wtedy utraty fokusu, więc tekst wpisywany w innym
//! programie (np. hasło) trafiałby do zdalnej sesji; tam komenda zwraca `system: false`. Windows: niskopoziomowy hak klawiatury z crate'a `keygrab`. Inne platformy tego
//! nie potrafią: komenda kończy się wtedy sukcesem z `system: false`, a frontend i tak przechwytuje
//! skróty aplikacji.
//!
//! Przechwytywanie należy do jednej sesji i kończy się razem z nią (`release_for`), a także przy
//! blokadzie pliku i przeładowaniu interfejsu (`release_all` w `close_all_sessions`), niezależnie
//! od tego, czy interfejs zdąży je wyłączyć.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use uuid::Uuid;

use crate::state::AppState;

/// Zwolnienie przechwytywania. Nie blokuje: platforma wykonuje właściwą pracę w wątku głównym.
pub type Release = Box<dyn FnOnce() + Send>;

/// Skrót zwalniający przechwytywanie, jak go wysyła frontend (scancody zestawu 1).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ReleaseCombo {
    scancode: u8,
    extended: bool,
    ctrl: bool,
    alt: bool,
    shift: bool,
    meta: bool,
}

impl ReleaseCombo {
    fn into_combo(self) -> keygrab::Combo {
        keygrab::Combo {
            scancode: self.scancode,
            extended: self.extended,
            ctrl: self.ctrl,
            alt: self.alt,
            shift: self.shift,
            meta: self.meta,
        }
    }
}

/// Wynik włączenia: czy przejęto klawisze systemowe.
#[derive(Debug, Serialize)]
pub struct GrabResult {
    pub system: bool,
}

struct Holder {
    session: Uuid,
    /// Numer nadany przy `set`: pozwala zwolnić tylko własne przechwytywanie (`release_generation`).
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    generation: u64,
    release: Release,
}

/// Kto przechwytuje klawisze (najwyżej jedna sesja) i jak to przechwytywanie zwolnić.
#[derive(Default)]
pub struct Grabs {
    /// Serializuje włączanie i wyłączanie (praca w wątku głównym trwa między krokami).
    gate: tokio::sync::Mutex<()>,
    holder: Mutex<Option<Holder>>,
    /// Licznik generacji przechwytywań (rośnie przy każdym `set`).
    next_generation: AtomicU64,
}

impl Grabs {
    /// Zapamiętuje przechwytywanie sesji; poprzednie (jeśli jest) zostaje najpierw zwolnione.
    /// Zwraca numer generacji tego przechwytywania.
    pub fn set(&self, session: Uuid, release: Release) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let old = self.holder.lock().expect("keys").replace(Holder {
            session,
            generation,
            release,
        });
        if let Some(old) = old {
            (old.release)();
        }
        generation
    }

    /// Zwalnia przechwytywanie tylko wtedy, gdy nadal należy do tej sesji i ma tę generację. Spóźnione
    /// zdarzenie starego wątku przekazującego nie zwolni nowego przechwytywania tej samej sesji.
    #[cfg(any(windows, test))]
    pub fn release_generation(&self, session: Uuid, generation: u64) -> bool {
        let mut guard = self.holder.lock().expect("keys");
        if guard
            .as_ref()
            .is_some_and(|h| h.session == session && h.generation == generation)
        {
            let holder = guard.take();
            drop(guard);
            if let Some(h) = holder {
                (h.release)();
            }
            return true;
        }
        false
    }

    /// Zwalnia przechwytywanie, jeśli należy do tej sesji. Zwraca, czy coś zwolniono.
    pub fn release_for(&self, session: Uuid) -> bool {
        let mut guard = self.holder.lock().expect("keys");
        if guard.as_ref().is_some_and(|h| h.session == session) {
            let holder = guard.take();
            drop(guard);
            if let Some(h) = holder {
                (h.release)();
            }
            return true;
        }
        false
    }

    /// Zwalnia przechwytywanie bez względu na sesję. Zwraca, czy coś zwolniono.
    pub fn release_all(&self) -> bool {
        let holder = self.holder.lock().expect("keys").take();
        match holder {
            Some(h) => {
                (h.release)();
                true
            }
            None => false,
        }
    }
}

/// Nazwa powodu zwolnienia w zdarzeniu `rdp-keys-released`.
#[cfg(any(windows, test))]
fn reason_name(reason: keygrab::Released) -> &'static str {
    match reason {
        keygrab::Released::Combo => "combo",
        keygrab::Released::Foreground => "foreground",
        keygrab::Released::HookLost => "hook_lost",
    }
}

/// Przekazuje zdarzenia haka: klawisze do `send_key`, a po `Released` woła `on_released` i kończy.
/// Pętla kończy się też, gdy źródło zdarzeń się skończy (hak zdjęty).
#[cfg(any(windows, test))]
fn forward_events(
    events: impl IntoIterator<Item = keygrab::Event>,
    mut send_key: impl FnMut(keygrab::Key),
    on_released: impl FnOnce(keygrab::Released),
) {
    for event in events {
        match event {
            keygrab::Event::Key(key) => send_key(key),
            keygrab::Event::Released(reason) => {
                on_released(reason);
                return;
            }
        }
    }
}

/// Ładunek zdarzenia `rdp-keys-released`.
#[cfg(windows)]
#[derive(Serialize, Clone)]
struct ReleasedPayload {
    id: Uuid,
    reason: &'static str,
}

/// Linux: przejęcie klawiatury przez GDK. Możliwości muszą być dokładnie `KEYBOARD`: GDK na
/// Waylandzie wstrzymuje skróty kompozytora tylko wtedy, gdy możliwości są równe tej wartości
/// (każda inna kombinacja, np. z wskaźnikiem, nie daje błędu, ale też nie wstrzymuje skrótów).
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use gtk::gdk::prelude::SeatExt;
    use gtk::gdk::{GrabStatus, SeatCapabilities};
    use gtk::glib::prelude::ObjectExt;
    use gtk::prelude::WidgetExt;
    use tauri::Manager;

    /// Okno GDK głównego okna i domyślne gniazdo wejścia. Tylko w wątku głównym.
    fn seat_and_window(app: &AppHandle) -> Option<(gtk::gdk::Seat, gtk::gdk::Window)> {
        let window = app
            .get_webview_window("main")?
            .gtk_window()
            .ok()?
            .window()?;
        let seat = window.display().default_seat()?;
        Some((seat, window))
    }

    /// Czy okno działa na Waylandzie. Nazwa typu wyświetlacza jak w `DisplayExtManual::backend`
    /// (gdk 0.18), ale bez paniki dla nieznanego zaplecza.
    fn is_wayland(window: &gtk::gdk::Window) -> bool {
        window.display().type_().name() == "GdkWaylandDisplay"
    }

    fn grab(app: &AppHandle) -> bool {
        let Some((seat, window)) = seat_and_window(app) else {
            return false;
        };
        // X11: przejęcie przetrwałoby zmianę fokusu bez wiedzy okna (patrz opis modułu).
        if !is_wayland(&window) {
            return false;
        }
        seat.grab(&window, SeatCapabilities::KEYBOARD, true, None, None, None)
            == GrabStatus::Success
    }

    fn ungrab(app: &AppHandle) {
        if let Some((seat, _)) = seat_and_window(app) {
            seat.ungrab();
        }
    }

    /// Przejmuje klawiaturę i rejestruje zwolnienie. Zwraca `true` tylko dla `GrabStatus::Success`.
    pub async fn engage(app: &AppHandle, session: Uuid, _release: Option<keygrab::Combo>) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let a = app.clone();
        if app
            .run_on_main_thread(move || {
                let _ = tx.send(grab(&a));
            })
            .is_err()
        {
            return false;
        }
        if !rx.await.unwrap_or(false) {
            return false;
        }
        let a = app.clone();
        let release: Release = Box::new(move || {
            let b = a.clone();
            let _ = a.run_on_main_thread(move || ungrab(&b));
        });
        let _ = tauri::Manager::state::<AppState>(app)
            .keys
            .set(session, release);
        true
    }
}

/// Windows: hak `WH_KEYBOARD_LL` z crate'a `keygrab`, który trzyma go we własnym wątku z pętlą
/// komunikatów (hak w wątku głównym system może zdjąć po cichu przy przycięciu interfejsu). Hak
/// działa tylko dlatego, że `main.rs` wyłącza rejestrację surowego wejścia klawiatury
/// (`device_event_filter`): z nią system nie woła haka własnego procesu przy aktywnym oknie. Etapy
/// trafiają do dziennika diagnostycznego jako `RDP: klawisze systemowe: ...`, bez treści klawiszy.
#[cfg(windows)]
mod platform {
    use super::*;
    use rdp::ToWorker;
    use tauri::{Emitter, Manager};

    pub async fn engage(app: &AppHandle, session: Uuid, release: Option<keygrab::Combo>) -> bool {
        let state = app.state::<AppState>();
        let Some(client) = state.rdp.lock().expect("rdp").get(&session).cloned() else {
            return false;
        };
        let Some(window) = app
            .get_webview_window("main")
            .and_then(|w| w.hwnd().ok())
            .map(|h| h.0 as isize)
        else {
            state.log("RDP: klawisze systemowe: nie znaleziono okna głównego");
            return false;
        };
        // `sink` jest wołany z funkcji haka: tylko wkłada zdarzenie do kolejki, bez blokowania.
        let (events_tx, events_rx) = std::sync::mpsc::channel::<keygrab::Event>();
        let sink: keygrab::Sink = Box::new(move |e| {
            let _ = events_tx.send(e);
        });
        let (tx, rx) = tokio::sync::oneshot::channel();
        if app
            .run_on_main_thread(move || {
                let _ = tx.send(keygrab::start(window, release, sink));
            })
            .is_err()
        {
            return false;
        }
        match rx.await {
            Ok(Ok(())) => state.log("RDP: klawisze systemowe: hak założony"),
            Ok(Err(e)) => {
                state.log(format!("RDP: klawisze systemowe: {e}"));
                return false;
            }
            Err(_) => return false,
        }
        let a = app.clone();
        let release_fn: Release = Box::new(move || {
            let b = a.clone();
            let _ = a.run_on_main_thread(move || {
                // Liczniki odróżniają hak, którego system nie woła (zero wywołań), od haka, który
                // przepuszcza zdarzenia do systemu.
                if let Some(s) = keygrab::stop() {
                    b.state::<AppState>().log(format!(
                        "RDP: klawisze systemowe: liczniki haka: wywołań {}, zatrzymanych {}, przepuszczonych {}, bez scancodu {}, wstrzykniętych {}",
                        s.calls, s.swallowed, s.passed, s.no_scancode, s.injected
                    ));
                }
            });
        });
        // Zwolnienie musi być zarejestrowane, zanim ruszy pętla przekazująca zdarzenia.
        let generation = state.keys.set(session, release_fn);
        let app = app.clone();
        std::thread::spawn(move || {
            // Liczba przekazanych zdarzeń idzie do dziennika: zero przy zwolnieniu oznacza hak,
            // który zwolnił się na pierwszym klawiszu.
            let sent = std::cell::Cell::new(0u64);
            let released = std::cell::Cell::new(false);
            forward_events(
                events_rx,
                |k| {
                    sent.set(sent.get() + 1);
                    // Klawisze z haka nie docierają do okna, więc aktywność zgłaszamy tutaj.
                    app.state::<AppState>().touch_activity();
                    let _ = client.send(&ToWorker::Key {
                        scancode: k.scancode,
                        extended: k.extended,
                        down: k.down,
                    });
                },
                |reason| {
                    released.set(true);
                    app.state::<AppState>().log(format!(
                        "RDP: klawisze systemowe: hak zwolnił przechwytywanie (powód: {}), przekazanych zdarzeń: {}",
                        reason_name(reason),
                        sent.get()
                    ));
                    // Zdarzenie tylko wtedy, gdy przechwytywanie nadal jest tym samym (sesja i
                    // generacja); zwolnione z zewnątrz albo zastąpione nowszym nie zgłasza powodu.
                    if app
                        .state::<AppState>()
                        .keys
                        .release_generation(session, generation)
                    {
                        let _ = app.emit(
                            "rdp-keys-released",
                            ReleasedPayload {
                                id: session,
                                reason: reason_name(reason),
                            },
                        );
                    }
                },
            );
            if !released.get() {
                app.state::<AppState>().log(format!(
                    "RDP: klawisze systemowe: hak zdjęty, przekazanych zdarzeń: {}",
                    sent.get()
                ));
            }
        });
        true
    }
}

/// Pozostałe platformy: bez przejęcia klawiszy systemowych.
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::*;

    pub async fn engage(
        _app: &AppHandle,
        _session: Uuid,
        _release: Option<keygrab::Combo>,
    ) -> bool {
        false
    }
}

/// Włącza albo wyłącza przechwytywanie klawiszy systemowych dla sesji RDP. Włączenie zwalnia
/// przechwytywanie poprzedniej sesji. `system` mówi, czy klawisze systemowe zostały przejęte.
#[tauri::command]
pub async fn rdp_grab_keys(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    on: bool,
    release: Option<ReleaseCombo>,
) -> Result<GrabResult, String> {
    let _gate = state.keys.gate.lock().await;
    if !on {
        state.keys.release_for(id);
        return Ok(GrabResult { system: false });
    }
    if !state.rdp.lock().expect("rdp").contains_key(&id) {
        return Err("Sesja już nie istnieje.".into());
    }
    // Ponowne włączenie (np. ze zmienionym skrótem) zaczyna od zwolnienia poprzedniego.
    state.keys.release_all();
    let system = platform::engage(&app, id, release.map(ReleaseCombo::into_combo)).await;
    // Sesja mogła się skończyć w trakcie włączania, a jej sprzątanie nie zdążyło zwolnić tego,
    // czego jeszcze nie zarejestrowano.
    if system && !state.rdp.lock().expect("rdp").contains_key(&id) {
        state.keys.release_for(id);
        return Ok(GrabResult { system: false });
    }
    Ok(GrabResult { system })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting() -> (Arc<AtomicUsize>, Release) {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        (
            n,
            Box::new(move || {
                n2.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    #[test]
    fn grab_belongs_to_one_session_and_is_released_once() {
        let grabs = Grabs::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(!grabs.release_for(a) && !grabs.release_all());
        let (na, ra) = counting();
        grabs.set(a, ra);
        // Cudza sesja nie zwalnia.
        assert!(!grabs.release_for(b));
        assert_eq!(na.load(Ordering::SeqCst), 0);
        // Włączenie dla innej sesji najpierw zwalnia poprzednią.
        let (nb, rb) = counting();
        grabs.set(b, rb);
        assert_eq!(na.load(Ordering::SeqCst), 1);
        assert!(grabs.release_for(b));
        assert!(!grabs.release_for(b), "drugi raz nie zwalnia");
        assert_eq!(nb.load(Ordering::SeqCst), 1);
        let (nc, rc) = counting();
        grabs.set(a, rc);
        assert!(grabs.release_all());
        assert!(!grabs.release_all());
        assert_eq!(nc.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_generation_does_not_release_a_newer_grab_of_the_same_session() {
        let grabs = Grabs::default();
        let a = Uuid::new_v4();
        let (n1, r1) = counting();
        let g1 = grabs.set(a, r1);
        // Ponowne włączenie tej samej sesji zwalnia stare i nadaje nową generację.
        let (n2, r2) = counting();
        let g2 = grabs.set(a, r2);
        assert_ne!(g1, g2);
        assert_eq!(n1.load(Ordering::SeqCst), 1);
        // Spóźnione zwolnienie ze starego wątku nic nie robi.
        assert!(!grabs.release_generation(a, g1));
        assert_eq!(n2.load(Ordering::SeqCst), 0);
        assert!(!grabs.release_generation(Uuid::new_v4(), g2));
        assert!(grabs.release_generation(a, g2));
        assert!(!grabs.release_generation(a, g2));
        assert_eq!(n2.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn frontend_combo_converts_to_keygrab_combo() {
        let c: ReleaseCombo = serde_json::from_str(
            r#"{"scancode":1,"extended":true,"ctrl":true,"alt":false,"shift":true,"meta":false}"#,
        )
        .unwrap();
        assert_eq!(
            c.into_combo(),
            keygrab::Combo {
                scancode: 1,
                extended: true,
                ctrl: true,
                alt: false,
                shift: true,
                meta: false,
            }
        );
        // `null` od frontendu to brak skrótu; poza zakresem scancode jest błędem.
        assert!(
            serde_json::from_str::<Option<ReleaseCombo>>("null")
                .unwrap()
                .is_none()
        );
        assert!(
            serde_json::from_str::<ReleaseCombo>(
                r#"{"scancode":300,"extended":false,"ctrl":false,"alt":false,"shift":false,"meta":false}"#
            )
            .is_err()
        );
    }

    #[test]
    fn forwarding_sends_keys_and_stops_at_release() {
        use keygrab::{Event, Key, Released};
        let key = |scancode, down| Key {
            scancode,
            extended: false,
            down,
        };
        let events = vec![
            Event::Key(key(0x1e, true)),
            Event::Key(key(0x1e, false)),
            Event::Released(Released::Combo),
            // Po zwolnieniu nic już nie jest przekazywane.
            Event::Key(key(0x30, true)),
        ];
        let mut sent = Vec::new();
        let mut reason = None;
        forward_events(events, |k| sent.push(k), |r| reason = Some(r));
        assert_eq!(sent, vec![key(0x1e, true), key(0x1e, false)]);
        assert_eq!(reason, Some(Released::Combo));
        // Koniec źródła bez `Released` (hak zdjęty z zewnątrz) nie woła zwolnienia.
        let mut called = false;
        forward_events(vec![Event::Key(key(1, true))], |_| {}, |_| called = true);
        assert!(!called);
        assert_eq!(reason_name(Released::Combo), "combo");
        assert_eq!(reason_name(Released::Foreground), "foreground");
        assert_eq!(reason_name(Released::HookLost), "hook_lost");
    }
}
