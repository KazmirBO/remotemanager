//! Przechwytywanie klawiszy systemowych (Win, Alt+Tab itp.) przez sesję RDP.
//!
//! Linux: przejęcie klawiatury przez GDK na głównym oknie (na Waylandzie wstrzymuje to skróty
//! kompozytora). Windows: niskopoziomowy hak klawiatury z crate'a `keygrab`. Inne platformy tego
//! nie potrafią: komenda kończy się wtedy sukcesem z `system: false`, a frontend i tak przechwytuje
//! skróty aplikacji.
//!
//! Przechwytywanie należy do jednej sesji i kończy się razem z nią (`release_for`), a także przy
//! blokadzie pliku i przeładowaniu interfejsu (`release_all` w `close_all_sessions`), niezależnie
//! od tego, czy interfejs zdąży je wyłączyć.

use std::sync::Mutex;

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
    release: Release,
}

/// Kto przechwytuje klawisze (najwyżej jedna sesja) i jak to przechwytywanie zwolnić.
#[derive(Default)]
pub struct Grabs {
    /// Serializuje włączanie i wyłączanie (praca w wątku głównym trwa między krokami).
    gate: tokio::sync::Mutex<()>,
    holder: Mutex<Option<Holder>>,
}

impl Grabs {
    /// Zapamiętuje przechwytywanie sesji; poprzednie (jeśli jest) zostaje najpierw zwolnione.
    pub fn set(&self, session: Uuid, release: Release) {
        let old = self
            .holder
            .lock()
            .expect("keys")
            .replace(Holder { session, release });
        if let Some(old) = old {
            (old.release)();
        }
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

    fn grab(app: &AppHandle) -> bool {
        let Some((seat, window)) = seat_and_window(app) else {
            return false;
        };
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
        tauri::Manager::state::<AppState>(app)
            .keys
            .set(session, release);
        true
    }
}

/// Windows: hak `WH_KEYBOARD_LL` zakładany w wątku głównym (ma pętlę komunikatów okna).
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
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                state.log(format!("RDP: przechwytywanie klawiszy systemowych: {e}"));
                return false;
            }
            Err(_) => return false,
        }
        let a = app.clone();
        let release_fn: Release = Box::new(move || {
            let _ = a.run_on_main_thread(keygrab::stop);
        });
        // Zwolnienie musi być zarejestrowane, zanim ruszy pętla przekazująca zdarzenia.
        state.keys.set(session, release_fn);
        let app = app.clone();
        std::thread::spawn(move || {
            forward_events(
                events_rx,
                |k| {
                    let _ = client.send(&ToWorker::Key {
                        scancode: k.scancode,
                        extended: k.extended,
                        down: k.down,
                    });
                },
                |reason| {
                    // Zdarzenie tylko wtedy, gdy przechwytywanie nadal należało do tej sesji
                    // (zwolnione z zewnątrz samo nie zgłasza powodu).
                    if app.state::<AppState>().keys.release_for(session) {
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
