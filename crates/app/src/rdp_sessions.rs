//! Sesje RDP: proces pomocniczy `rdp-worker`, obraz do frontendu przez `ipc::Channel`.
//!
//! Do frontendu płyną dwa rodzaje wiadomości: JSON ze zdarzeniami sterującymi oraz surowe bajty
//! obrazu (`x,y,w,h` jako `u16 LE`, potem RGBA).

use model::{Id, Protocol};
use rdp::{ConnectParams, Event, FromWorker, RdpClient, ToWorker};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tokio::sync::Notify;
use tokio::sync::mpsc::channel;
use uuid::Uuid;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::clipboard::{ClipSync, Outcome};
use crate::sessions::ask_trust;
use crate::state::AppState;

/// Ile bajtów obrazu może czekać na odebranie przez interfejs (dwa pełne ekrany 4K).
const IMAGE_WINDOW: u64 = 64 * 1024 * 1024;

/// Kontrola przepływu obrazu jednej sesji. Kanał do interfejsu nie ma limitu, więc bez niej wolno
/// rysujący interfejs (albo szybko zmieniający się ekran) powodowałby nieograniczony wzrost pamięci.
/// Pętla sesji liczy wysłane bajty, interfejs potwierdza odebrane (`rdp_ack`), a po przekroczeniu
/// okna pętla przestaje odbierać zdarzenia z procesu, co przez potok i sieć spowalnia sam serwer.
#[derive(Default)]
pub struct Flow {
    outstanding: AtomicU64,
    acked: Notify,
}

impl Flow {
    fn sent(&self, bytes: u64) {
        self.outstanding.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Interfejs odebrał `bytes` bajtów obrazu. Nadmiarowe potwierdzenie zeruje licznik.
    pub fn ack(&self, bytes: u64) {
        // Odejmowanie z nasyceniem w pętli `compare_exchange`: działa na każdej wersji kompilatora
        // (`fetch_update` jest przestarzałe od Rust 1.100, a jego następcy nie ma w starszych).
        let mut current = self.outstanding.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.outstanding.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        self.acked.notify_one();
    }

    fn congested(&self) -> bool {
        self.outstanding.load(Ordering::Relaxed) > IMAGE_WINDOW
    }

    /// Czeka, aż w oknie będzie miejsce. Zwraca `false`, gdy sesja w tym czasie przestała istnieć
    /// (`alive` jest sprawdzane co 250 ms, żeby zamknięcie sesji nie zostawiło pętli w zawieszeniu).
    async fn wait(&self, alive: impl Fn() -> bool) -> bool {
        while self.congested() {
            if !alive() {
                return false;
            }
            let _ = tokio::time::timeout(Duration::from_millis(250), self.acked.notified()).await;
        }
        true
    }
}

/// Podstawowy i największy odstęp między sprawdzeniami lokalnego schowka.
const CLIP_POLL: Duration = Duration::from_secs(1);
const CLIP_POLL_MAX: Duration = Duration::from_secs(10);

/// Odstęp do następnego sprawdzenia lokalnego schowka. Sprawdzenie czyta i haszuje całą zawartość,
/// a przy dużym obrazie trwa setki milisekund, więc odstęp rośnie z kosztem ostatniego odczytu tak,
/// żeby sprawdzanie zajmowało najwyżej ok. 5% czasu. Powrót fokusu do sesji sprawdza schowek od razu
/// (`rdp_clipboard_focus`), więc dłuższy odstęp opóźnia tylko zmiany zrobione w tle.
fn clip_poll_delay(cost: Duration) -> Duration {
    cost.saturating_mul(20).clamp(CLIP_POLL, CLIP_POLL_MAX)
}

#[tauri::command]
pub async fn connect_rdp(
    app: AppHandle,
    state: State<'_, AppState>,
    host_id: Id,
    width: u16,
    height: u16,
    password: Option<String>,
    on_event: Channel<InvokeResponseBody>,
) -> Result<Uuid, String> {
    // Licznik przeładowań musi być odczytany przed pierwszym `await`, inaczej przeładowanie
    // w czasie czekania na blokadę dokumentu uszłoby uwadze kontroli po wstawieniu sesji.
    let reloads = state.reloads.load(Ordering::SeqCst);
    let params = state
        .read(|doc| {
            let host = doc.tree.host(host_id).ok_or("Nie ma takiego hosta")?;
            if host.protocol != Protocol::Rdp {
                return Err("Ten host nie używa RDP.".to_string());
            }
            let r = doc.tree.resolve(host_id).map_err(|e| e.to_string())?;
            let username = r
                .fields
                .username
                .clone()
                .ok_or_else(|| format!("Host {} nie ma ustawionego użytkownika.", host.name))?;
            // Hasło podane przy łączeniu ma pierwszeństwo i nie jest zapisywane.
            let password = password
                .clone()
                .filter(|p| !p.is_empty())
                .or_else(|| r.fields.password.clone())
                .ok_or_else(|| {
                    format!(
                        "NEEDS_PASSWORD:Host {} nie ma zapisanego hasła, a RDP z NLA go wymaga.",
                        host.name
                    )
                })?;
            Ok(ConnectParams {
                host: host.address.clone(),
                port: r.port,
                username,
                domain: r.fields.domain.clone(),
                password,
                kerberos: r.fields.rdp_kerberos.unwrap_or(false),
                kdc: r.fields.rdp_kdc.clone(),
                width: width.clamp(200, 8192),
                height: height.clamp(200, 8192),
            })
        })
        .await?;
    let (host, port) = (params.host.clone(), params.port);
    state.log(format!("RDP: łączenie z {host}:{port}"));

    let worker = rdp::find_worker().ok_or(
        "Nie znaleziono procesu RDP (multiremotemanager-rdp-worker). Zbuduj go: cargo build --manifest-path tools/rdp/Cargo.toml, albo ustaw MRM_RDP_WORKER.",
    )?;
    // Ścieżka procesu w dzienniku pozwala od razu zobaczyć, która binarka obsługuje sesję.
    state.log(format!("RDP: proces {}", worker.display()));
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    let client = RdpClient::spawn(&worker, params, tx)
        .map_err(|e| format!("Nie można uruchomić procesu RDP: {e}"))?;
    let id = Uuid::new_v4();
    state.rdp.lock().expect("rdp").insert(id, client.clone());
    let sync = Arc::new(ClipSync::new(
        state.data_dir.join("clip").join(id.to_string()),
    ));
    state
        .rdp_clip
        .lock()
        .expect("clip")
        .insert(id, sync.clone());
    let flow = Arc::new(Flow::default());
    state
        .rdp_flow
        .lock()
        .expect("flow")
        .insert(id, flow.clone());
    // Blokada pliku najpierw ustawia `inner` na `None`, a potem opróżnia mapy sesji (jak przy SSH).
    // Klient wstawiony po blokadzie trzeba zamknąć tutaj, zanim zostanie zwrócony do interfejsu.
    // To samo po przeładowaniu interfejsu w trakcie łączenia (`reset_after_reload`).
    let locked = state.inner.lock().await.is_none();
    if locked || state.reloads.load(Ordering::SeqCst) != reloads {
        state.rdp_clip.lock().expect("clip").remove(&id);
        state.rdp_flow.lock().expect("flow").remove(&id);
        let c = state.rdp.lock().expect("rdp").remove(&id);
        if let Some(c) = c {
            c.close();
        }
        return Err(crate::sessions::interrupted_message(locked).into());
    }

    // Sprawdzanie lokalnego schowka, gdy okno sesji ma fokus: zmiany są ogłaszane serwerowi.
    {
        let (app, sync, client) = (app.clone(), sync.clone(), client.clone());
        tokio::spawn(async move {
            let mut delay = CLIP_POLL;
            loop {
                tokio::time::sleep(delay).await;
                if !app
                    .state::<AppState>()
                    .rdp
                    .lock()
                    .expect("rdp")
                    .contains_key(&id)
                {
                    break;
                }
                if !sync.watching.load(Ordering::Relaxed) || !clipboard_enabled(&app) {
                    delay = CLIP_POLL;
                    continue;
                }
                let s = sync.clone();
                let started = Instant::now();
                if let Ok(Some(msg)) =
                    tauri::async_runtime::spawn_blocking(move || s.local_announcement()).await
                {
                    let _ = client.send(&msg);
                }
                delay = clip_poll_delay(started.elapsed());
            }
        });
    }

    // Koniec pętli zdarzeń (sesja zamknięta albo proces padł) anuluje otwarte pytanie o certyfikat.
    let (session_end, _) = tokio::sync::broadcast::channel::<()>(1);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::Image(img) => {
                    let mut body = Vec::with_capacity(8 + img.rgba.len());
                    for v in [img.x, img.y, img.width, img.height] {
                        body.extend_from_slice(&v.to_le_bytes());
                    }
                    body.extend_from_slice(&img.rgba);
                    // Liczymy przed wysłaniem: potwierdzenie z interfejsu może przyjść, zanim ta
                    // pętla wróci do pracy, a odjęte od licznika bez tej ramki zostałoby obcięte
                    // do zera i jej bajty zalegałyby w oknie na stałe.
                    flow.sent(body.len() as u64);
                    if on_event.send(InvokeResponseBody::Raw(body)).is_err() {
                        break;
                    }
                    // Po przekroczeniu okna czekamy na potwierdzenia z interfejsu; koniec sesji
                    // (zamknięcie karty, blokada pliku) przerywa czekanie.
                    let alive = || {
                        app.state::<AppState>()
                            .rdp
                            .lock()
                            .expect("rdp")
                            .contains_key(&id)
                    };
                    if !flow.wait(alive).await {
                        break;
                    }
                }
                // Pytanie o certyfikat w osobnym zadaniu: pętla dalej odbiera zdarzenia (np. śmierć
                // procesu), a koniec sesji zamyka okno zaufania zamiast zostawiać je na 120 s.
                Event::Worker(FromWorker::Cert { fingerprint, .. }) => {
                    let (app, host, client) = (app.clone(), host.clone(), client.clone());
                    let mut ended = session_end.subscribe();
                    tokio::spawn(async move {
                        let accept = ask_trust(
                            app,
                            Protocol::Rdp,
                            host,
                            port,
                            "certyfikat TLS (SHA-256)".into(),
                            fingerprint,
                            async move {
                                let _ = ended.recv().await;
                            },
                        )
                        .await;
                        let _ = client.send(&ToWorker::Trust { accept });
                    });
                }
                // Wpisy diagnostyczne procesu zostają w dzienniku aplikacji, frontend ich nie dostaje.
                Event::Worker(FromWorker::Log { message }) => {
                    app.state::<AppState>()
                        .log(format!("RDP {host}: {message}"));
                }
                // Schowek obsługujemy po stronie backendu, frontend widzi tylko powiadomienia.
                Event::Worker(
                    FromWorker::ClipRemote { .. }
                    | FromWorker::ClipFiles { .. }
                    | FromWorker::ClipFilesDone { .. },
                )
                | Event::Clip { .. }
                    if !clipboard_enabled(&app) => {}
                // Serwer prosi o dane, a schowek jest wyłączony: odpowiadamy brakiem danych.
                Event::Worker(FromWorker::ClipRequest { kind }) if !clipboard_enabled(&app) => {
                    let _ = client.send(&ToWorker::ClipData {
                        kind,
                        data: Vec::new(),
                    });
                }
                // Bez fokusu zmiana zdalnego schowka czeka na powrót do sesji, żeby karta w tle
                // nie podmieniała schowka, z którego użytkownik korzysta w innym programie.
                Event::Worker(FromWorker::ClipRemote { kinds, files }) => {
                    if let Some(f) = sync.on_remote(kinds, files) {
                        let _ = client.send(&f.command());
                    }
                }
                Event::Clip { kind, data } => {
                    let outcome = sync.remote.lock().expect("clip").on_blob(kind, data);
                    match outcome {
                        Outcome::Set(item) => {
                            let sync = sync.clone();
                            tauri::async_runtime::spawn_blocking(move || sync.apply(item));
                        }
                        Outcome::Fetch(kind) => {
                            let _ = client.send(&ToWorker::ClipFetch { kind });
                        }
                        Outcome::Ignore => {}
                    }
                }
                Event::Worker(FromWorker::ClipFiles { files }) => {
                    if !files.is_empty() {
                        let dir = sync.next_download_dir();
                        let _ = client.send(&ToWorker::ClipDownload {
                            dir: dir.to_string_lossy().into_owned(),
                        });
                    }
                }
                Event::Worker(FromWorker::ClipFilesDone { paths }) => {
                    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
                    let count = paths.len();
                    let sync = sync.clone();
                    tauri::async_runtime::spawn_blocking(move || sync.apply_files(paths));
                    let msg = format!(
                        r#"{{"t":"notice","message":"Skopiowano do schowka elementy ze zdalnej sesji ({count})."}}"#
                    );
                    let _ = on_event.send(InvokeResponseBody::Json(msg));
                }
                Event::Worker(FromWorker::ClipRequest { kind }) => {
                    let (sync, client) = (sync.clone(), client.clone());
                    tauri::async_runtime::spawn_blocking(move || {
                        let _ = client.send(&sync.answer(kind));
                    });
                }
                Event::Worker(other) => {
                    let done =
                        matches!(other, FromWorker::Closed { .. } | FromWorker::Error { .. });
                    let json = serde_json::to_string(&other).unwrap_or_default();
                    if on_event.send(InvokeResponseBody::Json(json)).is_err() || done {
                        break;
                    }
                }
            }
        }
        let _ = session_end.send(());
        let st = app.state::<AppState>();
        st.rdp_clip.lock().expect("clip").remove(&id);
        st.rdp_flow.lock().expect("flow").remove(&id);
        if let Some(c) = st.rdp.lock().expect("rdp").remove(&id) {
            c.close();
        }
    });
    Ok(id)
}

fn clipboard_enabled(app: &AppHandle) -> bool {
    app.state::<AppState>()
        .config
        .lock()
        .expect("config")
        .rdp_clipboard
}

fn client(state: &AppState, id: Uuid) -> Result<RdpClient, String> {
    state
        .rdp
        .lock()
        .expect("rdp")
        .get(&id)
        .cloned()
        .ok_or_else(|| "Sesja już nie istnieje.".to_string())
}

/// Wejście z klawiatury i myszy. Frontend może wysłać tylko wejście, Ctrl+Alt+Del i zmianę
/// rozmiaru: polecenia sterujące procesem i schowkiem (ścieżki plików, katalog pobierania) wysyła
/// wyłącznie backend.
///
/// Komenda jest celowo synchroniczna: Tauri wykonuje takie komendy po kolei, w kolejności wywołań,
/// a komendy `async` uruchamia jako osobne zadania, które mogły się wyprzedzać (puszczenie klawisza
/// przed jego wciśnięciem, kliknięcie w starym miejscu). Zapis do stdin procesu nie blokuje, bo proces
/// czyta stdin w osobnym wątku do nieograniczonej kolejki.
#[tauri::command]
pub fn rdp_send(state: State<'_, AppState>, id: Uuid, cmd: ToWorker) -> Result<(), String> {
    if !frontend_allowed(&cmd) {
        return Err("To polecenie jest zarezerwowane dla aplikacji.".into());
    }
    client(&state, id)?.send(&cmd).map_err(|e| e.to_string())
}

/// Potwierdzenie z interfejsu: tyle bajtów obrazu zostało odebranych (patrz `Flow`).
#[tauri::command]
pub fn rdp_ack(state: State<'_, AppState>, id: Uuid, bytes: u64) {
    let flow = state.rdp_flow.lock().expect("flow").get(&id).cloned();
    if let Some(flow) = flow {
        flow.ack(bytes);
    }
}

#[tauri::command]
pub async fn rdp_close(state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    let c = state.rdp.lock().expect("rdp").remove(&id);
    if let Some(c) = c {
        c.close();
    }
    Ok(())
}

/// Fokus okna sesji włącza (albo wyłącza) ogłaszanie zmian lokalnego schowka serwerowi.
#[tauri::command]
pub async fn rdp_clipboard_focus(
    state: State<'_, AppState>,
    id: Uuid,
    focused: bool,
) -> Result<(), String> {
    let client = client(&state, id)?;
    let sync = state
        .rdp_clip
        .lock()
        .expect("clip")
        .get(&id)
        .cloned()
        .ok_or("Sesja już nie istnieje.")?;
    sync.watching.store(focused, Ordering::Relaxed);
    if focused && state.config.lock().expect("config").rdp_clipboard {
        // Zmiana lokalna z czasu bez fokusu jest ogłaszana; jeśli jej nie ma, pobieramy odłożoną
        // zmianę zdalną. Ogłoszenie nie jest wymuszane, żeby nie nadpisać zdalnego schowka starą
        // lokalną zawartością.
        let msg = tauri::async_runtime::spawn_blocking(move || {
            sync.local_announcement()
                .or_else(|| sync.take_pending().map(|f| f.command()))
        })
        .await
        .map_err(|e| e.to_string())?;
        if let Some(msg) = msg {
            client.send(&msg).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Polecenia, które frontend może wysłać do procesu RDP.
fn frontend_allowed(cmd: &ToWorker) -> bool {
    matches!(
        cmd,
        ToWorker::MouseMove { .. }
            | ToWorker::MouseButton { .. }
            | ToWorker::Wheel { .. }
            | ToWorker::Key { .. }
            | ToWorker::CtrlAltDel
            | ToWorker::Resize { .. }
    )
}

/// Wyłączenie schowka: serwer przestaje dostawać dane i pliki ogłoszone wcześniej.
pub fn clipboard_disabled(state: &AppState) {
    let clips: Vec<_> = state
        .rdp_clip
        .lock()
        .expect("clip")
        .iter()
        .map(|(id, c)| (*id, c.clone()))
        .collect();
    for (id, clip) in clips {
        clip.forget_announced();
        if let Some(client) = state.rdp.lock().expect("rdp").get(&id).cloned() {
            let _ = client.send(&ToWorker::ClipAnnounce { kinds: Vec::new() });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp::ClipKind;

    #[tokio::test]
    async fn image_flow_waits_for_acks_and_stops_when_session_is_gone() {
        let flow = Flow::default();
        // W oknie: bez czekania, także dokładnie na granicy.
        flow.sent(IMAGE_WINDOW);
        assert!(!flow.congested());
        assert!(flow.wait(|| true).await);
        // Ponad okno: czekanie trwa do potwierdzenia.
        flow.sent(1);
        assert!(flow.congested());
        let waiting = tokio::time::timeout(Duration::from_millis(100), flow.wait(|| true)).await;
        assert!(waiting.is_err(), "bez potwierdzenia pętla czeka");
        flow.ack(1024);
        assert!(flow.wait(|| true).await);
        // Sesja zniknęła w trakcie zatoru: czekanie kończy się wynikiem `false`.
        flow.sent(IMAGE_WINDOW);
        assert!(!flow.wait(|| false).await);
        // Nadmiarowe potwierdzenie nie przekręca licznika.
        flow.ack(u64::MAX);
        assert!(!flow.congested());
        assert!(flow.wait(|| true).await);
    }

    #[test]
    fn clipboard_poll_slows_down_with_expensive_reads() {
        assert_eq!(clip_poll_delay(Duration::ZERO), CLIP_POLL);
        assert_eq!(clip_poll_delay(Duration::from_millis(10)), CLIP_POLL);
        assert_eq!(
            clip_poll_delay(Duration::from_millis(200)),
            Duration::from_secs(4)
        );
        assert_eq!(clip_poll_delay(Duration::from_secs(5)), CLIP_POLL_MAX);
        assert_eq!(clip_poll_delay(Duration::MAX), CLIP_POLL_MAX);
    }

    #[test]
    fn frontend_cannot_send_clipboard_or_control_commands() {
        assert!(frontend_allowed(&ToWorker::CtrlAltDel));
        assert!(frontend_allowed(&ToWorker::Resize {
            width: 800,
            height: 600
        }));
        for cmd in [
            ToWorker::ClipAnnounceFiles {
                paths: vec!["/home/u/.ssh".into()],
            },
            ToWorker::ClipDownload {
                dir: "/tmp/x".into(),
            },
            ToWorker::ClipFetch {
                kind: ClipKind::Text,
            },
            ToWorker::ClipFetchFiles,
            ToWorker::ClipAnnounce { kinds: vec![] },
            ToWorker::Trust { accept: true },
        ] {
            assert!(!frontend_allowed(&cmd), "{cmd:?}");
        }
    }
}
