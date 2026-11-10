//! Sesje RDP: proces pomocniczy `rdp-worker`, obraz do frontendu przez `ipc::Channel`.
//!
//! Do frontendu płyną dwa rodzaje wiadomości: JSON ze zdarzeniami sterującymi oraz surowe bajty
//! obrazu (`x,y,w,h` jako `u16 LE`, potem RGBA).

use model::{Id, Protocol};
use rdp::{ConnectParams, Event, FromWorker, RdpClient, ToWorker};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tokio::sync::mpsc::unbounded_channel;
use uuid::Uuid;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::clipboard::{ClipSync, Outcome};
use crate::sessions::ask_trust;
use crate::state::AppState;

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
    let (tx, mut rx) = unbounded_channel();
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

    // Sprawdzanie lokalnego schowka, gdy okno sesji ma fokus: zmiany są ogłaszane serwerowi.
    {
        let (app, sync, client) = (app.clone(), sync.clone(), client.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                    continue;
                }
                let s = sync.clone();
                if let Ok(Some(msg)) =
                    tauri::async_runtime::spawn_blocking(move || s.local_announcement()).await
                {
                    let _ = client.send(&msg);
                }
            }
        });
    }

    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::Image(img) => {
                    let mut body = Vec::with_capacity(8 + img.rgba.len());
                    for v in [img.x, img.y, img.width, img.height] {
                        body.extend_from_slice(&v.to_le_bytes());
                    }
                    body.extend_from_slice(&img.rgba);
                    if on_event.send(InvokeResponseBody::Raw(body)).is_err() {
                        break;
                    }
                }
                Event::Worker(FromWorker::Cert { fingerprint, .. }) => {
                    let accept = ask_trust(
                        app.clone(),
                        Protocol::Rdp,
                        host.clone(),
                        port,
                        "certyfikat TLS (SHA-256)".into(),
                        fingerprint,
                    )
                    .await;
                    let _ = client.send(&ToWorker::Trust { accept });
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
                Event::Worker(FromWorker::ClipRemote { kinds, files }) => {
                    let fetch = sync.remote.lock().expect("clip").on_remote(&kinds, files);
                    if let Some(f) = fetch {
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
        let st = app.state::<AppState>();
        st.rdp_clip.lock().expect("clip").remove(&id);
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

/// Wejście z klawiatury i myszy. Polecenia sterujące procesem (`Connect`, `Trust`) są niedozwolone.
#[tauri::command]
pub async fn rdp_send(state: State<'_, AppState>, id: Uuid, cmd: ToWorker) -> Result<(), String> {
    if matches!(cmd, ToWorker::Connect(_) | ToWorker::Trust { .. }) {
        return Err("To polecenie jest zarezerwowane dla aplikacji.".into());
    }
    client(&state, id)?.send(&cmd).map_err(|e| e.to_string())
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
        sync.reset();
        let msg = tauri::async_runtime::spawn_blocking(move || sync.local_announcement())
            .await
            .map_err(|e| e.to_string())?;
        if let Some(msg) = msg {
            client.send(&msg).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
