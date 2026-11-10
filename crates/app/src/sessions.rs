//! Sesje SSH: łączenie, strumień danych do frontendu i decyzje o zaufaniu do kluczy hostów.

use std::sync::Arc;
use std::time::Duration;

use model::{Id, Protocol, TrustedKey};
use serde::Serialize;
use ssh::{Auth, Hop, HostKeyInfo, HostKeyVerifier, ShellEvent};
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody, Request};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

use std::io::Write as _;

use crate::session_log;
use crate::state::{AppState, Live, TrustAnswer};

#[derive(Serialize, Clone)]
struct TrustRequest {
    id: Uuid,
    protocol: Protocol,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    /// Odcisk zapamiętany wcześniej dla tego algorytmu, jeśli się zmienił.
    previous: Option<String>,
}

async fn ask_ssh_trust(app: AppHandle, info: HostKeyInfo) -> bool {
    ask_trust(
        app,
        Protocol::Ssh,
        info.host,
        info.port,
        info.algorithm,
        info.fingerprint,
    )
    .await
}

/// Sprawdza zapamiętane zaufanie i w razie potrzeby pyta użytkownika (SSH: klucz hosta, RDP: certyfikat).
pub async fn ask_trust(
    app: AppHandle,
    protocol: Protocol,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
) -> bool {
    let info = TrustSubject {
        host,
        port,
        algorithm,
        fingerprint,
    };
    let state = app.state::<AppState>();
    let previous = {
        let guard = state.inner.lock().await;
        let Some(u) = guard.as_ref() else {
            return false;
        };
        let known = u.doc.trusted(protocol, &info.host, info.port);
        if known
            .iter()
            .any(|k| k.algorithm == info.algorithm && k.fingerprint == info.fingerprint)
        {
            return true;
        }
        known
            .iter()
            .find(|k| k.algorithm == info.algorithm)
            .map(|k| k.fingerprint.clone())
    };
    let id = Uuid::new_v4();
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.trust.lock().expect("trust").insert(id, tx);
    let req = TrustRequest {
        id,
        protocol,
        host: info.host.clone(),
        port: info.port,
        algorithm: info.algorithm.clone(),
        fingerprint: info.fingerprint.clone(),
        previous,
    };
    if app.emit("trust-request", req).is_err() {
        state.trust.lock().expect("trust").remove(&id);
        return false;
    }
    let answer = tokio::time::timeout(Duration::from_secs(120), rx).await;
    state.trust.lock().expect("trust").remove(&id);
    match answer {
        Ok(Ok(a)) if a.accept => {
            if a.remember {
                let key = TrustedKey {
                    protocol,
                    host: info.host,
                    port: info.port,
                    algorithm: info.algorithm,
                    fingerprint: info.fingerprint,
                };
                let _ = state
                    .mutate(|doc| {
                        doc.trust(key);
                        Ok(())
                    })
                    .await;
            }
            true
        }
        _ => false,
    }
}

struct TrustSubject {
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
}

#[tauri::command]
pub async fn answer_trust(
    state: State<'_, AppState>,
    id: Uuid,
    accept: bool,
    remember: bool,
) -> Result<(), String> {
    let tx = state.trust.lock().expect("trust").remove(&id);
    if let Some(tx) = tx {
        let _ = tx.send(TrustAnswer { accept, remember });
    }
    Ok(())
}

fn hop_for(doc: &model::Document, id: Id) -> Result<Hop, String> {
    let host = doc.tree.host(id).ok_or("Nie ma takiego hosta")?;
    let r = doc.tree.resolve(id).map_err(|e| e.to_string())?;
    let username = r
        .fields
        .username
        .clone()
        .ok_or_else(|| format!("Host {} nie ma ustawionego użytkownika.", host.name))?;
    let auth = match r.fields.password {
        Some(p) => Auth::Password(Arc::new(Zeroizing::new(p))),
        None => Auth::Agent,
    };
    Ok(Hop {
        host: host.address.clone(),
        port: r.port,
        username,
        auth,
    })
}

fn control(json: &str) -> InvokeResponseBody {
    InvokeResponseBody::Json(json.to_owned())
}

#[tauri::command]
pub async fn connect_ssh(
    app: AppHandle,
    state: State<'_, AppState>,
    host_id: Id,
    cols: u32,
    rows: u32,
    password: Option<String>,
    on_event: Channel<InvokeResponseBody>,
) -> Result<Uuid, String> {
    let (hops, host_name) = state
        .read(|doc| {
            let host = doc.tree.host(host_id).ok_or("Nie ma takiego hosta")?;
            if host.protocol != Protocol::Ssh {
                return Err("Ten host nie używa SSH.".to_string());
            }
            let name = host.name.clone();
            let mut ids = doc.tree.jump_chain(host_id).map_err(|e| e.to_string())?;
            ids.push(host_id);
            let hops = ids
                .into_iter()
                .map(|id| hop_for(doc, id))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((hops, name))
        })
        .await?;
    let mut hops = hops;
    // Hasło podane przy łączeniu dotyczy tylko celu i nie jest nigdzie zapisywane.
    let asked_password = password.is_some();
    if let (Some(pw), Some(target)) = (password, hops.last_mut()) {
        target.auth = Auth::Password(Arc::new(Zeroizing::new(pw)));
    }
    let target_uses_agent = matches!(hops.last().map(|h| &h.auth), Some(Auth::Agent));
    state.log(format!("SSH: łączenie z {host_name}"));

    let app2 = app.clone();
    let verifier: HostKeyVerifier = Arc::new(move |info| {
        let app = app2.clone();
        Box::pin(ask_ssh_trust(app, info))
    });

    let session = match ssh::Session::connect(&hops, verifier).await {
        Ok(s) => s,
        Err(e) => {
            state.log(format!("SSH: {host_name}: {e}"));
            // Brak agenta, kluczy albo odrzucenie kluczy: frontend zapyta o hasło i spróbuje ponownie.
            let needs_password = target_uses_agent
                && !asked_password
                && matches!(
                    e,
                    ssh::Error::AgentUnavailable(_)
                        | ssh::Error::NoIdentities
                        | ssh::Error::AuthFailed
                );
            return Err(if needs_password {
                format!("NEEDS_PASSWORD:{e}")
            } else {
                e.to_string()
            });
        }
    };
    let (shell, mut rx) = session
        .open_shell(cols, rows)
        .await
        .map_err(|e| e.to_string())?;
    state.log(format!("SSH: połączono z {host_name}"));
    let id = Uuid::new_v4();
    state
        .sessions
        .lock()
        .expect("sessions")
        .insert(id, Arc::new(Live { session, shell }));

    let app3 = app.clone();
    let mut session_log = if state.config.lock().expect("config").log_sessions {
        session_log::open(&state.data_dir, &host_name).ok()
    } else {
        None
    };
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let body = match ev {
                ShellEvent::Data(d) => {
                    if let Some(f) = session_log.as_mut() {
                        let _ = f.write_all(&d);
                    }
                    InvokeResponseBody::Raw(d)
                }
                ShellEvent::Exit(code) => control(&format!(r#"{{"t":"exit","code":{code}}}"#)),
                ShellEvent::Closed => control(r#"{"t":"closed"}"#),
            };
            if on_event.send(body).is_err() {
                break;
            }
        }
        let live = app3
            .state::<AppState>()
            .sessions
            .lock()
            .expect("sessions")
            .remove(&id);
        if let Some(live) = live {
            live.session.disconnect().await;
        }
        app3.state::<AppState>()
            .log(format!("SSH: zakończono sesję z {host_name}"));
    });
    Ok(id)
}

fn live(state: &AppState, id: Uuid) -> Result<Arc<Live>, String> {
    state
        .sessions
        .lock()
        .expect("sessions")
        .get(&id)
        .cloned()
        .ok_or_else(|| "Sesja już nie istnieje.".to_string())
}

/// Dane z klawiatury jako surowe bajty; identyfikator sesji w nagłówku `x-session`.
#[tauri::command]
pub async fn ssh_write(state: State<'_, AppState>, request: Request<'_>) -> Result<(), String> {
    let InvokeBody::Raw(data) = request.body() else {
        return Err("Oczekiwano surowych danych.".into());
    };
    let id = request
        .headers()
        .get("x-session")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("Brak identyfikatora sesji.")?;
    live(&state, id)?
        .shell
        .write(data.clone())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_resize(
    state: State<'_, AppState>,
    id: Uuid,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    live(&state, id)?
        .shell
        .resize(cols, rows)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_close(state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    let l = state.sessions.lock().expect("sessions").remove(&id);
    if let Some(l) = l {
        let _ = l.shell.close().await;
        l.session.disconnect().await;
    }
    Ok(())
}
