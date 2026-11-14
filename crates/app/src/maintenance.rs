//! Synchronizacja, kopie zapasowe, dziennik diagnostyczny, konfiguracja lokalna i linki.

use std::path::PathBuf;

use model::link::{Link, parse_link};
use model::{Document, Id};
use serde::Serialize;
use tauri::State;

use crate::state::AppState;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------- synchronizacja ----------

#[derive(Serialize)]
pub struct SyncView {
    folder: Option<String>,
    /// "brak_pliku", "aktualny", "lokalne_zmiany", "zdalne_zmiany" albo "konflikt".
    status: Option<&'static str>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct SyncRun {
    view: SyncView,
    /// Po pobraniu zdalnej wersji plik jest zablokowany (mogło zmienić się hasło główne).
    locked: bool,
}

fn status_name(s: sync::Status) -> &'static str {
    match s {
        sync::Status::RemoteMissing => "brak_pliku",
        sync::Status::InSync => "aktualny",
        sync::Status::LocalChanged => "lokalne_zmiany",
        sync::Status::RemoteChanged => "zdalne_zmiany",
        sync::Status::Conflict => "konflikt",
    }
}

fn sync_view(state: &AppState) -> SyncView {
    let (folder, base) = {
        let c = state.config.lock().expect("config");
        (c.sync_folder.clone(), c.sync_base.clone())
    };
    let Some(folder) = folder else {
        return SyncView {
            folder: None,
            status: None,
            error: None,
        };
    };
    let (status, error) = match sync::status(&state.path, &folder, base.as_deref()) {
        Ok(s) => (Some(status_name(s)), None),
        Err(e) => (None, Some(e.to_string())),
    };
    SyncView {
        folder: Some(folder.display().to_string()),
        status,
        error,
    }
}

#[tauri::command]
pub async fn sync_status(state: State<'_, AppState>) -> Result<SyncView, String> {
    Ok(sync_view(&state))
}

#[tauri::command]
pub async fn sync_set_folder(
    state: State<'_, AppState>,
    folder: Option<String>,
) -> Result<SyncView, String> {
    let folder = folder
        .map(|f| f.trim().to_owned())
        .filter(|f| !f.is_empty())
        .map(PathBuf::from);
    if let Some(f) = &folder
        && !f.is_dir()
    {
        return Err(format!("Folder nie istnieje: {}", f.display()));
    }
    {
        let mut c = state.config.lock().expect("config");
        c.sync_folder = folder;
        c.sync_base = None;
    }
    state.save_config();
    state.log("synchronizacja: zmieniono folder");
    Ok(sync_view(&state))
}

/// Synchronizuje zgodnie ze stanem. W konflikcie wymaga `keep` ("local" albo "remote").
#[tauri::command]
pub async fn sync_run(state: State<'_, AppState>, keep: Option<String>) -> Result<SyncRun, String> {
    let keep = match keep.as_deref() {
        None => None,
        Some("local") => Some(sync::Keep::Local),
        Some("remote") => Some(sync::Keep::Remote),
        Some(_) => return Err("Nieznany wybór rozstrzygnięcia.".into()),
    };
    let (folder, base) = {
        let c = state.config.lock().expect("config");
        (
            c.sync_folder
                .clone()
                .ok_or("Synchronizacja nie jest skonfigurowana.")?,
            c.sync_base.clone(),
        )
    };
    // Blokada dokumentu na czas operacji na pliku, żeby zapis z interfejsu się nie wtrącił.
    let mut guard = state.inner.lock().await;
    let (st, new_base) =
        sync::sync(&state.path, &folder, base.as_deref(), keep).map_err(|e| match e {
            sync::Error::Conflict => "Konflikt: wybierz, którą wersję zachować.".to_string(),
            other => other.to_string(),
        })?;
    let pulled = matches!(
        (st, keep),
        (sync::Status::RemoteChanged, _) | (sync::Status::Conflict, Some(sync::Keep::Remote))
    );
    if pulled {
        *guard = None;
    }
    drop(guard);
    state.config.lock().expect("config").sync_base = new_base;
    state.save_config();
    state.log(format!(
        "synchronizacja: {}{}",
        status_name(st),
        if pulled {
            ", pobrano zdalną wersję"
        } else {
            ""
        }
    ));
    Ok(SyncRun {
        view: sync_view(&state),
        locked: pulled,
    })
}

// ---------- kopie zapasowe ----------

#[derive(Serialize)]
pub struct BackupInfo {
    n: usize,
    modified: u64,
    size: u64,
}

#[tauri::command]
pub async fn list_backups(state: State<'_, AppState>) -> Result<Vec<BackupInfo>, String> {
    let mut out = Vec::new();
    for n in 1..=20 {
        let p = vault::backup_file(&state.path, n);
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(BackupInfo {
            n,
            modified,
            size: meta.len(),
        });
    }
    Ok(out)
}

/// Przywraca dokument z kopii. Hasło jest potrzebne, bo kopia mogła powstać przed zmianą hasła głównego.
#[tauri::command]
pub async fn restore_backup(
    state: State<'_, AppState>,
    n: usize,
    password: String,
) -> Result<(), String> {
    if !(1..=20).contains(&n) {
        return Err("Nieprawidłowy numer kopii.".into());
    }
    let file = vault::backup_file(&state.path, n);
    let doc = tokio::task::spawn_blocking(move || vault::open_backup::<Document>(&file, &password))
        .await
        .map_err(err)?
        .map_err(|e| match e {
            vault::Error::Decrypt => {
                "Nieprawidłowe hasło dla tej kopii albo uszkodzona kopia.".to_string()
            }
            other => other.to_string(),
        })?;
    state
        .mutate(|d| {
            *d = doc;
            Ok(())
        })
        .await?;
    state.log(format!("przywrócono kopię nr {n}"));
    Ok(())
}

// ---------- diagnostyka i konfiguracja lokalna ----------

#[tauri::command]
pub async fn get_diagnostics(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.diag.lock().expect("diag").iter().cloned().collect())
}

#[tauri::command]
pub async fn clear_diagnostics(state: State<'_, AppState>) -> Result<(), String> {
    state.diag.lock().expect("diag").clear();
    Ok(())
}

#[derive(Serialize)]
pub struct LocalConfig {
    log_sessions: bool,
    rdp_clipboard: bool,
    logs_dir: String,
}

#[tauri::command]
pub async fn get_local_config(state: State<'_, AppState>) -> Result<LocalConfig, String> {
    Ok(local_config(&state))
}

fn local_config(state: &AppState) -> LocalConfig {
    // Jedna blokada: dwa `lock()` w jednym wyrażeniu zakleszczały wątek, bo tymczasowa blokada
    // z pierwszego pola żyje do końca całego wyrażenia.
    let (log_sessions, rdp_clipboard) = {
        let c = state.config.lock().expect("config");
        (c.log_sessions, c.rdp_clipboard)
    };
    LocalConfig {
        log_sessions,
        rdp_clipboard,
        logs_dir: state.data_dir.join("logs").display().to_string(),
    }
}

#[tauri::command]
pub async fn set_log_sessions(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.config.lock().expect("config").log_sessions = enabled;
    state.save_config();
    Ok(())
}

#[tauri::command]
pub async fn set_rdp_clipboard(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.config.lock().expect("config").rdp_clipboard = enabled;
    state.save_config();
    if !enabled {
        crate::rdp_sessions::clipboard_disabled(&state);
    }
    state.log(if enabled {
        "schowek RDP włączony"
    } else {
        "schowek RDP wyłączony"
    });
    Ok(())
}

// ---------- linki ----------

#[derive(Serialize)]
pub struct LinkView {
    protocol: model::Protocol,
    host: String,
    port: Option<u16>,
    /// Port po rozstrzygnięciu: z linku albo domyślny dla protokołu. Jedno źródło dla dopasowania
    /// hosta i dla tekstu pytania w interfejsie.
    resolved_port: u16,
    username: Option<String>,
    domain: Option<String>,
    /// Zapisany host o tym samym adresie, protokole i porcie (link bez portu oznacza port
    /// domyślny protokołu). Interfejs pyta przed połączeniem, link nigdy nie łączy sam.
    matching_host: Option<Id>,
}

fn link_view(doc: &Document, link: Link) -> LinkView {
    let port = link.port.unwrap_or(link.protocol.default_port());
    let matching_host = doc
        .tree
        .hosts
        .iter()
        .find(|h| {
            h.protocol == link.protocol
                && h.address.eq_ignore_ascii_case(&link.host)
                && doc
                    .tree
                    .resolve(h.id)
                    .map(|r| r.port == port)
                    .unwrap_or(false)
        })
        .map(|h| h.id);
    LinkView {
        protocol: link.protocol,
        host: link.host,
        port: link.port,
        resolved_port: port,
        username: link.username,
        domain: link.domain,
        matching_host,
    }
}

#[tauri::command]
pub async fn resolve_link(state: State<'_, AppState>, url: String) -> Result<LinkView, String> {
    let link = parse_link(&url).map_err(|e| format!("Nieprawidłowy link: {e}."))?;
    state.read(|doc| Ok(link_view(doc, link))).await
}

/// Link przekazany w argumentach uruchomienia, odbierany raz po odblokowaniu.
#[tauri::command]
pub async fn take_pending_link(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.pending_link.lock().expect("pending").take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_without_port_matches_only_default_port() {
        let mut doc = Document::default();
        let h = doc
            .tree
            .add_host("srv", "srv", model::Protocol::Ssh, None)
            .unwrap();
        doc.tree
            .hosts
            .iter_mut()
            .find(|x| x.id == h)
            .unwrap()
            .fields
            .port = Some(2222);
        let link = |u: &str| link_view(&doc, parse_link(u).unwrap()).matching_host;
        assert_eq!(link("ssh://srv"), None, "port domyślny 22 to inny host");
        assert_eq!(link("ssh://srv:2222"), Some(h));
        assert_eq!(link("rdp://srv:2222"), None, "inny protokół");
        let view = |u: &str| link_view(&doc, parse_link(u).unwrap());
        assert_eq!(
            (view("ssh://srv").port, view("ssh://srv").resolved_port),
            (None, 22)
        );
        assert_eq!(view("rdp://srv").resolved_port, 3389);
        assert_eq!(view("ssh://srv:2222").resolved_port, 2222);
    }

    #[test]
    fn local_config_does_not_deadlock() {
        let dir = std::env::temp_dir().join(format!("mrm-localcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = std::sync::Arc::new(AppState::new(dir.join("hosts.mrm")));
        let (tx, rx) = std::sync::mpsc::channel();
        let s = state.clone();
        std::thread::spawn(move || {
            let cfg = local_config(&s);
            let _ = tx.send(cfg.rdp_clipboard);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
            "odczyt konfiguracji lokalnej zawisł"
        );
        // Blokada konfiguracji jest wolna po odczycie.
        assert!(state.config.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
