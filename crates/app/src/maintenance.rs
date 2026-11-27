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

/// Wynik `sync_pull_locked`.
struct SyncOutcome {
    status: sync::Status,
    new_base: Option<String>,
    pulled: bool,
}

/// Czy dany stan i rozstrzygnięcie kończą się pobraniem zdalnej wersji.
fn pulls(st: sync::Status, keep: Option<sync::Keep>) -> bool {
    matches!(
        (st, keep),
        (sync::Status::RemoteChanged, _) | (sync::Status::Conflict, Some(sync::Keep::Remote))
    )
}

/// Właściwa synchronizacja na `AppState`, bez `AppHandle` (dzięki temu da się ją testować).
/// Zdalny plik, który nie jest poprawnym plikiem MRMV, nie jest pobierany (błąd, lokalny plik
/// i konfiguracja bez zmian); poprawny plik z innym hasłem jest legalny. Po pobraniu klucz
/// znika z pamięci pod tą samą blokadą dokumentu, co operacja na pliku (współbieżny `mutate`
/// nie nadpisze pobranego pliku starym dokumentem), potem anulowane są pytania o zaufanie.
/// Zamknięcie sesji i zdarzenie `vault-locked` robi wywołujący przez `lock_all`.
async fn sync_pull_locked(
    state: &AppState,
    folder: &std::path::Path,
    base: Option<&str>,
    keep: Option<sync::Keep>,
) -> Result<SyncOutcome, String> {
    // Blokada dokumentu na czas operacji na pliku, żeby zapis z interfejsu się nie wtrącił.
    let mut guard = state.inner.lock().await;
    let planned = sync::status(&state.path, folder, base).map_err(err)?;
    if pulls(planned, keep) {
        let remote = sync::remote_path(folder);
        // Kontrola strukturalna, a gdy plik ma ten sam klucz co odblokowany sejf (ta sama sól
        // i parametry KDF), także pełne uwierzytelnienie: plik obcięty w szyfrogramie odpada.
        let checked = vault::validate_file(&remote).and_then(|()| match guard.as_ref() {
            Some(u) => u.vault.verify_file(&remote).map(|_| ()),
            None => Ok(()),
        });
        if let Err(e) = checked {
            state.log(format!("synchronizacja: odmowa pobrania, zdalny plik: {e}"));
            return Err(format!(
                "Zdalny plik nie wygląda na poprawny plik z hostami ({e}). Nie pobrano go, lokalny plik zostaje bez zmian."
            ));
        }
    }
    let (status, new_base) = sync::sync(&state.path, folder, base, keep).map_err(|e| match e {
        sync::Error::Conflict => "Konflikt: wybierz, którą wersję zachować.".to_string(),
        other => other.to_string(),
    })?;
    let pulled = pulls(status, keep);
    if pulled {
        *guard = None;
    }
    drop(guard);
    if pulled {
        state.cancel_trust();
        state.log(
            "synchronizacja: poprzednia lokalna wersja zachowana w pliku z końcówką .przed-pobraniem",
        );
    }
    Ok(SyncOutcome {
        status,
        new_base,
        pulled,
    })
}

/// Synchronizuje zgodnie ze stanem. W konflikcie wymaga `keep` ("local" albo "remote").
#[tauri::command]
pub async fn sync_run(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    keep: Option<String>,
) -> Result<SyncRun, String> {
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
    let out = sync_pull_locked(&state, &folder, base.as_deref(), keep).await?;
    if out.pulled {
        // Klucz już zniknął pod blokadą; `lock_all` dokańcza resztę (zaufanie, sesje, zdarzenie).
        crate::commands::lock_all(&app, &state, "synchronizacja: plik zablokowany po pobraniu")
            .await;
    }
    state.config.lock().expect("config").sync_base = out.new_base;
    state.save_config();
    state.log(format!(
        "synchronizacja: {}{}",
        status_name(out.status),
        if out.pulled {
            ", pobrano zdalną wersję"
        } else {
            ""
        }
    ));
    Ok(SyncRun {
        view: sync_view(&state),
        locked: out.pulled,
    })
}

/// Różnice między wersją lokalną a plikiem z folderu synchronizacji.
#[derive(Serialize)]
pub struct SyncDiff {
    /// `false`: plik z folderu ma inne hasło główne, więc nie da się go odczytać kluczem z pamięci.
    readable: bool,
    diff: Option<model::diff::DocDiff>,
}

/// Porównuje dokument z pamięci z plikiem z folderu. Plik jest tylko czytany: przechodzi tę samą
/// kontrolę struktury co przed pobraniem, a odszyfrowuje go klucz z pamięci (bez pytania o hasło).
/// Wynik nazywa różnice bez wartości pól, więc hasła i klucze nie trafiają do interfejsu;
/// komunikaty błędów nie przytaczają treści pliku.
async fn sync_diff_for(state: &AppState, folder: &std::path::Path) -> Result<SyncDiff, String> {
    let remote = sync::remote_path(folder);
    // Blokada dokumentu na czas porównania, żeby porównywać spójną wersję lokalną.
    let guard = state.inner.lock().await;
    let u = guard.as_ref().ok_or("Plik z hostami jest zablokowany")?;
    if !remote.is_file() {
        return Err("W folderze synchronizacji nie ma jeszcze pliku z hostami.".into());
    }
    vault::validate_file(&remote)
        .map_err(|e| format!("Plik w folderze nie wygląda na poprawny plik z hostami ({e})."))?;
    let other = u
        .vault
        .read_file::<Document>(&remote)
        .map_err(|e| match e {
            vault::Error::Decrypt => {
                "Plik w folderze jest uszkodzony: nie przechodzi uwierzytelnienia.".to_string()
            }
            vault::Error::Serde(_) => {
                "Plik w folderze ma nieznaną strukturę (być może pochodzi z nowszej wersji programu)."
                    .to_string()
            }
            other => format!("Nie można odczytać pliku z folderu: {other}."),
        })?;
    Ok(match other {
        None => SyncDiff {
            readable: false,
            diff: None,
        },
        Some(doc) => SyncDiff {
            readable: true,
            diff: Some(model::diff::diff(&u.doc, &doc)),
        },
    })
}

/// Pokazuje, czym różni się wersja lokalna od pliku w folderze synchronizacji. Niczego nie zmienia.
#[tauri::command]
pub async fn sync_diff(state: State<'_, AppState>) -> Result<SyncDiff, String> {
    let folder = state
        .config
        .lock()
        .expect("config")
        .sync_folder
        .clone()
        .ok_or("Synchronizacja nie jest skonfigurowana.")?;
    sync_diff_for(&state, &folder).await
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

/// Odszyfrowuje kopię zapasową. Kopię bez kluczy sprzętowych otwiera samo hasło. Kopia z tą samą
/// listą kluczy co otwarty plik korzysta z klucza danych z pamięci, więc klucza nie trzeba
/// dotykać. Kopii z inną listą kluczy program nie odczyta.
pub(crate) async fn read_backup(
    state: &AppState,
    n: usize,
    password: String,
) -> Result<Document, String> {
    let bad_password = || "Nieprawidłowe hasło dla tej kopii albo uszkodzona kopia.".to_string();
    let file = vault::backup_file(&state.path, n);
    let password = zeroize::Zeroizing::new(password);
    let (probe_file, probe) = (file.clone(), password.clone());
    let plain =
        tokio::task::spawn_blocking(move || vault::open_backup::<Document>(&probe_file, &probe))
            .await
            .map_err(err)?;
    match plain {
        Ok(doc) => Ok(doc),
        Err(vault::Error::NeedsKey) => {
            let guard = state.inner.lock().await;
            let u = guard.as_ref().ok_or("Plik z hostami jest zablokowany")?;
            // Argon2 liczy się długo: `block_in_place` nie zatrzymuje innych zadań tokio.
            tokio::task::block_in_place(|| u.vault.open_sibling::<Document>(&file, &password))
                .map_err(|e| match e {
                    vault::Error::Decrypt => bad_password(),
                    vault::Error::NeedsKey => {
                        "Ta kopia ma inną listę kluczy sprzętowych niż otwarty plik, więc program \
                         nie może jej odczytać."
                            .to_string()
                    }
                    other => other.to_string(),
                })
        }
        Err(vault::Error::Decrypt) => Err(bad_password()),
        Err(other) => Err(other.to_string()),
    }
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
    let doc = read_backup(&state, n, password).await?;
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
    backup_count: usize,
    check_updates: bool,
}

#[tauri::command]
pub async fn get_local_config(state: State<'_, AppState>) -> Result<LocalConfig, String> {
    Ok(local_config(&state))
}

fn local_config(state: &AppState) -> LocalConfig {
    // Jedna blokada: dwa `lock()` w jednym wyrażeniu zakleszczały wątek, bo tymczasowa blokada
    // z pierwszego pola żyje do końca całego wyrażenia.
    let (log_sessions, rdp_clipboard, backup_count, check_updates) = {
        let c = state.config.lock().expect("config");
        (
            c.log_sessions,
            c.rdp_clipboard,
            c.backup_count,
            c.check_updates,
        )
    };
    LocalConfig {
        log_sessions,
        rdp_clipboard,
        backup_count,
        check_updates,
        logs_dir: state.data_dir.join("logs").display().to_string(),
    }
}

/// Zmienia liczbę kopii zapasowych: zapis w config.json, ustawienie w otwartym pliku i usunięcie
/// kopii o numerach powyżej nowego limitu (do 20).
#[tauri::command]
pub async fn set_backup_count(state: State<'_, AppState>, count: usize) -> Result<(), String> {
    if !(1..=20).contains(&count) {
        return Err("Liczba kopii zapasowych musi być liczbą od 1 do 20.".into());
    }
    state.config.lock().expect("config").backup_count = count;
    state.save_config();
    if let Some(u) = state.inner.lock().await.as_mut() {
        u.vault.set_backup_count(count);
    }
    let removed = prune_backups(&state.path, count);
    state.log(format!("kopie zapasowe: limit {count}, usunięto {removed}"));
    Ok(())
}

/// Usuwa `.bak{n}` dla n w (count+1)..=20; zwraca liczbę usuniętych.
fn prune_backups(path: &std::path::Path, count: usize) -> usize {
    ((count + 1)..=20)
        .filter(|&n| std::fs::remove_file(vault::backup_file(path, n)).is_ok())
        .count()
}

#[tauri::command]
pub async fn set_log_sessions(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.config.lock().expect("config").log_sessions = enabled;
    state.save_config();
    Ok(())
}

/// Włącza albo wyłącza sprawdzanie nowej wersji przy starcie (pytanie do GitHuba wysyła interfejs).
#[tauri::command]
pub async fn set_check_updates(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    state.config.lock().expect("config").check_updates = enabled;
    state.save_config();
    Ok(())
}

/// Strona wydań programu. Stała: komenda otwierająca przeglądarkę nie przyjmuje adresu z interfejsu.
pub const RELEASES_URL: &str = "https://github.com/KazmirBO/remotemanager/releases";

/// Otwiera stronę wydań w domyślnej przeglądarce systemu. Adres jest stałą programu, więc do
/// polecenia systemowego nie trafia nic, co pochodzi z interfejsu albo z sieci.
#[tauri::command]
pub fn open_releases_page(state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(windows)]
    let mut cmd = {
        let mut c = std::process::Command::new("explorer");
        c.arg(RELEASES_URL);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(RELEASES_URL);
        c
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match cmd.spawn() {
        Ok(_) => Ok(()),
        Err(e) => {
            state.log(format!("nie udało się otworzyć strony wydań: {e}"));
            Err(format!(
                "Nie udało się otworzyć przeglądarki. Adres strony wydań: {RELEASES_URL}"
            ))
        }
    }
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

    #[test]
    fn prune_backups_removes_only_numbers_above_limit() {
        let dir = std::env::temp_dir().join(format!("mrm-prune-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.mrm");
        for n in 1..=8 {
            std::fs::write(vault::backup_file(&path, n), b"x").unwrap();
        }
        assert_eq!(prune_backups(&path, 5), 3);
        for n in 1..=5 {
            assert!(vault::backup_file(&path, n).exists(), "{n}");
        }
        for n in 6..=8 {
            assert!(!vault::backup_file(&path, n).exists(), "{n}");
        }
        assert_eq!(prune_backups(&path, 5), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    use crate::state::Unlocked;
    use tokio::sync::oneshot;
    use uuid::Uuid;
    use vault::{KdfParams, Vault};

    fn dirs(name: &str) -> (PathBuf, PathBuf) {
        let d = std::env::temp_dir().join(format!("mrm-maint-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let remote = d.join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        (d.join("hosts.mrm"), remote)
    }

    fn doc_with(name: &str) -> Document {
        let mut d = Document::default();
        d.tree.add_folder(name, None).unwrap();
        d
    }

    /// Stan z odblokowanym plikiem i jednym oczekującym pytaniem o zaufanie.
    async fn unlocked(path: PathBuf) -> (AppState, oneshot::Receiver<crate::state::TrustAnswer>) {
        let doc = doc_with("Lokalny");
        let vault = Vault::create(&path, "haslo", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let state = AppState::new(path);
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        let (tx, rx) = oneshot::channel();
        state.trust.lock().unwrap().insert(Uuid::new_v4(), tx);
        (state, rx)
    }

    #[tokio::test]
    async fn sync_diff_compares_with_remote_file_and_changes_nothing() {
        let (path, remote) = dirs("diff");
        let (state, _rx) = unlocked(path.clone()).await;
        // Bez pliku w folderze nie ma czego porównywać.
        let e = sync_diff_for(&state, &remote).await.err().unwrap();
        assert!(e.contains("nie ma jeszcze pliku"), "{e}");
        // Zsynchronizowane: brak różnic.
        sync::sync(&path, &remote, None, None).unwrap();
        let same = sync_diff_for(&state, &remote).await.unwrap();
        assert!(same.readable);
        assert!(same.diff.unwrap().is_empty());
        // Lokalna zmiana z hasłem: różnica nazwana, bez wartości.
        state
            .mutate(|d| {
                let id = d
                    .tree
                    .add_host("db", "10.0.0.5", model::Protocol::Ssh, None)
                    .map_err(err)?;
                d.tree
                    .hosts
                    .iter_mut()
                    .find(|h| h.id == id)
                    .unwrap()
                    .fields
                    .password = Some("sekret-bazy".into());
                Ok(())
            })
            .await
            .unwrap();
        let local_before = std::fs::read(&path).unwrap();
        let remote_before = std::fs::read(sync::remote_path(&remote)).unwrap();
        let out = sync_diff_for(&state, &remote).await.unwrap();
        let d = out.diff.unwrap();
        assert_eq!(d.hosts.len(), 1);
        assert_eq!(d.hosts[0].side, model::diff::Side::LocalOnly);
        assert_eq!(d.hosts[0].name, "db");
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("sekret-bazy"), "{json}");
        // Porównanie niczego nie zapisuje.
        assert_eq!(std::fs::read(&path).unwrap(), local_before);
        assert_eq!(
            std::fs::read(sync::remote_path(&remote)).unwrap(),
            remote_before
        );
        // Plik w folderze z innym hasłem głównym: nieczytelny, ale to nie błąd.
        let foreign = remote.join("obcy.mrm");
        Vault::create(
            &foreign,
            "inne-haslo",
            KdfParams::FAST_FOR_TESTS,
            &doc_with("Obcy"),
        )
        .unwrap();
        std::fs::copy(&foreign, sync::remote_path(&remote)).unwrap();
        let out = sync_diff_for(&state, &remote).await.unwrap();
        assert!(!out.readable);
        assert!(out.diff.is_none());
        // Uszkodzony i obcy plik: czytelny błąd.
        let mut broken = remote_before.clone();
        *broken.last_mut().unwrap() ^= 1;
        std::fs::write(sync::remote_path(&remote), &broken).unwrap();
        let e = sync_diff_for(&state, &remote).await.err().unwrap();
        assert!(e.contains("uszkodzony"), "{e}");
        std::fs::write(sync::remote_path(&remote), b"to nie jest plik z hostami").unwrap();
        let e = sync_diff_for(&state, &remote).await.err().unwrap();
        assert!(e.contains("nie wygląda na poprawny plik"), "{e}");
        // Zablokowany plik lokalny.
        *state.inner.lock().await = None;
        let e = sync_diff_for(&state, &remote).await.err().unwrap();
        assert!(e.contains("zablokowany"), "{e}");
    }

    #[tokio::test]
    async fn pull_locks_cancels_trust_and_keeps_previous_local_version() {
        let (path, remote) = dirs("pull");
        let (state, rx) = unlocked(path.clone()).await;
        let (_, base) = sync::sync(&path, &remote, None, None).unwrap();
        // Zdalna wersja zaszyfrowana innym hasłem (zmiana hasła głównego na innej maszynie).
        let other = remote.join("inne.mrm");
        Vault::create(
            &other,
            "nowe",
            KdfParams::FAST_FOR_TESTS,
            &doc_with("Zdalny"),
        )
        .unwrap();
        std::fs::copy(&other, sync::remote_path(&remote)).unwrap();
        let before = std::fs::read(&path).unwrap();

        let out = sync_pull_locked(&state, &remote, base.as_deref(), None)
            .await
            .unwrap();
        assert!(out.pulled);
        assert!(state.inner.lock().await.is_none(), "plik zablokowany");
        assert!(state.trust.lock().unwrap().is_empty());
        assert!(rx.await.is_err(), "pytanie o zaufanie anulowane");
        assert_eq!(
            std::fs::read(sync::pre_pull_copy(&path)).unwrap(),
            before,
            "poprzednia lokalna wersja leży w kopii"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            std::fs::read(sync::remote_path(&remote)).unwrap()
        );
    }

    #[tokio::test]
    async fn truncated_remote_is_refused_and_local_file_is_untouched() {
        let (path, remote) = dirs("trunc");
        let (state, _rx) = unlocked(path.clone()).await;
        let (_, base) = sync::sync(&path, &remote, None, None).unwrap();
        let before = std::fs::read(&path).unwrap();
        let remote_file = sync::remote_path(&remote);
        let full = std::fs::read(&remote_file).unwrap();
        std::fs::write(&remote_file, &full[..30]).unwrap();

        let err = sync_pull_locked(&state, &remote, base.as_deref(), None)
            .await
            .err()
            .expect("odmowa");
        assert!(err.contains("Nie pobrano"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!sync::pre_pull_copy(&path).exists());
        assert!(state.inner.lock().await.is_some(), "plik nadal odblokowany");
        assert_eq!(state.trust.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn remote_truncated_inside_ciphertext_with_same_key_is_refused() {
        let (path, remote) = dirs("trunc-mid");
        // Dokument na tyle duży, żeby szyfrogram był wyraźnie dłuższy od nagłówka.
        let mut doc = doc_with("Lokalny");
        for i in 0..50 {
            doc.tree.add_folder(format!("k{i}"), None).unwrap();
        }
        let vault = Vault::create(&path, "haslo", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let state = AppState::new(path.clone());
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        let (_, base) = sync::sync(&path, &remote, None, None).unwrap();
        let before = std::fs::read(&path).unwrap();
        let remote_file = sync::remote_path(&remote);
        let full = std::fs::read(&remote_file).unwrap();
        // Strukturalnie poprawny (dłuższy niż nagłówek i znacznik), ale ucięty w połowie.
        std::fs::write(&remote_file, &full[..full.len() / 2]).unwrap();
        vault::validate_file(&remote_file).expect("strukturalnie przechodzi");

        let err = sync_pull_locked(&state, &remote, base.as_deref(), None)
            .await
            .err()
            .expect("odmowa");
        assert!(err.contains("Nie pobrano"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!sync::pre_pull_copy(&path).exists());
        assert!(state.inner.lock().await.is_some(), "plik nadal odblokowany");
    }
}
