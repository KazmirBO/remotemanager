use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use model::Document;
use tokio::sync::oneshot;
use uuid::Uuid;
use vault::Vault;

use crate::config::Config;

pub struct Unlocked {
    pub vault: Vault,
    pub doc: Document,
}

pub struct Live {
    pub session: ssh::Session,
    pub shell: ssh::ShellHandle,
}

pub struct TrustAnswer {
    pub accept: bool,
    pub remember: bool,
}

const DIAG_LIMIT: usize = 500;

pub struct AppState {
    pub path: PathBuf,
    pub data_dir: PathBuf,
    pub config: Mutex<Config>,
    /// Dziennik diagnostyczny w pamięci. Nigdy nie trafiają tu hasła ani klucze.
    pub diag: Mutex<VecDeque<String>>,
    pub pending_link: Mutex<Option<String>>,
    pub inner: tokio::sync::Mutex<Option<Unlocked>>,
    pub sessions: Mutex<HashMap<Uuid, Arc<Live>>>,
    pub trust: Mutex<HashMap<Uuid, oneshot::Sender<TrustAnswer>>>,
    pub rdp: Mutex<HashMap<Uuid, rdp::RdpClient>>,
    pub rdp_clip: Mutex<HashMap<Uuid, Arc<crate::clipboard::ClipSync>>>,
    /// Kontrola przepływu obrazu sesji RDP (potwierdzenia z interfejsu).
    pub rdp_flow: Mutex<HashMap<Uuid, Arc<crate::rdp_sessions::Flow>>>,
    /// Licznik przeładowań interfejsu. Połączenie, które zaczęło się przed przeładowaniem, a skończyło
    /// po nim, nie ma karty w nowym interfejsie i zamyka się samo (jak przy blokadzie pliku).
    pub reloads: AtomicU64,
}

impl AppState {
    pub fn new(path: PathBuf) -> Self {
        let data_dir = path.parent().map(PathBuf::from).unwrap_or_default();
        let (config, warning) = Config::load(&data_dir.join("config.json"));
        let state = Self {
            path,
            data_dir,
            config: Mutex::new(config),
            diag: Mutex::new(VecDeque::new()),
            pending_link: Mutex::new(None),
            inner: tokio::sync::Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            trust: Mutex::new(HashMap::new()),
            rdp: Mutex::new(HashMap::new()),
            rdp_clip: Mutex::new(HashMap::new()),
            rdp_flow: Mutex::new(HashMap::new()),
            reloads: AtomicU64::new(0),
        };
        if let Some(w) = warning {
            state.log(w);
        }
        state
    }

    /// Dopisuje wpis do dziennika diagnostycznego (czas to sekundy epoki UNIX).
    pub fn log(&self, msg: impl AsRef<str>) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut d = self.diag.lock().expect("diag");
        if d.len() >= DIAG_LIMIT {
            d.pop_front();
        }
        d.push_back(format!("{secs} {}", msg.as_ref()));
    }

    pub fn save_config(&self) {
        let cfg = self.config.lock().expect("config").clone();
        if let Err(e) = cfg.save(&self.data_dir.join("config.json")) {
            self.log(format!("nie udało się zapisać konfiguracji: {e}"));
        }
    }

    /// Przed zapisem: czy plik jest zsynchronizowany, więc po zapisie można go wysłać automatycznie.
    /// Zwraca folder i wspólny skrót obu stron. To on jest bazą dla wysyłki po zapisie, a nie
    /// `sync_base` z konfiguracji, które bywa puste albo nieaktualne (ustawienie folderu je zeruje),
    /// przez co zwykły zapis wyglądałby jak konflikt i wysyłka cicho by ustała.
    pub fn sync_pre(&self) -> Option<(PathBuf, String)> {
        let folder = self.config.lock().expect("config").sync_folder.clone()?;
        if !folder.is_dir() {
            return None;
        }
        let local = sync::file_hash(&self.path).ok()??;
        let remote = sync::file_hash(&sync::remote_path(&folder)).ok()??;
        (local == remote).then_some((folder, local))
    }

    /// Po zapisie: wysyła plik, jeśli przed zapisem był zsynchronizowany. Stan sprawdzamy ponownie,
    /// bo w trakcie zapisu zdalny plik mógł się zmienić (np. Syncthing dostarczył wersję z innej
    /// maszyny); wtedy nie wysyłamy, a użytkownik zobaczy konflikt w oknie synchronizacji.
    /// Błąd trafia tylko do dziennika.
    pub fn sync_post(&self, pre: Option<(PathBuf, String)>) {
        let Some((folder, base)) = pre else { return };
        match sync::status(&self.path, &folder, Some(&base)) {
            Ok(sync::Status::LocalChanged) => {}
            Ok(st) => {
                self.log(format!(
                    "synchronizacja: pominięto automatyczną wysyłkę, stan po zapisie: {st:?}"
                ));
                return;
            }
            Err(e) => {
                self.log(format!(
                    "synchronizacja: automatyczna wysyłka nie powiodła się: {e}"
                ));
                return;
            }
        }
        match sync::push(&self.path, &folder, Some(&base)) {
            Ok(hash) => {
                self.config.lock().expect("config").sync_base = Some(hash);
                self.save_config();
                self.log("synchronizacja: plik wysłany automatycznie");
            }
            Err(e) => self.log(format!(
                "synchronizacja: automatyczna wysyłka nie powiodła się: {e}"
            )),
        }
    }

    /// Wykonuje mutację na kopii dokumentu, zapisuje plik i dopiero potem podmienia stan.
    pub async fn mutate<R>(
        &self,
        f: impl FnOnce(&mut Document) -> Result<R, String>,
    ) -> Result<R, String> {
        let mut guard = self.inner.lock().await;
        let u = guard.as_mut().ok_or("Plik z hostami jest zablokowany")?;
        let mut next = u.doc.clone();
        let out = f(&mut next)?;
        // Mutacja bez zmian nie zapisuje pliku: każdy zapis rotuje kopie `.bak` i wysyła plik
        // do synchronizacji, więc pusty zapis wypychałby starsze wersje z kopii.
        if next == u.doc {
            return Ok(out);
        }
        let pre = self.sync_pre();
        u.vault.save(&next).map_err(|e| e.to_string())?;
        u.doc = next;
        self.sync_post(pre);
        Ok(out)
    }

    /// Anuluje otwarte pytania o zaufanie do klucza hosta. Upuszczenie nadawców kończy oczekiwanie
    /// w `ask_trust` błędem odbioru, więc połączenie odrzuca klucz zamiast czekać 120 s.
    pub fn cancel_trust(&self) {
        self.trust.lock().expect("trust").clear();
    }

    pub async fn read<R>(
        &self,
        f: impl FnOnce(&Document) -> Result<R, String>,
    ) -> Result<R, String> {
        let guard = self.inner.lock().await;
        let u = guard.as_ref().ok_or("Plik z hostami jest zablokowany")?;
        f(&u.doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault::KdfParams;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("hosts.mrm")
    }

    async fn unlocked(name: &str) -> AppState {
        let path = tmp(name);
        let doc = Document::default();
        let vault = Vault::create(&path, "tajne-haslo", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let state = AppState::new(path);
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        state
    }

    #[tokio::test]
    async fn mutation_is_persisted_and_readable_after_reopen() {
        let state = unlocked("persist").await;
        state
            .mutate(|d| {
                d.tree
                    .add_folder("Firma", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
        let (_, doc) = Vault::open::<Document>(&state.path, "tajne-haslo").unwrap();
        assert_eq!(doc.tree.folders.len(), 1);
        assert_eq!(doc.tree.folders[0].name, "Firma");
    }

    #[tokio::test]
    async fn failed_mutation_changes_neither_memory_nor_file() {
        let state = unlocked("fail").await;
        let res: Result<(), String> = state
            .mutate(|d| {
                d.tree
                    .add_folder("Tymczasowy", None)
                    .map_err(|e| e.to_string())?;
                Err("błąd w trakcie".into())
            })
            .await;
        assert!(res.is_err());
        assert_eq!(state.read(|d| Ok(d.tree.folders.len())).await.unwrap(), 0);
        let (_, doc) = Vault::open::<Document>(&state.path, "tajne-haslo").unwrap();
        assert!(doc.tree.folders.is_empty());
    }

    #[tokio::test]
    async fn autosync_pushes_only_when_previously_in_sync() {
        let state = unlocked("autosync").await;
        let remote = state.data_dir.join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        let (_, base) = sync::sync(&state.path, &remote, None, None).unwrap();
        {
            let mut c = state.config.lock().unwrap();
            c.sync_folder = Some(remote.clone());
            c.sync_base = base;
        }
        // Zsynchronizowany plik: zmiana jest wysyłana automatycznie.
        state
            .mutate(|d| {
                d.tree
                    .add_folder("A", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&state.path).unwrap(),
            std::fs::read(sync::remote_path(&remote)).unwrap()
        );
        assert_eq!(
            state.config.lock().unwrap().sync_base,
            sync::file_hash(&state.path).unwrap()
        );

        // Ktoś zmienił zdalny plik: kolejny zapis nie może go nadpisać.
        std::fs::write(sync::remote_path(&remote), b"zmiana z innej maszyny").unwrap();
        state
            .mutate(|d| {
                d.tree
                    .add_folder("B", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(sync::remote_path(&remote)).unwrap(),
            b"zmiana z innej maszyny"
        );
        assert!(
            state
                .diag
                .lock()
                .unwrap()
                .iter()
                .all(|l| !l.contains("zmiana z innej maszyny"))
        );
    }

    #[tokio::test]
    async fn autosync_works_without_stored_base() {
        let state = unlocked("autosync-nobase").await;
        let remote = state.data_dir.join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        // Folder ma już identyczny plik, a bazy nie ma (tak jest po ustawieniu folderu).
        std::fs::copy(&state.path, sync::remote_path(&remote)).unwrap();
        state.config.lock().unwrap().sync_folder = Some(remote.clone());
        assert_eq!(state.config.lock().unwrap().sync_base, None);
        state
            .mutate(|d| {
                d.tree
                    .add_folder("A", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&state.path).unwrap(),
            std::fs::read(sync::remote_path(&remote)).unwrap(),
            "zapis został wysłany mimo braku bazy"
        );
        assert_eq!(
            state.config.lock().unwrap().sync_base,
            sync::file_hash(&state.path).unwrap()
        );
        let konflikty = std::fs::read_dir(&remote)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".konflikt-")
            })
            .count();
        assert_eq!(konflikty, 0);
    }

    #[tokio::test]
    async fn autosync_skips_push_when_remote_changed_during_save() {
        let state = unlocked("autosync-race").await;
        let remote = state.data_dir.join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        let (_, base) = sync::sync(&state.path, &remote, None, None).unwrap();
        {
            let mut c = state.config.lock().unwrap();
            c.sync_folder = Some(remote.clone());
            c.sync_base = base.clone();
        }
        let pre = state.sync_pre();
        assert!(pre.is_some());
        // Zapis lokalny i jednocześnie nowa wersja z innej maszyny.
        std::fs::write(&state.path, b"lokalny zapis").unwrap();
        std::fs::write(sync::remote_path(&remote), b"z innej maszyny").unwrap();
        state.sync_post(pre);
        assert_eq!(
            std::fs::read(sync::remote_path(&remote)).unwrap(),
            b"z innej maszyny"
        );
        assert_eq!(state.config.lock().unwrap().sync_base, base);
        let konflikty = std::fs::read_dir(&remote)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".konflikt-")
            })
            .count();
        assert_eq!(konflikty, 0);
    }

    #[tokio::test]
    async fn diagnostics_are_bounded() {
        let state = AppState::new(tmp("diag"));
        for i in 0..700 {
            state.log(format!("wpis {i}"));
        }
        let d = state.diag.lock().unwrap();
        assert_eq!(d.len(), 500);
        assert!(d.back().unwrap().ends_with("wpis 699"));
    }

    #[tokio::test]
    async fn mutation_without_changes_does_not_write_file() {
        let state = unlocked("noop").await;
        let before = std::fs::read(&state.path).unwrap();
        state.mutate(|_| Ok(())).await.unwrap();
        assert_eq!(std::fs::read(&state.path).unwrap(), before);
        assert!(!vault::backup_file(&state.path, 1).exists());

        // Prawdziwa zmiana nadal zapisuje plik (nowy nonce zmienia bajty).
        state
            .mutate(|d| {
                d.tree
                    .add_folder("Zmiana", None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap();
        assert_ne!(std::fs::read(&state.path).unwrap(), before);
    }

    #[tokio::test]
    async fn cancel_trust_drops_pending_questions() {
        let state = AppState::new(tmp("cancel-trust"));
        let (tx, rx) = oneshot::channel::<TrustAnswer>();
        state.trust.lock().unwrap().insert(Uuid::new_v4(), tx);
        state.cancel_trust();
        assert!(state.trust.lock().unwrap().is_empty());
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn reload_closes_sessions_and_trust_but_keeps_file_unlocked() {
        let state = unlocked("reload").await;
        *state.pending_link.lock().unwrap() = Some("ssh://srv".into());
        let (tx, rx) = oneshot::channel::<TrustAnswer>();
        state.trust.lock().unwrap().insert(Uuid::new_v4(), tx);
        crate::commands::reset_after_reload(&state).await;
        assert!(state.sessions.lock().unwrap().is_empty());
        assert!(state.rdp.lock().unwrap().is_empty());
        assert!(state.trust.lock().unwrap().is_empty());
        assert!(rx.await.is_err());
        // Plik zostaje odblokowany, a link czekający na odblokowanie nie ginie.
        assert!(state.read(|_| Ok(())).await.is_ok());
        assert_eq!(
            state.pending_link.lock().unwrap().as_deref(),
            Some("ssh://srv")
        );
        assert_eq!(state.reloads.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Pierwsze ładowanie bez sesji niczego nie wpisuje do dziennika.
        assert!(state.diag.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn locked_state_rejects_access() {
        let state = AppState::new(tmp("locked"));
        assert!(state.read(|_| Ok(())).await.is_err());
        assert!(state.mutate(|_| Ok(())).await.is_err());
    }
}
