//! Synchronizacja zaszyfrowanego pliku przez folder (np. Syncthing, Nextcloud, dysk sieciowy).
//!
//! Plik jest nieprzezroczysty dla tego crate'a: porównujemy skróty SHA-256 trzech wersji:
//! lokalnej, zdalnej i bazowej (skrót z chwili ostatniej udanej synchronizacji). Zmiana po jednej
//! stronie to zwykła wysyłka albo pobranie, zmiana po obu to konflikt rozstrzygany przez użytkownika.
//! Przegrana kopia nigdy nie jest tracona: zostaje obok jako `*.konflikt-<czas>`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("błąd wejścia/wyjścia: {0}")]
    Io(#[from] io::Error),
    #[error("brak lokalnego pliku z hostami")]
    LocalMissing,
    #[error("brak zdalnego pliku do pobrania")]
    RemoteMissing,
    #[error("folder synchronizacji nie istnieje: {0}")]
    NoFolder(PathBuf),
    #[error("operacja wymaga rozstrzygnięcia konfliktu")]
    Conflict,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Stan względem folderu synchronizacji.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// W folderze nie ma jeszcze pliku.
    RemoteMissing,
    InSync,
    /// Zmieniono tylko lokalnie: można wysłać.
    LocalChanged,
    /// Zmieniono tylko zdalnie: można pobrać.
    RemoteChanged,
    /// Zmieniono po obu stronach od ostatniej synchronizacji.
    Conflict,
}

/// Rozstrzygnięcie konfliktu: która wersja wygrywa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    Local,
    Remote,
}

/// Nazwa pliku w folderze synchronizacji.
pub const REMOTE_NAME: &str = "hosts.mrm";

pub fn remote_path(folder: &Path) -> PathBuf {
    folder.join(REMOTE_NAME)
}

/// Skrót SHA-256 pliku (hex) albo `None`, gdy pliku nie ma.
pub fn file_hash(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(hex(&Sha256::digest(&bytes)))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wyznacza stan na podstawie skrótów lokalnego, zdalnego i bazowego pliku.
pub fn classify(local: Option<&str>, remote: Option<&str>, base: Option<&str>) -> Status {
    match (local, remote) {
        (_, None) => Status::RemoteMissing,
        (Some(l), Some(r)) if l == r => Status::InSync,
        (None, Some(_)) => Status::RemoteChanged,
        (Some(l), Some(r)) => match base {
            Some(b) if l == b => Status::RemoteChanged,
            Some(b) if r == b => Status::LocalChanged,
            // Bez bazy (pierwsza synchronizacja) albo obie strony różne od bazy.
            _ => Status::Conflict,
        },
    }
}

pub fn status(local: &Path, folder: &Path, base: Option<&str>) -> Result<Status> {
    if !folder.is_dir() {
        return Err(Error::NoFolder(folder.to_owned()));
    }
    let l = file_hash(local)?;
    let r = file_hash(&remote_path(folder))?;
    Ok(classify(l.as_deref(), r.as_deref(), base))
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn conflict_copy(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".konflikt-{}", timestamp()));
    PathBuf::from(name)
}

/// Kopiuje `from` do `to` atomowo (plik tymczasowy obok celu, `fsync`, `rename`).
fn copy_atomic(from: &Path, to: &Path) -> Result<()> {
    let data = fs::read(from)?;
    let mut tmp = to.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, to)?;
    Ok(())
}

/// Wysyła lokalny plik do folderu. Jeśli zdalny plik się różni, jego kopia trafia do `*.konflikt-*`.
/// Zwraca nowy skrót bazowy.
pub fn push(local: &Path, folder: &Path) -> Result<String> {
    if !folder.is_dir() {
        return Err(Error::NoFolder(folder.to_owned()));
    }
    let local_hash = file_hash(local)?.ok_or(Error::LocalMissing)?;
    let remote = remote_path(folder);
    if let Some(rh) = file_hash(&remote)?
        && rh != local_hash
    {
        copy_atomic(&remote, &conflict_copy(&remote))?;
    }
    copy_atomic(local, &remote)?;
    Ok(local_hash)
}

/// Pobiera zdalny plik na miejsce lokalnego. Lokalna wersja, jeśli się różni, zostaje jako `*.konflikt-*`.
/// Zwraca nowy skrót bazowy.
pub fn pull(local: &Path, folder: &Path) -> Result<String> {
    let remote = remote_path(folder);
    let remote_hash = file_hash(&remote)?.ok_or(Error::RemoteMissing)?;
    if let Some(lh) = file_hash(local)?
        && lh != remote_hash
    {
        copy_atomic(local, &conflict_copy(local))?;
    }
    copy_atomic(&remote, local)?;
    Ok(remote_hash)
}

/// Wykonuje synchronizację zgodnie ze stanem. W konflikcie wymaga `keep`, w pozostałych przypadkach
/// `keep` jest ignorowane. Zwraca stan sprzed działania i nowy skrót bazowy (`None`, gdy nic nie zrobiono).
pub fn sync(
    local: &Path,
    folder: &Path,
    base: Option<&str>,
    keep: Option<Keep>,
) -> Result<(Status, Option<String>)> {
    let st = status(local, folder, base)?;
    let new_base = match (st, keep) {
        (Status::InSync, _) => file_hash(local)?,
        (Status::RemoteMissing | Status::LocalChanged, _) => Some(push(local, folder)?),
        (Status::RemoteChanged, _) => Some(pull(local, folder)?),
        (Status::Conflict, Some(Keep::Local)) => Some(push(local, folder)?),
        (Status::Conflict, Some(Keep::Remote)) => Some(pull(local, folder)?),
        (Status::Conflict, None) => return Err(Error::Conflict),
    };
    Ok((st, new_base))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        root: PathBuf,
        local: PathBuf,
        folder: PathBuf,
    }

    impl Dirs {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("mrm-sync-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let folder = root.join("remote");
            fs::create_dir_all(&folder).unwrap();
            Self {
                local: root.join("hosts.mrm"),
                folder,
                root,
            }
        }
        fn remote(&self) -> PathBuf {
            remote_path(&self.folder)
        }
        fn conflicts(&self, dir: &Path) -> usize {
            fs::read_dir(dir)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(".konflikt-")
                })
                .count()
        }
    }

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn classify_covers_all_cases() {
        use Status::*;
        assert_eq!(classify(Some("a"), None, None), RemoteMissing);
        assert_eq!(classify(Some("a"), Some("a"), Some("x")), InSync);
        assert_eq!(classify(Some("b"), Some("a"), Some("a")), LocalChanged);
        assert_eq!(classify(Some("a"), Some("b"), Some("a")), RemoteChanged);
        assert_eq!(classify(Some("b"), Some("c"), Some("a")), Conflict);
        assert_eq!(classify(Some("b"), Some("c"), None), Conflict);
        assert_eq!(classify(None, Some("c"), None), RemoteChanged);
    }

    #[test]
    fn first_sync_pushes_then_stays_in_sync() {
        let d = Dirs::new("first");
        fs::write(&d.local, b"v1").unwrap();
        let (st, base) = sync(&d.local, &d.folder, None, None).unwrap();
        assert_eq!(st, Status::RemoteMissing);
        assert_eq!(fs::read(d.remote()).unwrap(), b"v1");
        let (st, _) = sync(&d.local, &d.folder, base.as_deref(), None).unwrap();
        assert_eq!(st, Status::InSync);
    }

    #[test]
    fn local_edit_is_pushed_and_remote_edit_is_pulled() {
        let d = Dirs::new("edits");
        fs::write(&d.local, b"v1").unwrap();
        let (_, base) = sync(&d.local, &d.folder, None, None).unwrap();

        fs::write(&d.local, b"v2-local").unwrap();
        let (st, base) = sync(&d.local, &d.folder, base.as_deref(), None).unwrap();
        assert_eq!(st, Status::LocalChanged);
        assert_eq!(fs::read(d.remote()).unwrap(), b"v2-local");

        fs::write(d.remote(), b"v3-remote").unwrap();
        let (st, base) = sync(&d.local, &d.folder, base.as_deref(), None).unwrap();
        assert_eq!(st, Status::RemoteChanged);
        assert_eq!(fs::read(&d.local).unwrap(), b"v3-remote");
        assert_eq!(base, file_hash(&d.local).unwrap());
    }

    #[test]
    fn conflict_needs_a_choice_and_keeps_the_loser() {
        let d = Dirs::new("conflict");
        fs::write(&d.local, b"v1").unwrap();
        let (_, base) = sync(&d.local, &d.folder, None, None).unwrap();
        fs::write(&d.local, b"local-edit").unwrap();
        fs::write(d.remote(), b"remote-edit").unwrap();

        assert!(matches!(
            sync(&d.local, &d.folder, base.as_deref(), None),
            Err(Error::Conflict)
        ));
        // Odmowa niczego nie zmieniła.
        assert_eq!(fs::read(&d.local).unwrap(), b"local-edit");
        assert_eq!(fs::read(d.remote()).unwrap(), b"remote-edit");

        sync(&d.local, &d.folder, base.as_deref(), Some(Keep::Remote)).unwrap();
        assert_eq!(fs::read(&d.local).unwrap(), b"remote-edit");
        assert_eq!(
            d.conflicts(&d.root),
            1,
            "lokalna wersja zostaje jako kopia konfliktu"
        );
        let saved = fs::read_dir(&d.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains(".konflikt-"))
            .unwrap();
        assert_eq!(fs::read(saved).unwrap(), b"local-edit");
    }

    #[test]
    fn keeping_local_preserves_remote_copy() {
        let d = Dirs::new("keeplocal");
        fs::write(&d.local, b"v1").unwrap();
        let (_, base) = sync(&d.local, &d.folder, None, None).unwrap();
        fs::write(&d.local, b"L").unwrap();
        fs::write(d.remote(), b"R").unwrap();
        sync(&d.local, &d.folder, base.as_deref(), Some(Keep::Local)).unwrap();
        assert_eq!(fs::read(d.remote()).unwrap(), b"L");
        assert_eq!(d.conflicts(&d.folder), 1);
    }

    #[test]
    fn errors_for_missing_pieces() {
        let d = Dirs::new("errors");
        assert!(matches!(
            push(&d.local, &d.folder),
            Err(Error::LocalMissing)
        ));
        assert!(matches!(
            pull(&d.local, &d.folder),
            Err(Error::RemoteMissing)
        ));
        assert!(matches!(
            status(&d.local, &d.root.join("nie-ma"), None),
            Err(Error::NoFolder(_))
        ));
    }

    #[test]
    fn pull_into_missing_local_file_works() {
        let d = Dirs::new("pullnew");
        fs::write(d.remote(), b"zdalny").unwrap();
        let (st, base) = sync(&d.local, &d.folder, None, None).unwrap();
        assert_eq!(st, Status::RemoteChanged);
        assert_eq!(fs::read(&d.local).unwrap(), b"zdalny");
        assert!(base.is_some());
    }
}
