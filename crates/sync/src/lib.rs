//! Synchronizacja zaszyfrowanego pliku przez folder (np. Syncthing, Nextcloud, dysk sieciowy).
//!
//! Plik jest nieprzezroczysty dla tego crate'a: porównujemy skróty SHA-256 trzech wersji:
//! lokalnej, zdalnej i bazowej (skrót z chwili ostatniej udanej synchronizacji). Zmiana po jednej
//! stronie to zwykła wysyłka albo pobranie, zmiana po obu to konflikt rozstrzygany przez użytkownika.
//! Przegrana kopia nigdy nie jest tracona: zostaje obok jako `*.konflikt-<czas>`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Wolna nazwa kopii konfliktu obok `path`. Dwie kopie w tej samej sekundzie dostają licznik,
/// żeby druga nie nadpisała pierwszej.
fn conflict_copy(path: &Path) -> PathBuf {
    let stamp = timestamp();
    (0u32..)
        .map(|n| {
            let mut name = path.as_os_str().to_owned();
            if n == 0 {
                name.push(format!(".konflikt-{stamp}"));
            } else {
                name.push(format!(".konflikt-{stamp}-{n}"));
            }
            PathBuf::from(name)
        })
        .find(|p| !p.exists())
        .expect("nieskończony iterator")
}

/// Unikalna nazwa pliku tymczasowego obok `to`: `.<nazwa>.<pid>-<nanosekundy>-<licznik>.tmp`.
fn tmp_path(to: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = std::ffi::OsString::from(".");
    name.push(to.file_name().unwrap_or_default());
    name.push(format!(
        ".{}-{nanos}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    to.with_file_name(name)
}

/// Kopiuje `from` do `to` atomowo: plik tymczasowy o unikalnej nazwie obok celu (`create_new`, więc
/// bez podążania za dowiązaniem i bez dzielenia pliku z drugą maszyną na dysku sieciowym; na Unix
/// tryb 0600), `fsync`, `rename` i `fsync` katalogu. Przy błędzie plik tymczasowy jest usuwany.
fn copy_atomic(from: &Path, to: &Path) -> Result<()> {
    let data = fs::read(from)?;
    let mut tmp = tmp_path(to);
    let mut tries = 0;
    let mut f = loop {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        match opts.open(&tmp) {
            Ok(f) => break f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && tries < 8 => {
                tries += 1;
                tmp = tmp_path(to);
            }
            Err(e) => return Err(e.into()),
        }
    };
    let done = f
        .write_all(&data)
        .and_then(|()| f.sync_all())
        .and_then(|()| {
            drop(f);
            fs::rename(&tmp, to)
        });
    if let Err(e) = done {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        let dir = match to.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        let _ = fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Wysyła lokalny plik do folderu. Jeśli zdalny plik zawiera zmiany, których nie ma w bazie
/// (`base`, skrót z ostatniej synchronizacji), jego kopia trafia do `*.konflikt-*`. Zwykła wysyłka
/// po zmianie lokalnej (zdalny plik równy bazie) nie tworzy kopii. Zwraca nowy skrót bazowy.
pub fn push(local: &Path, folder: &Path, base: Option<&str>) -> Result<String> {
    if !folder.is_dir() {
        return Err(Error::NoFolder(folder.to_owned()));
    }
    let local_hash = file_hash(local)?.ok_or(Error::LocalMissing)?;
    let remote = remote_path(folder);
    if let Some(rh) = file_hash(&remote)?
        && rh != local_hash
        && Some(rh.as_str()) != base
    {
        copy_atomic(&remote, &conflict_copy(&remote))?;
    }
    copy_atomic(local, &remote)?;
    Ok(local_hash)
}

/// Kopia lokalnej wersji sprzed pobrania. Jest jedna i nadpisywana przy kolejnym pobraniu;
/// to nie jest kopia konfliktu.
pub fn pre_pull_copy(local: &Path) -> PathBuf {
    let mut name = local.as_os_str().to_owned();
    name.push(".przed-pobraniem");
    PathBuf::from(name)
}

/// Pobiera zdalny plik na miejsce lokalnego. Lokalna wersja, jeśli zawiera zmiany spoza bazy,
/// zostaje jako `*.konflikt-*`. Niezależnie od tego bieżąca lokalna wersja trafia (atomowo)
/// do `pre_pull_copy`, bo zdalny plik mógł okazać się bezużyteczny. Zwraca nowy skrót bazowy.
pub fn pull(local: &Path, folder: &Path, base: Option<&str>) -> Result<String> {
    let remote = remote_path(folder);
    let remote_hash = file_hash(&remote)?.ok_or(Error::RemoteMissing)?;
    if let Some(lh) = file_hash(local)?
        && lh != remote_hash
        && Some(lh.as_str()) != base
    {
        copy_atomic(local, &conflict_copy(local))?;
    }
    if local.exists() {
        copy_atomic(local, &pre_pull_copy(local))?;
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
        (Status::RemoteMissing | Status::LocalChanged, _) => Some(push(local, folder, base)?),
        (Status::RemoteChanged, _) => Some(pull(local, folder, base)?),
        (Status::Conflict, Some(Keep::Local)) => Some(push(local, folder, base)?),
        (Status::Conflict, Some(Keep::Remote)) => Some(pull(local, folder, base)?),
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
        // Zwykła wysyłka i zwykłe pobranie nie zostawiają kopii konfliktu po żadnej stronie.
        assert_eq!(d.conflicts(&d.root), 0);
        assert_eq!(d.conflicts(&d.folder), 0);
    }

    #[test]
    fn pull_keeps_one_overwritten_copy_of_the_local_version() {
        let d = Dirs::new("prepull");
        fs::write(&d.local, b"v1").unwrap();
        let (_, base) = sync(&d.local, &d.folder, None, None).unwrap();
        fs::write(d.remote(), b"v2-remote").unwrap();
        let (_, base) = sync(&d.local, &d.folder, base.as_deref(), None).unwrap();
        assert_eq!(fs::read(pre_pull_copy(&d.local)).unwrap(), b"v1");
        fs::write(d.remote(), b"v3-remote").unwrap();
        sync(&d.local, &d.folder, base.as_deref(), None).unwrap();
        // Kopia jest jedna i dotyczy ostatnio nadpisanej wersji; to nie kopia konfliktu.
        assert_eq!(fs::read(pre_pull_copy(&d.local)).unwrap(), b"v2-remote");
        assert_eq!(d.conflicts(&d.root), 0);
    }

    #[test]
    fn conflict_copies_in_the_same_second_do_not_overwrite_each_other() {
        let d = Dirs::new("samesecond");
        fs::write(&d.local, b"L").unwrap();
        fs::write(d.remote(), b"R1").unwrap();
        push(&d.local, &d.folder, None).unwrap();
        fs::write(d.remote(), b"R2").unwrap();
        push(&d.local, &d.folder, None).unwrap();
        assert_eq!(d.conflicts(&d.folder), 2);
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
            push(&d.local, &d.folder, None),
            Err(Error::LocalMissing)
        ));
        assert!(matches!(
            pull(&d.local, &d.folder, None),
            Err(Error::RemoteMissing)
        ));
        assert!(matches!(
            status(&d.local, &d.root.join("nie-ma"), None),
            Err(Error::NoFolder(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn push_does_not_follow_symlink_and_keeps_file_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = Dirs::new("symlink");
        let victim = d.root.join("ofiara.txt");
        fs::write(&victim, b"nietkniete").unwrap();
        // Dawna stała nazwa pliku tymczasowego nie może przekierować zapisu.
        std::os::unix::fs::symlink(&victim, d.folder.join("hosts.mrm.tmp")).unwrap();
        fs::write(&d.local, b"v1").unwrap();
        push(&d.local, &d.folder, None).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"nietkniete");
        assert_eq!(fs::read(d.remote()).unwrap(), b"v1");
        assert!(!fs::symlink_metadata(d.remote()).unwrap().is_symlink());
        let mode = fs::metadata(d.remote()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Poza dowiązaniem nie zostają pliki tymczasowe.
        let tmps = fs::read_dir(&d.folder)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(tmps, 1);
    }

    #[test]
    fn failed_copy_leaves_no_temp_file() {
        let d = Dirs::new("tmpclean");
        fs::write(&d.local, b"v1").unwrap();
        // Cel będący katalogiem: plik tymczasowy powstaje, a `rename` się nie udaje.
        fs::create_dir_all(d.remote()).unwrap();
        assert!(copy_atomic(&d.local, &d.remote()).is_err());
        let tmps = fs::read_dir(&d.folder)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(tmps, 0);
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
