//! Zaszyfrowany plik z danymi aplikacji.
//!
//! Format (wszystkie liczby little-endian):
//! `magic "MRMV" | wersja u8 | m_cost u32 | t_cost u32 | p_cost u32 | sol[16] | nonce[24] | szyfrogram`.
//! Nagłówek (bajty przed szyfrogramem) jest uwierzytelniany jako AAD, więc jego modyfikacja
//! jest wykrywana. Klucz wynika z hasła głównego przez Argon2id, szyfr to XChaCha20-Poly1305.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MRMV";
/// Aktualna wersja formatu pliku.
pub const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN + NONCE_LEN;
/// Górne limity parametrów Argon2id przyjmowanych z nagłówka (pamięć w KiB: 4 GiB).
const MAX_M_COST: u32 = 4 * 1024 * 1024;
const MAX_T_COST: u32 = 100;
const MAX_P_COST: u32 = 64;
/// Domyślna liczba zachowywanych kopii zapasowych.
pub const DEFAULT_BACKUPS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("błąd wejścia/wyjścia: {0}")]
    Io(#[from] io::Error),
    #[error("to nie jest plik z hostami (zły nagłówek)")]
    BadMagic,
    #[error("plik jest uszkodzony lub obcięty")]
    Truncated,
    #[error("nieobsługiwana wersja formatu: {0}")]
    UnsupportedVersion(u8),
    #[error("nieprawidłowe hasło główne albo uszkodzony plik")]
    Decrypt,
    #[error("nieprawidłowe parametry KDF")]
    BadKdfParams,
    #[error("błąd szyfrowania")]
    Encrypt,
    #[error("błąd serializacji: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("błąd losowania: {0}")]
    Random(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Parametry Argon2id zapisywane w nagłówku.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Pamięć w KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Wartości domyślne (64 MiB, 3 przebiegi, 1 wątek). Do przestrojenia benchmarkiem na obu platformach.
    pub const DEFAULT: Self = Self {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
    /// Tanie parametry wyłącznie do testów.
    pub const FAST_FOR_TESTS: Self = Self {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
}

/// Wynik `Vault::verify_file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// Ten sam klucz, plik uwierzytelniony.
    SameKey,
    /// Inna sól (zmiana hasła głównego gdzie indziej): nie da się sprawdzić bez hasła.
    OtherKey,
}

/// Otwarty plik: trzyma klucz, więc zapis nie wymaga ponownego KDF.
pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    backups: usize,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| Error::Random(e.to_string()))?;
    Ok(buf)
}

fn derive_key(password: &[u8], salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|_| Error::BadKdfParams)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| Error::BadKdfParams)?;
    Ok(key)
}

fn encode_header(kdf: KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.push(FORMAT_VERSION);
    h.extend_from_slice(&kdf.m_cost.to_le_bytes());
    h.extend_from_slice(&kdf.t_cost.to_le_bytes());
    h.extend_from_slice(&kdf.p_cost.to_le_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    h
}

/// Licznik bajtów udający `Write`: pozwala poznać długość serializacji przed właściwym zapisem.
struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Unikalna nazwa pliku tymczasowego obok `path`: `.<nazwa>.<losowe>.tmp`.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    let rnd = random::<8>().unwrap_or([0; 8]);
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    name.push(format!(".{}-{hex}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Pierwsza połowa zapisu atomowego: plik tymczasowy o unikalnej nazwie w tym samym katalogu
/// (`create_new`, więc bez podążania za dowiązaniem i bez dzielenia pliku z innym procesem;
/// na Unix tryb 0600) i `fsync`. Zwraca ścieżkę pliku tymczasowego, który potem trafia na miejsce
/// docelowe przez `rename`. Przy błędzie plik tymczasowy jest usuwany.
fn write_tmp(path: &Path, data: &[u8]) -> io::Result<PathBuf> {
    let mut last = None;
    for _ in 0..8 {
        let tmp = tmp_path(path);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        match opts.open(&tmp) {
            Ok(mut f) => {
                let res = f.write_all(data).and_then(|()| f.sync_all());
                drop(f);
                return match res {
                    Ok(()) => Ok(tmp),
                    Err(e) => {
                        let _ = fs::remove_file(&tmp);
                        Err(e)
                    }
                };
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("nie udało się utworzyć pliku tymczasowego")))
}

/// Utrwala wpis katalogu po `rename` (Unix; błąd ignorowany, to tylko dodatkowa trwałość).
fn sync_dir(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        let _ = fs::File::open(dir).and_then(|d| d.sync_all());
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn backup_path(path: &Path, n: usize) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(format!(".bak{n}"));
    PathBuf::from(p)
}

impl Vault {
    /// Tworzy nowy plik z zadanym dokumentem. Odmawia nadpisania istniejącego pliku.
    pub fn create<T: Serialize>(
        path: impl Into<PathBuf>,
        password: &str,
        kdf: KdfParams,
        doc: &T,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "plik już istnieje",
            )));
        }
        let salt = random::<SALT_LEN>()?;
        let key = derive_key(password.as_bytes(), &salt, kdf)?;
        let v = Self {
            path,
            key,
            salt,
            kdf,
            backups: DEFAULT_BACKUPS,
        };
        v.write(doc, false)?;
        Ok(v)
    }

    /// Otwiera plik i odszyfrowuje dokument.
    pub fn open<T: DeserializeOwned>(
        path: impl Into<PathBuf>,
        password: &str,
    ) -> Result<(Self, T)> {
        let path = path.into();
        let data = fs::read(&path)?;
        let (kdf, salt, nonce) = parse_header(&data)?;
        let key = derive_key(password.as_bytes(), &salt, kdf)?;
        let doc = decrypt(&key, &data, &nonce)?;
        Ok((
            Self {
                path,
                key,
                salt,
                kdf,
                backups: DEFAULT_BACKUPS,
            },
            doc,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sprawdza inny plik kluczem z pamięci, bez pytania o hasło. Gdy sól i parametry KDF w jego
    /// nagłówku jest taka sama jak w tym sejfie, uwierzytelnia całość (nagłówek z parametrami KDF
    /// jest AAD, więc inne parametry przy tej samej soli to uszkodzenie) i zwraca `SameKey` albo
    /// błąd; inna sól (zmiana hasła głównego gdzie indziej) daje `OtherKey` bez błędu, bo nie ma
    /// czym sprawdzić. Odszyfrowana treść jest zerowana i nie opuszcza funkcji.
    pub fn verify_file(&self, path: &Path) -> Result<Verified> {
        let data = fs::read(path)?;
        let (_, salt, nonce) = parse_header(&data)?;
        if salt != self.salt {
            return Ok(Verified::OtherKey);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Decrypt)?;
        let _plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &data[HEADER_LEN..],
                        aad: &data[..HEADER_LEN],
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        Ok(Verified::SameKey)
    }

    pub fn set_backup_count(&mut self, n: usize) {
        self.backups = n;
    }

    /// Zapisuje dokument; przed nadpisaniem rotuje kopie `.bak1` (najnowsza) ... `.bakN`.
    pub fn save<T: Serialize>(&self, doc: &T) -> Result<()> {
        self.write(doc, true)
    }

    /// Zmienia hasło główne: nowa sól, nowy klucz, zapis całego dokumentu. Klucz w pamięci zmienia
    /// się dopiero po udanym zapisie, więc nieudana zmiana zostawia stare hasło w mocy.
    pub fn change_password<T: Serialize>(&mut self, new_password: &str, doc: &T) -> Result<()> {
        let salt = random::<SALT_LEN>()?;
        let key = derive_key(new_password.as_bytes(), &salt, self.kdf)?;
        self.write_with(&key, &salt, doc, true)?;
        self.key = key;
        self.salt = salt;
        Ok(())
    }

    fn write<T: Serialize>(&self, doc: &T, rotate: bool) -> Result<()> {
        self.write_with(&self.key, &self.salt, doc, rotate)
    }

    /// Zapis: szyfrowanie, plik tymczasowy z `fsync`, dopiero potem rotacja kopii i `rename`.
    /// Błąd przed rotacją (szyfrowanie, plik tymczasowy) nie rusza ani pliku, ani kopii `.bakN`.
    /// Błąd samego `rename` następuje już po rotacji: plik zostaje bez zmian, ale kopie są
    /// przesunięte, a `.bak1` jest kopią bieżącego pliku, więc powtarzane niepowodzenia
    /// wypełniają kopie tą samą wersją.
    fn write_with<T: Serialize>(
        &self,
        key: &[u8; 32],
        salt: &[u8; SALT_LEN],
        doc: &T,
        rotate: bool,
    ) -> Result<()> {
        // Bufor jawnego JSON-a o z góry znanej pojemności: `to_vec` rosłoby przez realokacje,
        // a porzucone porcje z hasłami nie byłyby zerowane.
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, doc)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(counter.0));
        serde_json::to_writer(&mut *plain, doc)?;
        let nonce = random::<NONCE_LEN>()?;
        let header = encode_header(self.kdf, salt, &nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Encrypt)?;
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Encrypt)?;
        let mut out = header;
        out.extend_from_slice(&ct);
        let tmp = write_tmp(&self.path, &out)?;
        let committed = (|| -> io::Result<()> {
            if rotate && self.backups > 0 && self.path.exists() {
                self.rotate_backups()?;
            }
            fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = committed {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_dir(&self.path);
        Ok(())
    }

    fn rotate_backups(&self) -> io::Result<()> {
        let last = backup_path(&self.path, self.backups);
        if last.exists() {
            fs::remove_file(&last)?;
        }
        for n in (1..self.backups).rev() {
            let from = backup_path(&self.path, n);
            if from.exists() {
                fs::rename(&from, backup_path(&self.path, n + 1))?;
            }
        }
        fs::copy(&self.path, backup_path(&self.path, 1))?;
        Ok(())
    }
}

/// Sprawdza bez hasła, że plik ma strukturę pliku MRMV w obsługiwanej wersji: magic, wersję,
/// kompletny nagłówek z parametrami KDF w dozwolonych granicach (górnych i dolnych) i szyfrogram co najmniej
/// długości znacznika uwierzytelnienia. Nie sprawdza, czy hasło pasuje.
pub fn validate_file(path: &Path) -> Result<()> {
    let data = fs::read(path)?;
    parse_header(&data).map(|_| ())
}

fn parse_header(data: &[u8]) -> Result<(KdfParams, [u8; SALT_LEN], [u8; NONCE_LEN])> {
    if data.len() < 4 || &data[..4] != MAGIC {
        return Err(Error::BadMagic);
    }
    if data.len() < HEADER_LEN + 16 {
        return Err(Error::Truncated);
    }
    let version = data[4];
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().expect("4 bajty"));
    let kdf = KdfParams {
        m_cost: u32_at(5),
        t_cost: u32_at(9),
        p_cost: u32_at(13),
    };
    // Nagłówek jest uwierzytelniany dopiero po wyliczeniu klucza, więc parametry z niezaufanego pliku
    // (np. z folderu synchronizacji) ograniczamy przed KDF, żeby nie alokować terabajtów pamięci.
    if kdf.m_cost > MAX_M_COST || kdf.t_cost > MAX_T_COST || kdf.p_cost > MAX_P_COST {
        return Err(Error::BadKdfParams);
    }
    // Dolne granice (t_cost = 0, p_cost = 0, za mała pamięć) odrzuca dopiero Argon2: sprawdzamy je
    // tu, żeby plik, którego nie da się otworzyć, nie przeszedł kontroli przed pobraniem.
    Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32)).map_err(|_| Error::BadKdfParams)?;
    let salt = data[17..17 + SALT_LEN].try_into().expect("sól");
    let nonce = data[17 + SALT_LEN..HEADER_LEN].try_into().expect("nonce");
    Ok((kdf, salt, nonce))
}

fn decrypt<T: DeserializeOwned>(key: &[u8; 32], data: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<T> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Decrypt)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: &data[HEADER_LEN..],
                    aad: &data[..HEADER_LEN],
                },
            )
            .map_err(|_| Error::Decrypt)?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

/// Odczyt dokumentu z kopii zapasowej (np. przy przywracaniu) tym samym hasłem.
pub fn open_backup<T: DeserializeOwned>(backup: &Path, password: &str) -> Result<T> {
    let data = fs::read(backup)?;
    let (kdf, salt, nonce) = parse_header(&data)?;
    let key = derive_key(password.as_bytes(), &salt, kdf)?;
    decrypt(&key, &data, &nonce)
}

/// Ścieżka kopii o numerze `n` (1 = najnowsza).
pub fn backup_file(path: &Path, n: usize) -> PathBuf {
    backup_path(path, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Doc {
        hosts: Vec<String>,
    }

    fn doc(n: usize) -> Doc {
        Doc {
            hosts: (0..n).map(|i| format!("h{i}")).collect(),
        }
    }

    /// Ścieżka pliku w osobnym katalogu tymczasowym, który znika razem z wartością.
    struct Tmp {
        dir: PathBuf,
        file: PathBuf,
    }

    impl std::ops::Deref for Tmp {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.file
        }
    }

    impl AsRef<Path> for Tmp {
        fn as_ref(&self) -> &Path {
            &self.file
        }
    }

    impl From<&Tmp> for PathBuf {
        fn from(t: &Tmp) -> PathBuf {
            t.file.clone()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn tmp(name: &str) -> Tmp {
        let dir = std::env::temp_dir().join(format!("mrm-vault-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Tmp {
            file: dir.join("hosts.mrm"),
            dir,
        }
    }

    /// Chwilowo zabiera katalog pliku, więc zapis kończy się błędem przed `rename` i przed rotacją.
    fn block_dir(p: &Tmp) -> PathBuf {
        let moved = p.dir.with_extension("zabrany");
        fs::rename(&p.dir, &moved).unwrap();
        moved
    }

    fn unblock_dir(p: &Tmp, moved: PathBuf) {
        fs::rename(moved, &p.dir).unwrap();
    }

    fn leftovers(p: &Tmp) -> usize {
        fs::read_dir(&p.dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count()
    }

    #[test]
    fn round_trip() {
        let p = tmp("rt");
        Vault::create(&p, "tajne", KdfParams::FAST_FOR_TESTS, &doc(3)).unwrap();
        let (_, d): (_, Doc) = Vault::open(&p, "tajne").unwrap();
        assert_eq!(d, doc(3));
    }

    #[test]
    fn wrong_password() {
        let p = tmp("pw");
        Vault::create(&p, "tajne", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "inne"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn corrupted_byte_in_body_and_header() {
        let p = tmp("corrupt");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(2)).unwrap();
        let orig = fs::read(&p).unwrap();
        for idx in [orig.len() - 1, 5 + 4 /* t_cost */ + 1, 20] {
            let mut bad = orig.clone();
            bad[idx] ^= 1;
            fs::write(&p, &bad).unwrap();
            assert!(Vault::open::<Doc>(&p, "x").is_err(), "bajt {idx}");
        }
    }

    #[test]
    fn bad_magic_truncated_and_future_version() {
        let p = tmp("hdr");
        fs::write(&p, b"nie plik").unwrap();
        assert!(matches!(Vault::open::<Doc>(&p, "x"), Err(Error::BadMagic)));
        fs::write(&p, b"MRMV\x01abc").unwrap();
        assert!(matches!(Vault::open::<Doc>(&p, "x"), Err(Error::Truncated)));
        let q = tmp("v2b");
        Vault::create(&q, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        let mut d = fs::read(&q).unwrap();
        d[4] = 99;
        fs::write(&q, d).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&q, "x"),
            Err(Error::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn save_changes_nonce_and_rotates_backups() {
        let p = tmp("bak");
        let mut v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        v.set_backup_count(2);
        let first = fs::read(&p).unwrap();
        for n in 1..=3 {
            v.save(&doc(n)).unwrap();
        }
        assert_ne!(
            first[17 + SALT_LEN..HEADER_LEN],
            fs::read(&p).unwrap()[17 + SALT_LEN..HEADER_LEN]
        );
        assert!(backup_file(&p, 1).exists() && backup_file(&p, 2).exists());
        assert!(!backup_file(&p, 3).exists());
        let b1: Doc = open_backup(&backup_file(&p, 1), "x").unwrap();
        let b2: Doc = open_backup(&backup_file(&p, 2), "x").unwrap();
        assert_eq!((b1, b2), (doc(2), doc(1)));
    }

    #[test]
    fn change_password() {
        let p = tmp("chpw");
        let mut v = Vault::create(&p, "stare", KdfParams::FAST_FOR_TESTS, &doc(2)).unwrap();
        v.change_password("nowe", &doc(2)).unwrap();
        assert!(Vault::open::<Doc>(&p, "stare").is_err());
        assert_eq!(Vault::open::<Doc>(&p, "nowe").unwrap().1, doc(2));
    }

    #[test]
    fn failed_password_change_keeps_old_password() {
        let p = tmp("chpw-fail");
        let mut v = Vault::create(&p, "stare", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        let blocker = block_dir(&p);
        assert!(v.change_password("nowe", &doc(1)).is_err());
        unblock_dir(&p, blocker);
        // Kolejny zwykły zapis nadal używa starego hasła.
        v.save(&doc(2)).unwrap();
        assert_eq!(Vault::open::<Doc>(&p, "stare").unwrap().1, doc(2));
        assert!(Vault::open::<Doc>(&p, "nowe").is_err());
    }

    #[test]
    fn failed_save_does_not_rotate_backups() {
        let p = tmp("bak-fail");
        let mut v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        v.set_backup_count(3);
        v.save(&doc(1)).unwrap();
        let blocker = block_dir(&p);
        for _ in 0..3 {
            assert!(v.save(&doc(9)).is_err());
        }
        unblock_dir(&p, blocker);
        assert!(
            !backup_file(&p, 2).exists(),
            "nieudane zapisy nie rotują kopii"
        );
        let b1: Doc = open_backup(&backup_file(&p, 1), "x").unwrap();
        assert_eq!(b1, doc(0));
        assert_eq!(Vault::open::<Doc>(&p, "x").unwrap().1, doc(1));
    }

    #[test]
    fn validate_file_checks_structure_without_password() {
        let p = tmp("validate");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        validate_file(&p).unwrap();
        let data = fs::read(&p).unwrap();
        fs::write(&p, &data[..30]).unwrap();
        assert!(matches!(validate_file(&p), Err(Error::Truncated)));
        fs::write(&p, &data[..HEADER_LEN + 15]).unwrap();
        assert!(matches!(validate_file(&p), Err(Error::Truncated)));
        fs::write(&p, b"nie mrmv, ale dluzszy niz naglowek i znacznik").unwrap();
        assert!(matches!(validate_file(&p), Err(Error::BadMagic)));
        let mut bad = data.clone();
        bad[4] = 9;
        fs::write(&p, &bad).unwrap();
        assert!(matches!(
            validate_file(&p),
            Err(Error::UnsupportedVersion(9))
        ));
        assert!(validate_file(&p.with_extension("brak")).is_err());
    }

    #[test]
    fn verify_file_same_key_corrupted_and_other_key() {
        let p = tmp("verify");
        let v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(20)).unwrap();
        assert_eq!(v.verify_file(&p).unwrap(), Verified::SameKey);
        // Zapis zmienia nonce, ale nie sól: plik nadal tym samym kluczem.
        v.save(&doc(21)).unwrap();
        assert_eq!(v.verify_file(&p).unwrap(), Verified::SameKey);
        let data = fs::read(&p).unwrap();
        // Obcięty w środku szyfrogramu.
        let cut = p.with_extension("obciety");
        fs::write(&cut, &data[..HEADER_LEN + (data.len() - HEADER_LEN) / 2]).unwrap();
        assert!(matches!(v.verify_file(&cut), Err(Error::Decrypt)));
        // Zmieniony bajt szyfrogramu.
        let mut bad = data.clone();
        *bad.last_mut().unwrap() ^= 1;
        fs::write(&cut, &bad).unwrap();
        assert!(matches!(v.verify_file(&cut), Err(Error::Decrypt)));
        // Inne hasło (inna sól): nie da się sprawdzić, ale bez błędu.
        let other = p.with_extension("inne");
        Vault::create(&other, "y", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        assert_eq!(v.verify_file(&other).unwrap(), Verified::OtherKey);
        // Uszkodzona struktura to nadal błąd.
        fs::write(&cut, &data[..30]).unwrap();
        assert!(matches!(v.verify_file(&cut), Err(Error::Truncated)));
    }

    #[test]
    fn absurd_kdf_params_are_rejected_before_kdf() {
        let p = tmp("kdf-limit");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        let mut data = fs::read(&p).unwrap();
        data[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&p, &data).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "x"),
            Err(Error::BadKdfParams)
        ));
    }

    #[test]
    fn invalid_kdf_params_are_rejected_before_download() {
        let p = tmp("kdf-low");
        let v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        let orig = fs::read(&p).unwrap();
        // t_cost = 0, p_cost = 0 i m_cost < 8 * p_cost.
        for (range, val) in [(9..13, 0u32), (13..17, 0), (5..9, 7)] {
            let mut bad = orig.clone();
            bad[range].copy_from_slice(&val.to_le_bytes());
            fs::write(&p, &bad).unwrap();
            assert!(matches!(validate_file(&p), Err(Error::BadKdfParams)));
            assert!(matches!(v.verify_file(&p), Err(Error::BadKdfParams)));
        }
    }

    #[test]
    fn verify_file_same_salt_other_kdf_is_corruption() {
        let p = tmp("verify-kdf");
        let v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(2)).unwrap();
        let mut data = fs::read(&p).unwrap();
        data[5..9].copy_from_slice(&16u32.to_le_bytes());
        fs::write(&p, &data).unwrap();
        validate_file(&p).unwrap();
        assert!(matches!(v.verify_file(&p), Err(Error::Decrypt)));
    }

    #[test]
    fn write_does_not_follow_symlinks_and_leaves_no_temp_files() {
        let p = tmp("tmp-names");
        let v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        #[cfg(unix)]
        {
            // Dawna stała nazwa pliku tymczasowego nie może przekierować zapisu.
            let victim = p.dir.join("ofiara.txt");
            fs::write(&victim, b"nietkniete").unwrap();
            std::os::unix::fs::symlink(&victim, p.dir.join("hosts.mrm.tmp")).unwrap();
            v.save(&doc(2)).unwrap();
            assert_eq!(fs::read(&victim).unwrap(), b"nietkniete");
            assert_eq!(Vault::open::<Doc>(&p, "x").unwrap().1, doc(2));
            fs::remove_file(p.dir.join("hosts.mrm.tmp")).unwrap();
        }
        assert_eq!(leftovers(&p), 0);
        let blocker = block_dir(&p);
        assert!(v.save(&doc(3)).is_err());
        unblock_dir(&p, blocker);
        assert_eq!(leftovers(&p), 0);
    }

    #[cfg(unix)]
    #[test]
    fn file_and_backups_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("mode");
        let v = Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        v.save(&doc(1)).unwrap();
        for f in [p.to_path_buf(), backup_file(&p, 1)] {
            let mode = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", f.display());
        }
    }

    #[test]
    fn create_refuses_overwrite() {
        let p = tmp("ow");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        assert!(Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).is_err());
    }
}
