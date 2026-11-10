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

/// Zapis atomowy: plik tymczasowy w tym samym katalogu, `fsync`, `rename`.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
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

    pub fn set_backup_count(&mut self, n: usize) {
        self.backups = n;
    }

    /// Zapisuje dokument; przed nadpisaniem rotuje kopie `.bak1` (najnowsza) ... `.bakN`.
    pub fn save<T: Serialize>(&self, doc: &T) -> Result<()> {
        self.write(doc, true)
    }

    /// Zmienia hasło główne: nowa sól, nowy klucz, zapis całego dokumentu.
    pub fn change_password<T: Serialize>(&mut self, new_password: &str, doc: &T) -> Result<()> {
        let salt = random::<SALT_LEN>()?;
        self.key = derive_key(new_password.as_bytes(), &salt, self.kdf)?;
        self.salt = salt;
        self.write(doc, true)
    }

    fn write<T: Serialize>(&self, doc: &T, rotate: bool) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(doc)?);
        let nonce = random::<NONCE_LEN>()?;
        let header = encode_header(self.kdf, &self.salt, &nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| Error::BadKdfParams)?;
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Decrypt)?;
        let mut out = header;
        out.extend_from_slice(&ct);
        if rotate && self.backups > 0 && self.path.exists() {
            self.rotate_backups()?;
        }
        write_atomic(&self.path, &out)?;
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
    let salt = data[17..17 + SALT_LEN].try_into().expect("sól");
    let nonce = data[17 + SALT_LEN..HEADER_LEN].try_into().expect("nonce");
    Ok((kdf, salt, nonce))
}

fn decrypt<T: DeserializeOwned>(key: &[u8; 32], data: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<T> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::BadKdfParams)?;
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

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-vault-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.join("hosts.mrm")
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
        Vault::create(tmp("v2"), "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
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
    fn create_refuses_overwrite() {
        let p = tmp("ow");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        assert!(Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).is_err());
    }
}
