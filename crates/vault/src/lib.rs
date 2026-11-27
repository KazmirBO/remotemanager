//! Zaszyfrowany plik z danymi aplikacji.
//!
//! Format (wszystkie liczby little-endian):
//! `magic "MRMV" | wersja u8 | m_cost u32 | t_cost u32 | p_cost u32 | sol[16] | nonce[24] | szyfrogram`.
//! Nagłówek (bajty przed szyfrogramem) jest uwierzytelniany jako AAD, więc jego modyfikacja
//! jest wykrywana. Klucz wynika z hasła głównego przez Argon2id, szyfr to XChaCha20-Poly1305.
//!
//! Wersja 2 ma ten sam początek, a po nonce jeszcze `flagi u8 | dlugosc_rozszerzenia u16 |
//! rozszerzenie`. Zapisuje ją plik "chroniony" (`Vault::set_protected`), czyli taki, którego
//! dokument wymaga dodatkowego składnika przy otwieraniu: program sprzed wersji 2 takiego pliku
//! nie otworzy, więc nie pominie tego wymogu ani nie zapisze pliku bez niego. Flagi i rozszerzenie
//! opisują składniki szyfrowania; plik z nieznaną flagą jest odrzucany.
//!
//! Klucze sprzętowe (flaga 1). Rozszerzenie ma wtedy postać `sol_wyzwania[32] | liczba u8 |
//! wpisy`, a wpis to `dlugosc_id u16 | id_poswiadczenia | nonce[24] | opakowany_klucz[48] |
//! dlugosc_nazwy u8 | nazwa`. Plik ma losowy klucz danych. Każdy zarejestrowany klucz sprzętowy
//! zwraca dla soli wyzwania własny sekret (rozszerzenie hmac-secret w FIDO2), którym klucz danych
//! jest opakowany w jego wpisie, więc każdy klucz otwiera plik samodzielnie. Klucz szyfrujący treść
//! powstaje z klucza hasła i klucza danych (HKDF-SHA256), czyli do odszyfrowania potrzebne są
//! i hasło, i któryś z kluczy sprzętowych. Zmiana hasła nie wymaga klucza sprzętowego, dodanie
//! kolejnego klucza nie wymaga pozostałych, a usunięcie klucza zmienia klucz danych i sól, więc
//! wymaga sekretów kluczy, które zostają.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MRMV";
/// Znacznik pakietu eksportu hostów. Układ nagłówka i szyfr są takie same jak w pliku z hostami,
/// ale inny znacznik sprawia, że pakietu nie da się otworzyć, przywrócić ani zsynchronizować jako
/// pliku z hostami, a pliku z hostami nie da się zaimportować jako pakietu.
const EXPORT_MAGIC: &[u8; 4] = b"MRMX";
/// Podstawowa wersja formatu pliku (plik bez dodatkowego składnika).
pub const FORMAT_VERSION: u8 = 1;
/// Wersja formatu pliku chronionego dodatkowym składnikiem.
pub const FORMAT_PROTECTED: u8 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN + NONCE_LEN;
/// Stała część nagłówka wersji 2 po nonce: flagi i długość rozszerzenia.
const V2_TAIL: usize = 1 + 2;
/// Flaga nagłówka wersji 2: rozszerzenie zawiera listę kluczy sprzętowych.
const FLAG_KEYS: u8 = 1;
/// Długość sekretu z klucza sprzętowego i soli wyzwania.
pub const KEY_SECRET_LEN: usize = 32;
/// Najwięcej zarejestrowanych kluczy sprzętowych.
pub const MAX_KEYS: usize = 4;
/// Najdłuższy identyfikator poświadczenia klucza sprzętowego.
const MAX_CREDENTIAL: usize = 1024;
/// Najdłuższa nazwa klucza sprzętowego (w bajtach).
pub const MAX_KEY_NAME: usize = 64;
/// Opakowany klucz danych: 32 bajty i znacznik uwierzytelnienia.
const WRAP_LEN: usize = 32 + 16;
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
    #[error("to nie jest plik eksportu hostów")]
    NotExport,
    #[error("plik jest uszkodzony lub obcięty")]
    Truncated,
    #[error("nieobsługiwana wersja formatu: {0}")]
    UnsupportedVersion(u8),
    #[error("plik używa zabezpieczeń, których ta wersja programu nie obsługuje")]
    UnsupportedFeatures,
    #[error("plik jest zabezpieczony kluczem sprzętowym")]
    NeedsKey,
    #[error("ten klucz sprzętowy nie pasuje do pliku")]
    KeyRejected,
    #[error("lista kluczy sprzętowych w pliku jest uszkodzona")]
    BadKeys,
    #[error("nie można zmienić kluczy sprzętowych: {0}")]
    KeyRequest(&'static str),
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

/// Zarejestrowany klucz sprzętowy: poświadczenie, nazwa i klucz danych opakowany jego sekretem.
#[derive(Clone, PartialEq, Eq)]
struct KeySlot {
    credential: Vec<u8>,
    name: String,
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAP_LEN],
}

/// Lista kluczy sprzętowych z nagłówka: wspólna sól wyzwania i wpisy.
#[derive(Clone, PartialEq, Eq)]
struct KeySection {
    salt: [u8; KEY_SECRET_LEN],
    slots: Vec<KeySlot>,
}

impl KeySection {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.salt);
        out.push(self.slots.len() as u8);
        for s in &self.slots {
            out.extend_from_slice(&(s.credential.len() as u16).to_le_bytes());
            out.extend_from_slice(&s.credential);
            out.extend_from_slice(&s.nonce);
            out.extend_from_slice(&s.wrapped);
            out.push(s.name.len() as u8);
            out.extend_from_slice(s.name.as_bytes());
        }
        out
    }

    /// Czyta listę z rozszerzenia nagłówka. Dane pochodzą z niezaufanego pliku, więc każda
    /// długość jest sprawdzana, a po ostatnim wpisie nie może zostać ani bajt.
    fn parse(ext: &[u8]) -> Result<Self> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if rest.len() < n {
                return Err(Error::BadKeys);
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Ok(head)
        }
        let mut rest = ext;
        let salt = take(&mut rest, KEY_SECRET_LEN)?.try_into().expect("sól");
        let count = usize::from(take(&mut rest, 1)?[0]);
        if count == 0 || count > MAX_KEYS {
            return Err(Error::BadKeys);
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let id_len = usize::from(u16::from_le_bytes(
                take(&mut rest, 2)?.try_into().expect("2 bajty"),
            ));
            if id_len == 0 || id_len > MAX_CREDENTIAL {
                return Err(Error::BadKeys);
            }
            let credential = take(&mut rest, id_len)?.to_vec();
            let nonce = take(&mut rest, NONCE_LEN)?.try_into().expect("nonce");
            let wrapped = take(&mut rest, WRAP_LEN)?.try_into().expect("klucz");
            let name_len = usize::from(take(&mut rest, 1)?[0]);
            if name_len > MAX_KEY_NAME {
                return Err(Error::BadKeys);
            }
            let name = std::str::from_utf8(take(&mut rest, name_len)?)
                .map_err(|_| Error::BadKeys)?
                .to_owned();
            if slots.iter().any(|s: &KeySlot| s.credential == credential) {
                return Err(Error::BadKeys);
            }
            slots.push(KeySlot {
                credential,
                name,
                nonce,
                wrapped,
            });
        }
        if !rest.is_empty() {
            return Err(Error::BadKeys);
        }
        Ok(Self { salt, slots })
    }

    fn infos(&self) -> Vec<KeyInfo> {
        self.slots
            .iter()
            .map(|s| KeyInfo {
                credential: s.credential.clone(),
                name: s.name.clone(),
            })
            .collect()
    }
}

/// Zarejestrowany klucz sprzętowy widziany z zewnątrz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Identyfikator poświadczenia, po którym klucz rozpoznaje, że pytanie jest do niego.
    pub credential: Vec<u8>,
    pub name: String,
}

/// Klucz szyfrujący treść pliku z kluczem sprzętowym: zależy od klucza hasła i klucza danych.
fn content_key(
    pass_key: &[u8; 32],
    data_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(pass_key);
    ikm[32..].copy_from_slice(data_key);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm.as_ref())
        .expand(b"mrm-content-key-v1", key.as_mut())
        .expect("32 bajty to poprawna długość wyjścia HKDF");
    key
}

/// Klucz opakowujący klucz danych, wyprowadzony z sekretu klucza sprzętowego.
fn wrapping_key(secret: &[u8; KEY_SECRET_LEN], salt: &[u8; KEY_SECRET_LEN]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(b"mrm-key-wrap-v1", key.as_mut())
        .expect("32 bajty to poprawna długość wyjścia HKDF");
    key
}

/// Opakowuje klucz danych sekretem klucza sprzętowego. Identyfikator poświadczenia jest AAD,
/// więc wpisu nie da się przypiąć do innego poświadczenia.
fn wrap_data_key(
    secret: &[u8; KEY_SECRET_LEN],
    salt: &[u8; KEY_SECRET_LEN],
    credential: &[u8],
    data_key: &[u8; 32],
) -> Result<([u8; NONCE_LEN], [u8; WRAP_LEN])> {
    let nonce = random::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key(secret, salt).as_ref())
        .map_err(|_| Error::Encrypt)?;
    let wrapped = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: data_key,
                aad: credential,
            },
        )
        .map_err(|_| Error::Encrypt)?;
    Ok((nonce, wrapped.try_into().map_err(|_| Error::Encrypt)?))
}

/// Odpakowuje klucz danych; zły sekret (inny klucz sprzętowy albo inny PIN) daje `KeyRejected`.
fn unwrap_data_key(
    secret: &[u8; KEY_SECRET_LEN],
    salt: &[u8; KEY_SECRET_LEN],
    slot: &KeySlot,
) -> Result<Zeroizing<[u8; 32]>> {
    let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key(secret, salt).as_ref())
        .map_err(|_| Error::KeyRejected)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(slot.nonce),
                Payload {
                    msg: &slot.wrapped,
                    aad: &slot.credential,
                },
            )
            .map_err(|_| Error::KeyRejected)?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Ok(key)
}

/// Otwarty plik: trzyma klucz, więc zapis nie wymaga ponownego KDF.
pub struct Vault {
    path: PathBuf,
    /// Klucz szyfrujący treść: klucz hasła albo, z kluczem sprzętowym, pochodna hasła i klucza danych.
    key: Zeroizing<[u8; 32]>,
    /// Klucz wyprowadzony z hasła (Argon2id). Bez klucza sprzętowego równy `key`.
    pass_key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    backups: usize,
    /// Zapis w wersji 2 formatu (plik wymaga dodatkowego składnika przy otwieraniu).
    protected: bool,
    /// Zarejestrowane klucze sprzętowe.
    keys: Option<KeySection>,
    /// Klucz danych pliku z kluczem sprzętowym (odpakowany przy otwieraniu).
    data_key: Option<Zeroizing<[u8; 32]>>,
}

/// Wynik pierwszego kroku otwierania pliku.
#[allow(clippy::large_enum_variant)]
pub enum Opened<T> {
    /// Hasło wystarczyło.
    Ready(Vault, T),
    /// Plik wymaga jeszcze klucza sprzętowego.
    NeedsKey(KeyChallenge),
}

/// Plik z kluczem sprzętowym po podaniu hasła: wie, o co zapytać klucz, i dokańcza otwieranie
/// z jego odpowiedzią. Celowo bez `Debug`: trzyma klucz wyprowadzony z hasła.
pub struct KeyChallenge {
    path: PathBuf,
    data: Vec<u8>,
    header: Header,
    pass_key: Zeroizing<[u8; 32]>,
}

impl KeyChallenge {
    fn section(&self) -> &KeySection {
        self.header
            .keys
            .as_ref()
            .expect("wyzwanie powstaje tylko dla pliku z kluczami")
    }

    /// Zarejestrowane klucze: każdy z nich otwiera plik.
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.section().infos()
    }

    /// Sól, dla której klucz sprzętowy ma zwrócić sekret.
    pub fn salt(&self) -> [u8; KEY_SECRET_LEN] {
        self.section().salt
    }

    /// Dokańcza otwieranie sekretem zwróconym przez klucz o podanym poświadczeniu. `KeyRejected`
    /// oznacza, że klucz albo jego sekret nie pasuje do pliku, a `Decrypt`, że klucz pasuje, ale
    /// hasło było złe (bez klucza sprzętowego hasła nie da się sprawdzić) albo plik jest uszkodzony.
    pub fn finish<T: DeserializeOwned>(
        &self,
        credential: &[u8],
        secret: &[u8; KEY_SECRET_LEN],
    ) -> Result<(Vault, T)> {
        let section = self.section();
        let slot = section
            .slots
            .iter()
            .find(|s| s.credential == credential)
            .ok_or(Error::KeyRejected)?;
        let data_key = unwrap_data_key(secret, &section.salt, slot)?;
        let key = content_key(&self.pass_key, &data_key, &self.header.salt);
        let doc = decrypt(&key, &self.data, &self.header)?;
        Ok((
            Vault {
                path: self.path.clone(),
                key,
                pass_key: self.pass_key.clone(),
                salt: self.header.salt,
                kdf: self.header.kdf,
                backups: DEFAULT_BACKUPS,
                protected: true,
                keys: Some(section.clone()),
                data_key: Some(data_key),
            },
            doc,
        ))
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| Error::Random(e.to_string()))?;
    Ok(buf)
}

/// Losowe bajty z generatora systemu (np. sekret TOTP i kody zapasowe w aplikacji).
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    random::<N>()
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

fn encode_header(
    magic: &[u8; 4],
    version: u8,
    kdf: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    keys: Option<&KeySection>,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN + V2_TAIL);
    h.extend_from_slice(magic);
    h.push(version);
    h.extend_from_slice(&kdf.m_cost.to_le_bytes());
    h.extend_from_slice(&kdf.t_cost.to_le_bytes());
    h.extend_from_slice(&kdf.p_cost.to_le_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    if version == FORMAT_PROTECTED {
        let ext = keys.map(KeySection::encode).unwrap_or_default();
        h.push(if keys.is_some() { FLAG_KEYS } else { 0 });
        h.extend_from_slice(&(ext.len() as u16).to_le_bytes());
        h.extend_from_slice(&ext);
    }
    h
}

/// Szyfruje dokument do postaci pliku: nagłówek ze znacznikiem `magic` i szyfrogram.
fn encrypt<T: Serialize>(
    magic: &[u8; 4],
    version: u8,
    key: &[u8; 32],
    kdf: KdfParams,
    salt: &[u8; SALT_LEN],
    keys: Option<&KeySection>,
    doc: &T,
) -> Result<Vec<u8>> {
    // Bufor jawnego JSON-a o z góry znanej pojemności: `to_vec` rosłoby przez realokacje,
    // a porzucone porcje z hasłami nie byłyby zerowane.
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, doc)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *plain, doc)?;
    let nonce = random::<NONCE_LEN>()?;
    let header = encode_header(magic, version, kdf, salt, &nonce, keys);
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
    Ok(out)
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
            pass_key: key.clone(),
            key,
            salt,
            kdf,
            backups: DEFAULT_BACKUPS,
            protected: false,
            keys: None,
            data_key: None,
        };
        v.write(doc, false)?;
        Ok(v)
    }

    /// Otwiera plik i odszyfrowuje dokument samym hasłem. Plik z kluczem sprzętowym daje
    /// `NeedsKey`; do niego służy `open_step`.
    pub fn open<T: DeserializeOwned>(
        path: impl Into<PathBuf>,
        password: &str,
    ) -> Result<(Self, T)> {
        match Self::open_step(path, password)? {
            Opened::Ready(vault, doc) => Ok((vault, doc)),
            Opened::NeedsKey(_) => Err(Error::NeedsKey),
        }
    }

    /// Pierwszy krok otwierania: wylicza klucz z hasła. Zwykły plik jest od razu odszyfrowany,
    /// a plik z kluczem sprzętowym zwraca wyzwanie, które dokańcza otwieranie odpowiedzią klucza.
    pub fn open_step<T: DeserializeOwned>(
        path: impl Into<PathBuf>,
        password: &str,
    ) -> Result<Opened<T>> {
        let path = path.into();
        let data = fs::read(&path)?;
        let h = parse_header(&data)?;
        let key = derive_key(password.as_bytes(), &h.salt, h.kdf)?;
        if h.keys.is_some() {
            return Ok(Opened::NeedsKey(KeyChallenge {
                path,
                data,
                header: h,
                pass_key: key,
            }));
        }
        let doc = decrypt(&key, &data, &h)?;
        Ok(Opened::Ready(
            Self {
                path,
                pass_key: key.clone(),
                key,
                salt: h.salt,
                kdf: h.kdf,
                backups: DEFAULT_BACKUPS,
                protected: h.version == FORMAT_PROTECTED,
                keys: None,
                data_key: None,
            },
            doc,
        ))
    }

    /// Zarejestrowane klucze sprzętowe (pusta lista, gdy plik ich nie używa).
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.keys
            .as_ref()
            .map(KeySection::infos)
            .unwrap_or_default()
    }

    /// Sól wyzwania pliku z kluczami sprzętowymi. Nowy klucz musi zwrócić sekret dla tej soli.
    pub fn key_salt(&self) -> Option<[u8; KEY_SECRET_LEN]> {
        self.keys.as_ref().map(|k| k.salt)
    }

    /// Nowa losowa sól wyzwania: dla pierwszego klucza i przy usuwaniu klucza.
    pub fn new_key_salt() -> Result<[u8; KEY_SECRET_LEN]> {
        random::<KEY_SECRET_LEN>()
    }

    /// Rejestruje klucz sprzętowy i zapisuje plik. `secret` to odpowiedź tego klucza na `salt`:
    /// dla pierwszego klucza sól jest nowa (`new_key_salt`), dla kolejnych musi to być `key_salt`.
    /// Pierwszy klucz wprowadza losowy klucz danych; kolejne dostają ten sam klucz danych we
    /// własnym wpisie, więc ich dodanie nie wymaga pozostałych kluczy. Stan w pamięci zmienia się
    /// dopiero po udanym zapisie.
    pub fn add_key<T: Serialize>(
        &mut self,
        doc: &T,
        name: &str,
        credential: &[u8],
        salt: &[u8; KEY_SECRET_LEN],
        secret: &[u8; KEY_SECRET_LEN],
    ) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_KEY_NAME || name.chars().any(char::is_control) {
            return Err(Error::KeyRequest(
                "nazwa klucza musi mieć od 1 do 64 bajtów",
            ));
        }
        if credential.is_empty() || credential.len() > MAX_CREDENTIAL {
            return Err(Error::KeyRequest(
                "nieprawidłowy identyfikator poświadczenia",
            ));
        }
        let (mut section, data_key) = match (&self.keys, &self.data_key) {
            (Some(section), Some(data_key)) => {
                if section.salt != *salt {
                    return Err(Error::KeyRequest("sekret policzono dla innej soli"));
                }
                if section.slots.len() >= MAX_KEYS {
                    return Err(Error::KeyRequest("osiągnięto limit kluczy"));
                }
                if section.slots.iter().any(|s| s.credential == credential) {
                    return Err(Error::KeyRequest("ten klucz jest już zarejestrowany"));
                }
                (section.clone(), data_key.clone())
            }
            _ => (
                KeySection {
                    salt: *salt,
                    slots: Vec::new(),
                },
                Zeroizing::new(random::<32>()?),
            ),
        };
        let (nonce, wrapped) = wrap_data_key(secret, &section.salt, credential, &data_key)?;
        section.slots.push(KeySlot {
            credential: credential.to_vec(),
            name: name.to_owned(),
            nonce,
            wrapped,
        });
        let key = content_key(&self.pass_key, &data_key, &self.salt);
        self.write_state(&key, &self.salt, Some(&section), doc, true)?;
        self.key = key;
        self.keys = Some(section);
        self.data_key = Some(data_key);
        Ok(())
    }

    /// Usuwa klucz sprzętowy i zapisuje plik. Gdy zostają inne klucze, plik dostaje nowy klucz
    /// danych i nową sól (usunięty klucz nie odpakuje już niczego, czym szyfrowane są nowe wersje),
    /// więc `remaining` musi zawierać dla każdego pozostającego klucza jego sekret dla `new_salt`.
    /// Usunięcie ostatniego klucza wyłącza ten składnik: klucz treści wraca do klucza z hasła.
    pub fn remove_key<T: Serialize>(
        &mut self,
        doc: &T,
        credential: &[u8],
        new_salt: &[u8; KEY_SECRET_LEN],
        remaining: &[(Vec<u8>, [u8; KEY_SECRET_LEN])],
    ) -> Result<()> {
        let section = self
            .keys
            .as_ref()
            .ok_or(Error::KeyRequest("plik nie ma kluczy sprzętowych"))?;
        let kept: Vec<&KeySlot> = section
            .slots
            .iter()
            .filter(|s| s.credential != credential)
            .collect();
        if kept.len() == section.slots.len() {
            return Err(Error::KeyRequest("nie ma takiego klucza"));
        }
        if kept.is_empty() {
            let key = self.pass_key.clone();
            self.write_state(&key, &self.salt, None, doc, true)?;
            self.key = key;
            self.keys = None;
            self.data_key = None;
            return Ok(());
        }
        if *new_salt == section.salt {
            return Err(Error::KeyRequest("sól musi być nowa"));
        }
        let data_key = Zeroizing::new(random::<32>()?);
        let mut slots = Vec::with_capacity(kept.len());
        for slot in kept {
            let (_, secret) = remaining
                .iter()
                .find(|(c, _)| *c == slot.credential)
                .ok_or(Error::KeyRequest("brak sekretu klucza, który zostaje"))?;
            let (nonce, wrapped) = wrap_data_key(secret, new_salt, &slot.credential, &data_key)?;
            slots.push(KeySlot {
                credential: slot.credential.clone(),
                name: slot.name.clone(),
                nonce,
                wrapped,
            });
        }
        let section = KeySection {
            salt: *new_salt,
            slots,
        };
        let key = content_key(&self.pass_key, &data_key, &self.salt);
        self.write_state(&key, &self.salt, Some(&section), doc, true)?;
        self.key = key;
        self.keys = Some(section);
        self.data_key = Some(data_key);
        Ok(())
    }

    /// Odszyfrowuje inny plik podanym hasłem, np. kopię zapasową. Plik bez kluczy sprzętowych
    /// wymaga tylko hasła. Plik z tą samą listą kluczy co otwarty korzysta z klucza danych
    /// z pamięci, więc nie trzeba dotykać klucza. Plik z inną listą kluczy daje `NeedsKey`.
    pub fn open_sibling<T: DeserializeOwned>(&self, path: &Path, password: &str) -> Result<T> {
        let data = fs::read(path)?;
        let h = parse_header(&data)?;
        let pass_key = derive_key(password.as_bytes(), &h.salt, h.kdf)?;
        let key = match (&h.keys, &self.keys, &self.data_key) {
            (None, _, _) => pass_key,
            (Some(theirs), Some(ours), Some(data_key)) if theirs == ours => {
                content_key(&pass_key, data_key, &h.salt)
            }
            _ => return Err(Error::NeedsKey),
        };
        decrypt(&key, &data, &h)
    }

    /// Czy podane hasło jest bieżącym hasłem głównym. Porównuje klucz wyprowadzony z hasła
    /// z kluczem z pamięci, więc działa także dla pliku z kluczem sprzętowym, którego samym
    /// hasłem nie da się otworzyć.
    pub fn check_password(&self, password: &str) -> Result<bool> {
        let key = derive_key(password.as_bytes(), &self.salt, self.kdf)?;
        let diff = key
            .iter()
            .zip(self.pass_key.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        Ok(diff == 0)
    }

    /// Czy sekret klucza o podanym poświadczeniu odpakowuje klucz danych tego pliku, czyli czy
    /// ten klucz sprzętowy otworzyłby plik.
    pub fn key_matches(&self, credential: &[u8], secret: &[u8; KEY_SECRET_LEN]) -> bool {
        let (Some(section), Some(data_key)) = (&self.keys, &self.data_key) else {
            return false;
        };
        section
            .slots
            .iter()
            .find(|s| s.credential == credential)
            .and_then(|slot| unwrap_data_key(secret, &section.salt, slot).ok())
            .is_some_and(|unwrapped| *unwrapped == **data_key)
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
        let h = parse_header(&data)?;
        // Inna lista kluczy sprzętowych to inny klucz danych, czyli też inny klucz treści.
        if h.salt != self.salt || h.keys != self.keys {
            return Ok(Verified::OtherKey);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Decrypt)?;
        let _plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(h.nonce),
                    Payload {
                        msg: &data[h.len..],
                        aad: &data[..h.len],
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        Ok(Verified::SameKey)
    }

    /// Odszyfrowuje inny plik kluczem z pamięci, bez pytania o hasło (np. plik z folderu
    /// synchronizacji, żeby pokazać różnice). Ta sama sól to ten sam klucz: wynik to
    /// `Some(dokument)`, a uszkodzenie albo inne parametry KDF dają błąd, jak w `verify_file`.
    /// Inna sól (hasło główne zmienione gdzie indziej) daje `None`, bo nie ma czym odszyfrować.
    pub fn read_file<T: DeserializeOwned>(&self, path: &Path) -> Result<Option<T>> {
        let data = fs::read(path)?;
        let h = parse_header(&data)?;
        if h.salt != self.salt || h.keys != self.keys {
            return Ok(None);
        }
        decrypt(&self.key, &data, &h).map(Some)
    }

    /// Czy plik jest zapisywany w wersji 2 formatu.
    pub fn protected(&self) -> bool {
        self.protected
    }

    /// Wybiera wersję formatu dla kolejnych zapisów: `true`, gdy dokument wymaga dodatkowego
    /// składnika przy otwieraniu (wersja 2, której starszy program nie otworzy), `false` dla
    /// zwykłego pliku (wersja 1, czytelna także dla starszego programu).
    pub fn set_protected(&mut self, protected: bool) {
        self.protected = protected;
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
    /// Z kluczem sprzętowym klucz danych zostaje ten sam, więc zmiana hasła nie wymaga klucza.
    pub fn change_password<T: Serialize>(&mut self, new_password: &str, doc: &T) -> Result<()> {
        let salt = random::<SALT_LEN>()?;
        let pass_key = derive_key(new_password.as_bytes(), &salt, self.kdf)?;
        let key = match &self.data_key {
            Some(data_key) => content_key(&pass_key, data_key, &salt),
            None => pass_key.clone(),
        };
        self.write_state(&key, &salt, self.keys.as_ref(), doc, true)?;
        self.key = key;
        self.pass_key = pass_key;
        self.salt = salt;
        Ok(())
    }

    fn write<T: Serialize>(&self, doc: &T, rotate: bool) -> Result<()> {
        self.write_state(&self.key, &self.salt, self.keys.as_ref(), doc, rotate)
    }

    /// Zapis: szyfrowanie, plik tymczasowy z `fsync`, dopiero potem rotacja kopii i `rename`.
    /// Błąd przed rotacją (szyfrowanie, plik tymczasowy) nie rusza ani pliku, ani kopii `.bakN`.
    /// Błąd samego `rename` następuje już po rotacji: plik zostaje bez zmian, ale kopie są
    /// przesunięte, a `.bak1` jest kopią bieżącego pliku, więc powtarzane niepowodzenia
    /// wypełniają kopie tą samą wersją.
    fn write_state<T: Serialize>(
        &self,
        key: &[u8; 32],
        salt: &[u8; SALT_LEN],
        keys: Option<&KeySection>,
        doc: &T,
        rotate: bool,
    ) -> Result<()> {
        // Lista kluczy sprzętowych istnieje tylko w wersji 2 formatu.
        let version = if self.protected || keys.is_some() {
            FORMAT_PROTECTED
        } else {
            FORMAT_VERSION
        };
        let out = encrypt(MAGIC, version, key, self.kdf, salt, keys, doc)?;
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

/// Odczytany nagłówek pliku.
#[derive(Clone)]
struct Header {
    version: u8,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    /// Długość całego nagłówka: tyle bajtów jest AAD, od tego miejsca zaczyna się szyfrogram.
    len: usize,
    /// Lista kluczy sprzętowych (tylko wersja 2 z flagą kluczy).
    keys: Option<KeySection>,
}

fn parse_header(data: &[u8]) -> Result<Header> {
    parse_header_as(MAGIC, data)
}

fn parse_header_as(magic: &[u8; 4], data: &[u8]) -> Result<Header> {
    if data.len() < 4 || &data[..4] != magic {
        return Err(Error::BadMagic);
    }
    if data.len() < HEADER_LEN + 16 {
        return Err(Error::Truncated);
    }
    let version = data[4];
    let (len, keys) = match version {
        FORMAT_VERSION => (HEADER_LEN, None),
        FORMAT_PROTECTED => {
            if data.len() < HEADER_LEN + V2_TAIL + 16 {
                return Err(Error::Truncated);
            }
            let flags = data[HEADER_LEN];
            let ext = usize::from(u16::from_le_bytes([
                data[HEADER_LEN + 1],
                data[HEADER_LEN + 2],
            ]));
            // Nieznana flaga opisuje składnik szyfrowania, którego ta wersja nie zna: otwarcie
            // takiego pliku byłoby błędne, a zapis zgubiłby te dane.
            if flags & !FLAG_KEYS != 0 {
                return Err(Error::UnsupportedFeatures);
            }
            let start = HEADER_LEN + V2_TAIL;
            if data.len() < start + ext + 16 {
                return Err(Error::Truncated);
            }
            let keys = if flags & FLAG_KEYS != 0 {
                Some(KeySection::parse(&data[start..start + ext])?)
            } else if ext != 0 {
                // Rozszerzenie bez flagi, która by je opisywała.
                return Err(Error::UnsupportedFeatures);
            } else {
                None
            };
            (start + ext, keys)
        }
        other => return Err(Error::UnsupportedVersion(other)),
    };
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
    Ok(Header {
        version,
        kdf,
        salt,
        nonce,
        len,
        keys,
    })
}

fn decrypt<T: DeserializeOwned>(key: &[u8; 32], data: &[u8], header: &Header) -> Result<T> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Decrypt)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(header.nonce),
                Payload {
                    msg: &data[header.len..],
                    aad: &data[..header.len],
                },
            )
            .map_err(|_| Error::Decrypt)?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

/// Odczyt dokumentu z kopii zapasowej (np. przy przywracaniu) tym samym hasłem. Kopia z kluczem
/// sprzętowym daje `NeedsKey`; z otwartego pliku czyta ją `Vault::open_sibling`.
pub fn open_backup<T: DeserializeOwned>(backup: &Path, password: &str) -> Result<T> {
    let data = fs::read(backup)?;
    let h = parse_header(&data)?;
    if h.keys.is_some() {
        return Err(Error::NeedsKey);
    }
    let key = derive_key(password.as_bytes(), &h.salt, h.kdf)?;
    decrypt(&key, &data, &h)
}

/// Szyfruje pakiet eksportu hasłem podanym przy eksporcie (własna sól, Argon2id jak w pliku
/// z hostami). Zwraca gotową zawartość pliku; zapis należy do wywołującego.
pub fn seal_export<T: Serialize>(password: &str, kdf: KdfParams, doc: &T) -> Result<Vec<u8>> {
    let salt = random::<SALT_LEN>()?;
    let key = derive_key(password.as_bytes(), &salt, kdf)?;
    encrypt(EXPORT_MAGIC, FORMAT_VERSION, &key, kdf, &salt, None, doc)
}

/// Odszyfrowuje pakiet eksportu. Dane bez znacznika pakietu (także plik z hostami) dają
/// `NotExport`, złe hasło albo uszkodzenie `Decrypt`. Parametry KDF z nagłówka przechodzą te same
/// granice co przy pliku z hostami, bo pakiet pochodzi z zewnątrz.
pub fn open_export<T: DeserializeOwned>(data: &[u8], password: &str) -> Result<T> {
    let h = parse_header_as(EXPORT_MAGIC, data).map_err(|e| match e {
        Error::BadMagic => Error::NotExport,
        e => e,
    })?;
    // Pakiet eksportu nie ma kluczy sprzętowych: chroni go samo hasło pliku.
    if h.keys.is_some() {
        return Err(Error::UnsupportedFeatures);
    }
    let key = derive_key(password.as_bytes(), &h.salt, h.kdf)?;
    decrypt(&key, data, &h)
}

/// Czy dane zaczynają się jak plik z hostami (do czytelnego komunikatu przy pomyłce plików).
pub fn looks_like_vault(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == MAGIC
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
    fn protected_file_uses_version_2_and_round_trips() {
        let p = tmp("v2");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        assert!(!v.protected());
        assert_eq!(fs::read(&p).unwrap()[4], FORMAT_VERSION);
        // Plik chroniony: wersja 2, puste flagi i rozszerzenie, treść czytelna tym samym hasłem.
        v.set_protected(true);
        v.save(&doc(2)).unwrap();
        let data = fs::read(&p).unwrap();
        assert_eq!(data[4], FORMAT_PROTECTED);
        assert_eq!(&data[HEADER_LEN..HEADER_LEN + V2_TAIL], &[0, 0, 0]);
        validate_file(&p).unwrap();
        assert_eq!(v.verify_file(&p).unwrap(), Verified::SameKey);
        assert_eq!(v.read_file::<Doc>(&p).unwrap(), Some(doc(2)));
        let (reopened, back) = Vault::open::<Doc>(&p, "haslo").unwrap();
        assert_eq!(back, doc(2));
        assert!(reopened.protected());
        // Kopia zapasowa sprzed ochrony (wersja 1) nadal się czyta, nowa jest w wersji 2.
        assert_eq!(
            open_backup::<Doc>(&backup_file(&p, 1), "haslo").unwrap(),
            doc(1)
        );
        v.save(&doc(3)).unwrap();
        assert_eq!(fs::read(backup_file(&p, 1)).unwrap()[4], FORMAT_PROTECTED);
        assert_eq!(
            open_backup::<Doc>(&backup_file(&p, 1), "haslo").unwrap(),
            doc(2)
        );
        // Zmiana hasła zachowuje ochronę, zdjęcie ochrony wraca do wersji 1.
        v.change_password("nowe", &doc(3)).unwrap();
        assert_eq!(fs::read(&p).unwrap()[4], FORMAT_PROTECTED);
        assert_eq!(Vault::open::<Doc>(&p, "nowe").unwrap().1, doc(3));
        v.set_protected(false);
        v.save(&doc(4)).unwrap();
        assert_eq!(fs::read(&p).unwrap()[4], FORMAT_VERSION);
        assert!(!Vault::open::<Doc>(&p, "nowe").unwrap().0.protected());
    }

    #[test]
    fn version_2_tail_is_authenticated_and_unknown_features_are_refused() {
        let p = tmp("v2-tail");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        v.set_protected(true);
        v.save(&doc(2)).unwrap();
        let good = fs::read(&p).unwrap();
        // Nieznana flaga i niepuste rozszerzenie: plik wymaga nowszego programu.
        let mut flagged = good.clone();
        flagged[HEADER_LEN] = 2;
        fs::write(&p, &flagged).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::UnsupportedFeatures)
        ));
        assert!(matches!(validate_file(&p), Err(Error::UnsupportedFeatures)));
        let mut extended = good.clone();
        extended[HEADER_LEN + 1] = 4;
        fs::write(&p, &extended).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::UnsupportedFeatures)
        ));
        // Zmiana samego numeru wersji (2 na 1 albo 1 na 2) psuje uwierzytelnienie: nie da się
        // "zdjąć ochrony" z pliku bez hasła ani jej podrobić.
        let mut downgraded = good.clone();
        downgraded[4] = FORMAT_VERSION;
        fs::write(&p, &downgraded).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::Decrypt)
        ));
        // Obcięcie w obrębie końcówki nagłówka.
        fs::write(&p, &good[..HEADER_LEN + V2_TAIL + 15]).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::Truncated)
        ));
        // Wersja nieznana obu formatom.
        let mut future = good.clone();
        future[4] = 3;
        fs::write(&p, &future).unwrap();
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::UnsupportedVersion(3))
        ));
        // Pakiet eksportu zostaje w wersji 1.
        let sealed = seal_export("haslo-eksportu", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        assert_eq!(sealed[4], FORMAT_VERSION);
    }

    #[test]
    fn read_file_decrypts_same_key_and_declines_other_key() {
        let p = tmp("read-file");
        let v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        // Kopia pliku z późniejszą zawartością (ten sam klucz, jak plik z folderu synchronizacji).
        let other = p.dir.join("zdalny.mrm");
        v.save(&doc(3)).unwrap();
        fs::copy(&*p, &other).unwrap();
        v.save(&doc(1)).unwrap();
        assert_eq!(v.read_file::<Doc>(&other).unwrap(), Some(doc(3)));
        // Uszkodzony bajt treści: błąd, nie pusty wynik.
        let mut bytes = fs::read(&other).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let broken = p.dir.join("uszkodzony.mrm");
        fs::write(&broken, &bytes).unwrap();
        assert!(matches!(v.read_file::<Doc>(&broken), Err(Error::Decrypt)));
        // Plik z innym hasłem (inna sól): nie da się odczytać bez hasła.
        let foreign = p.dir.join("obcy.mrm");
        Vault::create(&foreign, "inne", KdfParams::FAST_FOR_TESTS, &doc(2)).unwrap();
        assert_eq!(v.read_file::<Doc>(&foreign).unwrap(), None);
        // To nie plik z hostami.
        let junk = p.dir.join("smieci.mrm");
        fs::write(&junk, b"cokolwiek").unwrap();
        assert!(matches!(v.read_file::<Doc>(&junk), Err(Error::BadMagic)));
        assert!(matches!(
            v.read_file::<Doc>(&p.dir.join("brak.mrm")),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn export_round_trip_and_separation_from_vault_files() {
        let doc = doc(2);
        let sealed = seal_export("haslo-eksportu", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        assert_eq!(&sealed[..4], b"MRMX");
        assert!(!looks_like_vault(&sealed));
        let back: Doc = open_export(&sealed, "haslo-eksportu").unwrap();
        assert_eq!(back, doc);
        // Każdy eksport ma własną sól i nonce.
        let again = seal_export("haslo-eksportu", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        assert_ne!(sealed, again);
        // Złe hasło, uszkodzony bajt treści i nagłówka.
        assert!(matches!(
            open_export::<Doc>(&sealed, "inne"),
            Err(Error::Decrypt)
        ));
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open_export::<Doc>(&bad, "haslo-eksportu"),
            Err(Error::Decrypt)
        ));
        let mut bad = sealed.clone();
        bad[20] ^= 1;
        assert!(matches!(
            open_export::<Doc>(&bad, "haslo-eksportu"),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            open_export::<Doc>(&sealed[..30], "haslo-eksportu"),
            Err(Error::Truncated)
        ));
        // Pakiet nie jest plikiem z hostami: nie otworzy się ani nie przejdzie walidacji.
        let path = tmp("eksport-jako-sejf");
        fs::write(&path, &sealed).unwrap();
        assert!(matches!(validate_file(&path), Err(Error::BadMagic)));
        assert!(matches!(
            Vault::open::<Doc>(&path, "haslo-eksportu"),
            Err(Error::BadMagic)
        ));
        // A plik z hostami nie jest pakietem, nawet z tym samym hasłem.
        let path = tmp("sejf-jako-eksport");
        Vault::create(&path, "haslo-eksportu", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let data = fs::read(&*path).unwrap();
        assert!(looks_like_vault(&data));
        assert!(matches!(
            open_export::<Doc>(&data, "haslo-eksportu"),
            Err(Error::NotExport)
        ));
    }

    /// Udawany klucz sprzętowy: sekret zależy od klucza urządzenia, poświadczenia i soli,
    /// tak jak odpowiedź hmac-secret prawdziwego klucza.
    fn device_secret(
        device: u8,
        credential: &[u8],
        salt: &[u8; KEY_SECRET_LEN],
    ) -> [u8; KEY_SECRET_LEN] {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update([device]);
        h.update(credential);
        h.update(salt);
        h.finalize().into()
    }

    /// Otwiera plik hasłem i kluczem o podanym urządzeniu i poświadczeniu.
    fn open_with_key(
        p: &Tmp,
        password: &str,
        device: u8,
        credential: &[u8],
    ) -> Result<(Vault, Doc)> {
        match Vault::open_step::<Doc>(p, password)? {
            Opened::Ready(..) => panic!("plik nie wymaga klucza"),
            Opened::NeedsKey(ch) => {
                let secret = device_secret(device, credential, &ch.salt());
                ch.finish(credential, &secret)
            }
        }
    }

    #[test]
    fn hardware_key_is_required_together_with_password() {
        let p = tmp("klucz");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        assert!(v.keys().is_empty());
        assert_eq!(v.key_salt(), None);
        let salt = Vault::new_key_salt().unwrap();
        v.add_key(
            &doc(2),
            " Niebieski ",
            b"cred-a",
            &salt,
            &device_secret(1, b"cred-a", &salt),
        )
        .unwrap();
        assert_eq!(v.key_salt(), Some(salt));
        assert_eq!(
            v.keys(),
            vec![KeyInfo {
                credential: b"cred-a".to_vec(),
                name: "Niebieski".into()
            }]
        );
        // Plik ma wersję 2 z flagą kluczy, a sekret ani klucz danych nie leżą w nim jawnie.
        let data = fs::read(&p).unwrap();
        assert_eq!(data[4], FORMAT_PROTECTED);
        assert_eq!(data[HEADER_LEN], FLAG_KEYS);
        let secret = device_secret(1, b"cred-a", &salt);
        assert!(!data.windows(32).any(|w| w == secret));
        // Samo hasło nie wystarcza, ani przez `open`, ani przez kopię zapasową.
        assert!(matches!(
            Vault::open::<Doc>(&p, "haslo"),
            Err(Error::NeedsKey)
        ));
        assert!(matches!(
            open_backup::<Doc>(&p, "haslo"),
            Err(Error::NeedsKey)
        ));
        validate_file(&p).unwrap();
        // Hasło i klucz otwierają plik, a zapis zachowuje listę kluczy.
        let (reopened, back) = open_with_key(&p, "haslo", 1, b"cred-a").unwrap();
        assert_eq!(back, doc(2));
        assert_eq!(reopened.keys(), v.keys());
        assert!(reopened.protected());
        reopened.save(&doc(3)).unwrap();
        assert_eq!(open_with_key(&p, "haslo", 1, b"cred-a").unwrap().1, doc(3));
        // Inne urządzenie z tym samym poświadczeniem, nieznane poświadczenie i zły sekret.
        assert!(matches!(
            open_with_key(&p, "haslo", 2, b"cred-a"),
            Err(Error::KeyRejected)
        ));
        assert!(matches!(
            open_with_key(&p, "haslo", 1, b"cred-x"),
            Err(Error::KeyRejected)
        ));
        // Dobry klucz i złe hasło: klucz pasuje, ale treść się nie odszyfruje.
        assert!(matches!(
            open_with_key(&p, "zle-haslo", 1, b"cred-a"),
            Err(Error::Decrypt)
        ));
        // Sprawdzenie klucza i hasła na otwartym pliku.
        assert!(reopened.key_matches(b"cred-a", &secret));
        assert!(!reopened.key_matches(b"cred-a", &device_secret(2, b"cred-a", &salt)));
        assert!(!reopened.key_matches(b"cred-x", &secret));
        assert!(reopened.check_password("haslo").unwrap());
        assert!(!reopened.check_password("inne").unwrap());
        // Wyzwanie można wykorzystać ponownie po nieudanej próbie.
        let Opened::NeedsKey(ch) = Vault::open_step::<Doc>(&p, "haslo").unwrap() else {
            panic!("plik wymaga klucza");
        };
        assert_eq!(ch.keys().len(), 1);
        assert!(matches!(
            ch.finish::<Doc>(b"cred-a", &[0; KEY_SECRET_LEN]),
            Err(Error::KeyRejected)
        ));
        let good = device_secret(1, b"cred-a", &ch.salt());
        assert_eq!(ch.finish::<Doc>(b"cred-a", &good).unwrap().1, doc(3));
    }

    #[test]
    fn second_key_password_change_and_key_removal() {
        let p = tmp("klucze");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        let salt = Vault::new_key_salt().unwrap();
        v.add_key(
            &doc(1),
            "A",
            b"cred-a",
            &salt,
            &device_secret(1, b"cred-a", &salt),
        )
        .unwrap();
        // Drugi klucz: sekret dla tej samej soli, bez udziału pierwszego klucza.
        let other = Vault::new_key_salt().unwrap();
        assert!(matches!(
            v.add_key(
                &doc(1),
                "B",
                b"cred-b",
                &other,
                &device_secret(2, b"cred-b", &other)
            ),
            Err(Error::KeyRequest(_))
        ));
        v.add_key(
            &doc(1),
            "B",
            b"cred-b",
            &salt,
            &device_secret(2, b"cred-b", &salt),
        )
        .unwrap();
        assert_eq!(v.keys().len(), 2);
        assert_eq!(open_with_key(&p, "haslo", 1, b"cred-a").unwrap().1, doc(1));
        assert_eq!(open_with_key(&p, "haslo", 2, b"cred-b").unwrap().1, doc(1));
        // Powtórna rejestracja, zła nazwa i puste poświadczenie są odrzucane bez zapisu.
        let before = fs::read(&p).unwrap();
        for (name, cred) in [("A2", &b"cred-a"[..]), ("", b"cred-c"), ("C", b"")] {
            assert!(matches!(
                v.add_key(&doc(1), name, cred, &salt, &device_secret(3, cred, &salt)),
                Err(Error::KeyRequest(_))
            ));
        }
        assert_eq!(fs::read(&p).unwrap(), before);

        // Zmiana hasła nie wymaga żadnego klucza; stare hasło przestaje działać z każdym kluczem.
        v.change_password("nowe", &doc(2)).unwrap();
        assert_eq!(open_with_key(&p, "nowe", 1, b"cred-a").unwrap().1, doc(2));
        assert_eq!(open_with_key(&p, "nowe", 2, b"cred-b").unwrap().1, doc(2));
        assert!(matches!(
            open_with_key(&p, "haslo", 1, b"cred-a"),
            Err(Error::Decrypt)
        ));
        v.save(&doc(3)).unwrap();
        assert_eq!(open_with_key(&p, "nowe", 2, b"cred-b").unwrap().1, doc(3));

        // Usunięcie klucza A: nowa sól i sekret klucza B dla niej.
        let new_salt = Vault::new_key_salt().unwrap();
        assert!(matches!(
            v.remove_key(
                &doc(3),
                b"cred-a",
                &salt,
                &[(b"cred-b".to_vec(), device_secret(2, b"cred-b", &salt))]
            ),
            Err(Error::KeyRequest(_))
        ));
        assert!(matches!(
            v.remove_key(&doc(3), b"cred-a", &new_salt, &[]),
            Err(Error::KeyRequest(_))
        ));
        assert!(matches!(
            v.remove_key(&doc(3), b"cred-x", &new_salt, &[]),
            Err(Error::KeyRequest(_))
        ));
        let old_file = fs::read(&p).unwrap();
        v.remove_key(
            &doc(4),
            b"cred-a",
            &new_salt,
            &[(b"cred-b".to_vec(), device_secret(2, b"cred-b", &new_salt))],
        )
        .unwrap();
        assert_eq!(v.keys().len(), 1);
        assert_eq!(v.key_salt(), Some(new_salt));
        assert_eq!(open_with_key(&p, "nowe", 2, b"cred-b").unwrap().1, doc(4));
        assert!(matches!(
            open_with_key(&p, "nowe", 1, b"cred-a"),
            Err(Error::KeyRejected)
        ));
        // Klucz danych się zmienił: usunięty klucz odpakowuje stary klucz danych ze starej kopii,
        // ale nowej wersji pliku nim nie odszyfruje (nowy klucz treści).
        let old_copy = tmp("klucze-stara-kopia");
        fs::write(&old_copy, &old_file).unwrap();
        let (old_vault, _) = open_with_key(&old_copy, "nowe", 1, b"cred-a").unwrap();
        assert_eq!(old_vault.verify_file(&p).unwrap(), Verified::OtherKey);
        assert_eq!(old_vault.read_file::<Doc>(&p).unwrap(), None);
        // Zapis po usunięciu działa dalej.
        v.save(&doc(5)).unwrap();
        assert_eq!(open_with_key(&p, "nowe", 2, b"cred-b").unwrap().1, doc(5));

        // Usunięcie ostatniego klucza: wraca samo hasło i wersja 1.
        v.remove_key(&doc(6), b"cred-b", &Vault::new_key_salt().unwrap(), &[])
            .unwrap();
        assert!(v.keys().is_empty());
        assert_eq!(fs::read(&p).unwrap()[4], FORMAT_VERSION);
        assert_eq!(Vault::open::<Doc>(&p, "nowe").unwrap().1, doc(6));
        assert!(matches!(
            v.remove_key(&doc(6), b"cred-b", &new_salt, &[]),
            Err(Error::KeyRequest(_))
        ));
    }

    #[test]
    fn key_limit_sibling_files_and_sync_checks() {
        let p = tmp("klucze-pliki");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        v.save(&doc(2)).unwrap();
        // Kopia sprzed kluczy pod własną nazwą: kolejne zapisy przesuwają numery kopii.
        let plain_backup = p.dir.join("sprzed-kluczy.mrm");
        fs::copy(backup_file(&p, 1), &plain_backup).unwrap();
        let salt = Vault::new_key_salt().unwrap();
        for i in 0..MAX_KEYS as u8 {
            let cred = [b'c', i];
            v.add_key(
                &doc(3),
                &format!("K{i}"),
                &cred,
                &salt,
                &device_secret(i, &cred, &salt),
            )
            .unwrap();
        }
        assert!(matches!(
            v.add_key(
                &doc(3),
                "za dużo",
                b"zz",
                &salt,
                &device_secret(9, b"zz", &salt)
            ),
            Err(Error::KeyRequest(_))
        ));
        // Kopia sprzed kluczy czyta się samym hasłem, kopia z tą samą listą kluczy bez dotykania
        // klucza, a po zmianie listy kluczy starsza kopia wymaga klucza.
        assert_eq!(
            v.open_sibling::<Doc>(&plain_backup, "haslo").unwrap(),
            doc(1)
        );
        v.save(&doc(4)).unwrap();
        let keyed_backup = backup_file(&p, 1);
        assert_eq!(
            v.open_sibling::<Doc>(&keyed_backup, "haslo").unwrap(),
            doc(3)
        );
        assert!(matches!(
            v.open_sibling::<Doc>(&keyed_backup, "inne"),
            Err(Error::Decrypt)
        ));
        // Ten sam plik w folderze synchronizacji: ta sama lista kluczy daje pełną kontrolę.
        let remote = p.dir.join("zdalny.mrm");
        fs::copy(&*p, &remote).unwrap();
        assert_eq!(v.verify_file(&remote).unwrap(), Verified::SameKey);
        assert_eq!(v.read_file::<Doc>(&remote).unwrap(), Some(doc(4)));
        let mut broken = fs::read(&remote).unwrap();
        *broken.last_mut().unwrap() ^= 1;
        let bad = p.dir.join("zepsuty.mrm");
        fs::write(&bad, &broken).unwrap();
        assert!(matches!(v.verify_file(&bad), Err(Error::Decrypt)));
        // Po usunięciu klucza zdalna kopia ma inną listę kluczy: nie da się jej sprawdzić bez klucza.
        let new_salt = Vault::new_key_salt().unwrap();
        let remaining: Vec<_> = (1..MAX_KEYS as u8)
            .map(|i| {
                let cred = vec![b'c', i];
                let secret = device_secret(i, &cred, &new_salt);
                (cred, secret)
            })
            .collect();
        v.remove_key(&doc(5), &[b'c', 0], &new_salt, &remaining)
            .unwrap();
        assert_eq!(v.keys().len(), MAX_KEYS - 1);
        assert_eq!(v.verify_file(&remote).unwrap(), Verified::OtherKey);
        assert_eq!(v.read_file::<Doc>(&remote).unwrap(), None);
        assert!(matches!(
            v.open_sibling::<Doc>(&keyed_backup, "haslo"),
            Err(Error::NeedsKey)
        ));
    }

    #[test]
    fn key_section_in_header_is_validated_and_authenticated() {
        let p = tmp("klucze-naglowek");
        let mut v = Vault::create(&p, "haslo", KdfParams::FAST_FOR_TESTS, &doc(1)).unwrap();
        let salt = Vault::new_key_salt().unwrap();
        v.add_key(
            &doc(1),
            "Klucz",
            b"cred-a",
            &salt,
            &device_secret(1, b"cred-a", &salt),
        )
        .unwrap();
        let good = fs::read(&p).unwrap();
        let ext_at = HEADER_LEN + V2_TAIL;
        let ext_len = usize::from(u16::from_le_bytes([
            good[HEADER_LEN + 1],
            good[HEADER_LEN + 2],
        ]));
        let write = |bytes: &[u8]| fs::write(&p, bytes).unwrap();
        let open = || Vault::open_step::<Doc>(&p, "haslo").map(|_| ());
        // Zmiana nazwy klucza w nagłówku psuje uwierzytelnienie treści.
        let mut renamed = good.clone();
        renamed[ext_at + ext_len - 1] ^= 1;
        write(&renamed);
        assert!(matches!(
            open_with_key(&p, "haslo", 1, b"cred-a"),
            Err(Error::Decrypt)
        ));
        // Liczba kluczy zero albo ponad limit, obcięte rozszerzenie, nadmiarowy bajt.
        let mut zero = good.clone();
        zero[ext_at + KEY_SECRET_LEN] = 0;
        write(&zero);
        assert!(matches!(open(), Err(Error::BadKeys)));
        let mut many = good.clone();
        many[ext_at + KEY_SECRET_LEN] = MAX_KEYS as u8 + 1;
        write(&many);
        assert!(matches!(open(), Err(Error::BadKeys)));
        let mut short = good.clone();
        short[HEADER_LEN + 1..HEADER_LEN + 3]
            .copy_from_slice(&((ext_len - 1) as u16).to_le_bytes());
        write(&short);
        assert!(matches!(open(), Err(Error::BadKeys)));
        let mut long = good.clone();
        long[HEADER_LEN + 1..HEADER_LEN + 3].copy_from_slice(&((ext_len + 1) as u16).to_le_bytes());
        write(&long);
        assert!(matches!(open(), Err(Error::BadKeys)));
        // Rozszerzenie dłuższe niż plik.
        let mut huge = good.clone();
        huge[HEADER_LEN + 1..HEADER_LEN + 3].copy_from_slice(&u16::MAX.to_le_bytes());
        write(&huge);
        assert!(matches!(open(), Err(Error::Truncated)));
        assert!(matches!(validate_file(&p), Err(Error::Truncated)));
        // Rozszerzenie bez flagi kluczy i nieznana flaga obok flagi kluczy.
        let mut unflagged = good.clone();
        unflagged[HEADER_LEN] = 0;
        write(&unflagged);
        assert!(matches!(open(), Err(Error::UnsupportedFeatures)));
        let mut future = good.clone();
        future[HEADER_LEN] = FLAG_KEYS | 2;
        write(&future);
        assert!(matches!(open(), Err(Error::UnsupportedFeatures)));
        // Pakiet eksportu z listą kluczy jest odrzucany.
        let mut as_export = good.clone();
        as_export[..4].copy_from_slice(EXPORT_MAGIC);
        assert!(matches!(
            open_export::<Doc>(&as_export, "haslo"),
            Err(Error::UnsupportedFeatures)
        ));
        // Poprawny plik nadal się otwiera.
        write(&good);
        assert_eq!(open_with_key(&p, "haslo", 1, b"cred-a").unwrap().1, doc(1));
    }

    #[test]
    fn create_refuses_overwrite() {
        let p = tmp("ow");
        Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).unwrap();
        assert!(Vault::create(&p, "x", KdfParams::FAST_FOR_TESTS, &doc(0)).is_err());
    }
}
