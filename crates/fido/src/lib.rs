//! Klucz sprzętowy FIDO2 jako źródło sekretu (rozszerzenie hmac-secret).
//!
//! Klucz przechowuje poświadczenie i dla danej soli zwraca zawsze ten sam 32-bajtowy sekret,
//! którego nie da się z niego wyjąć inaczej. Crate `vault` opakowuje tym sekretem klucz danych
//! pliku z hostami. Dwie implementacje dają ten sam sekret dla tego samego klucza:
//!
//! - Linux: protokół CTAP2 po USB HID (`ctap-hid-fido2`), PIN podaje program,
//! - Windows: systemowe API WebAuthn (`webauthn.dll`), o PIN pyta okno systemu.
//!
//! Zgodność między systemami zapewniają dwie rzeczy. Sól przechodzi przez przekształcenie
//! rozszerzenia PRF z WebAuthn (`prf_salt`), które Windows stosuje sam, a część linuksowa
//! liczy jawnie. Klucz zawsze sprawdza użytkownika (PIN): hmac-secret ma osobny sekret dla
//! operacji z weryfikacją i bez niej, więc mieszanie obu trybów dawałoby różne wyniki.

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod linux;
pub mod soft;
#[cfg(windows)]
#[allow(unsafe_code)]
mod win;

/// Identyfikator strony ufającej (ang. _relying party_), do którego przypięte są poświadczenia.
/// Dwukropek na końcu (wzorem `ssh:` z OpenSSH) wyklucza zbieżność z adresem strony WWW.
/// Zmiana tej wartości unieważnia wszystkie zarejestrowane klucze.
pub const RP_ID: &str = "mrmv:";
/// Nazwa pokazywana przez system przy pytaniu o klucz.
pub const RP_NAME: &str = "Plik z hostami";
/// Długość soli i sekretu.
pub const SECRET_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("nie znaleziono klucza sprzętowego")]
    NoDevice,
    #[error("podłączono więcej niż jeden klucz sprzętowy")]
    ManyDevices,
    #[error("klucz wymaga PIN-u")]
    PinRequired,
    #[error("nieprawidłowy PIN klucza")]
    PinInvalid {
        /// Ile prób zostało, jeśli klucz to podał.
        retries: Option<u32>,
    },
    #[error("PIN klucza jest zablokowany")]
    PinBlocked,
    #[error("klucz wstrzymał sprawdzanie PIN-u do ponownego włożenia")]
    PinAuthBlocked,
    #[error("klucz nie ma ustawionego PIN-u")]
    PinNotSet,
    #[error("ten klucz nie jest zarejestrowany")]
    NotRegistered,
    #[error("ten klucz jest już zarejestrowany")]
    AlreadyRegistered,
    #[error("operacja anulowana")]
    Cancelled,
    #[error("minął czas na dotknięcie klucza")]
    Timeout,
    #[error("klucz albo system nie obsługuje tej funkcji: {0}")]
    Unsupported(String),
    #[error("błąd klucza sprzętowego: {0}")]
    Other(String),
}

/// Kto pyta o PIN klucza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinEntry {
    /// Program: PIN trzeba przekazać w wywołaniu.
    App,
    /// System operacyjny we własnym oknie: PIN w wywołaniu jest ignorowany.
    System,
}

/// Odpowiedź klucza: które poświadczenie odpowiedziało i jaki sekret zwróciło.
pub struct Secret {
    pub credential: Vec<u8>,
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
}

/// Klucz sprzętowy. Wywołania blokują do czasu dotknięcia klucza, więc nie wolno ich robić
/// z wątku pętli zdarzeń.
pub trait Authenticator: Send + Sync {
    fn pin_entry(&self) -> PinEntry;

    /// Tworzy na kluczu poświadczenie z obsługą hmac-secret i zwraca jego identyfikator.
    /// Klucz, który ma już poświadczenie z listy `exclude`, odmawia (`AlreadyRegistered`).
    fn register(&self, pin: Option<&str>, exclude: &[Vec<u8>]) -> Result<Vec<u8>, Error>;

    /// Pyta klucz o sekret dla soli. Odpowiada klucz, który ma jedno z poświadczeń z listy.
    fn secret(
        &self,
        credentials: &[Vec<u8>],
        salt: &[u8; SECRET_LEN],
        pin: Option<&str>,
    ) -> Result<Secret, Error>;
}

/// Klucz sprzętowy obsługiwany na tym systemie albo `None`, gdy takiej obsługi nie ma.
/// `window` to uchwyt głównego okna (Windows: `HWND`), nad którym system pokaże swoje okno.
pub fn platform(window: Option<isize>) -> Option<Box<dyn Authenticator>> {
    #[cfg(target_os = "linux")]
    {
        let _ = window;
        Some(Box::new(linux::HidKey))
    }
    #[cfg(windows)]
    {
        win::WinKey::new(window).map(|k| Box::new(k) as Box<dyn Authenticator>)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = window;
        None
    }
}

/// Sól w postaci, którą dostaje klucz: przekształcenie rozszerzenia PRF z WebAuthn,
/// `SHA-256("WebAuthn PRF" || 0x00 || sól)`. Windows liczy je sam, pozostałe implementacje
/// wołają tę funkcję, dzięki czemu ten sam klucz daje ten sam sekret na każdym systemie.
pub fn prf_salt(salt: &[u8; SECRET_LEN]) -> [u8; SECRET_LEN] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(salt);
    h.finalize().into()
}

/// Losowe wyzwanie dla klucza. Podpisu pod nim nie sprawdzamy: dowodem jest sekret, który
/// odpakowuje klucz danych.
#[cfg(any(target_os = "linux", windows))]
fn challenge() -> Result<[u8; 32], Error> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| Error::Other(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_salt_matches_webauthn_definition() {
        // Wartość policzona niezależnie: sha256(b"WebAuthn PRF\x00" + bytes(range(32))).
        let salt: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hex: String = prf_salt(&salt).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, EXPECTED);
        assert_ne!(prf_salt(&salt), prf_salt(&[0; 32]));
    }

    const EXPECTED: &str = "dc1f4f3b3d759586245d5de7e2e115d2a056a2df27109db7cef9b4b3a89bb106";
}
