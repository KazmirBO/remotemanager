//! Dodatkowy składnik przy otwieraniu pliku z hostami: kody jednorazowe TOTP (RFC 6238).
//!
//! Sekret TOTP leży w zaszyfrowanym dokumencie, więc kod da się sprawdzić dopiero po odszyfrowaniu
//! pliku hasłem głównym. To bramka w programie, a nie składnik szyfrowania: chroni przed otwarciem
//! pliku w programie przez kogoś, kto zna samo hasło, ale nie przed odszyfrowaniem pliku innym
//! narzędziem. Składnikiem szyfrowania może być dopiero klucz sprzętowy.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Długość okna czasu kodu w sekundach.
pub const PERIOD: u64 = 30;
/// Liczba cyfr kodu.
pub const DIGITS: usize = 6;
/// Długość sekretu w bajtach (zalecana dla HMAC-SHA1).
pub const SECRET_LEN: usize = 20;
/// Liczba kodów zapasowych wydawanych przy włączeniu.
pub const RECOVERY_CODES: usize = 8;
/// Długość kodu zapasowego w znakach (bez łącznika): 10 znaków base32 to 50 bitów.
pub const RECOVERY_LEN: usize = 10;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Kodowanie base32 (RFC 4648) bez dopełnienia, tak jak oczekują aplikacje uwierzytelniające.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Kod dla danego numeru okna (HOTP z RFC 4226 z licznikiem równym numerowi okna).
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret).expect("HMAC przyjmuje klucz każdej długości");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 10u32.pow(DIGITS as u32)
}

/// Czy tekst jest kodem TOTP: dokładnie sześć cyfr po usunięciu spacji.
fn parse_code(text: &str) -> Option<u32> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Sprawdza kod w chwili `now` (sekundy od początku epoki). Przyjmuje bieżące okno oraz jedno
/// wcześniej i jedno później, żeby drobna różnica zegarów nie odrzucała dobrego kodu.
pub fn verify(secret: &[u8], text: &str, now: u64) -> bool {
    let Some(code) = parse_code(text) else {
        return false;
    };
    let step = now / PERIOD;
    // Wszystkie trzy okna są liczone zawsze, bez wcześniejszego wyjścia.
    let mut ok = false;
    for s in [step.saturating_sub(1), step, step + 1] {
        ok |= code_at(secret, s) == code;
    }
    ok
}

/// Dopuszcza w etykiecie adresu tylko znaki bezpieczne, resztę koduje procentowo.
fn percent(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Adres `otpauth://` do wklejenia w aplikacji uwierzytelniającej.
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        percent(issuer),
        percent(account),
        base32(secret),
        percent(issuer),
    )
}

/// Kod zapasowy z losowych bajtów: dziesięć znaków base32 w dwóch grupach, np. `ABCDE-FGH23`.
pub fn recovery_code(random: &[u8]) -> String {
    let text = base32(random);
    let text = &text[..RECOVERY_LEN.min(text.len())];
    let (a, b) = text.split_at(text.len() / 2);
    format!("{a}-{b}")
}

/// Kod zapasowy bez łącznika i spacji, wielkimi literami (tak wpisany kod też pasuje).
fn normalize_recovery(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

/// Skrót kodu zapasowego przechowywany w dokumencie zamiast samego kodu.
pub fn recovery_hash(code: &str) -> String {
    Sha256::digest(normalize_recovery(code).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Ustawienia TOTP zapisane w dokumencie.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totp {
    /// Sekret. Nie wolno go logować ani wysyłać do interfejsu po włączeniu.
    pub secret: Vec<u8>,
    /// Skróty niewykorzystanych kodów zapasowych.
    #[serde(default)]
    pub recovery: Vec<String>,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"***")
            .field("recovery", &self.recovery.len())
            .finish()
    }
}

impl Totp {
    /// Nowe ustawienia z sekretu i jawnych kodów zapasowych (zapisywane są ich skróty).
    pub fn new(secret: Vec<u8>, recovery_codes: &[String]) -> Self {
        Self {
            secret,
            recovery: recovery_codes.iter().map(|c| recovery_hash(c)).collect(),
        }
    }

    /// Sprawdza kod TOTP w chwili `now`.
    pub fn verify(&self, code: &str, now: u64) -> bool {
        verify(&self.secret, code, now)
    }

    /// Czy tekst jest niewykorzystanym kodem zapasowym.
    pub fn has_recovery(&self, code: &str) -> bool {
        let normalized = normalize_recovery(code);
        normalized.len() == RECOVERY_LEN && self.recovery.contains(&recovery_hash(code))
    }

    /// Zużywa kod zapasowy: zwraca `true` i usuwa go, jeśli był ważny.
    pub fn use_recovery(&mut self, code: &str) -> bool {
        if !self.has_recovery(code) {
            return false;
        }
        let hash = recovery_hash(code);
        self.recovery.retain(|h| *h != hash);
        true
    }
}

/// Dodatkowe składniki wymagane przy otwieraniu pliku.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mfa {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Totp>,
}

impl Mfa {
    /// Żaden składnik nie jest włączony: plik zostaje w podstawowej wersji formatu.
    pub fn is_empty(&self) -> bool {
        self.totp.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;

    /// Sekret z przykładów RFC 6238 dla SHA-1.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn codes_match_rfc_6238_vectors() {
        // Wektory z dodatku B (8 cyfr); sześć cyfr to ich końcówka.
        for (time, expected) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(code_at(RFC_SECRET, time / PERIOD), expected, "czas {time}");
        }
    }

    #[test]
    fn verify_accepts_neighbouring_windows_only() {
        let now = 1_111_111_109u64;
        let current = format!("{:06}", code_at(RFC_SECRET, now / PERIOD));
        assert_eq!(current, "081804");
        assert!(verify(RFC_SECRET, &current, now));
        assert!(verify(RFC_SECRET, "081 804", now));
        assert!(verify(RFC_SECRET, " 081804 ", now));
        // Jedno okno wcześniej i później przechodzi, dwa już nie.
        assert!(verify(RFC_SECRET, &current, now + PERIOD));
        assert!(verify(RFC_SECRET, &current, now - PERIOD));
        assert!(!verify(RFC_SECRET, &current, now + 2 * PERIOD));
        assert!(!verify(RFC_SECRET, &current, now - 2 * PERIOD));
        // Zły kod, zła długość, litery, pusty tekst, inny sekret.
        assert!(!verify(RFC_SECRET, "081805", now));
        assert!(!verify(RFC_SECRET, "81804", now));
        assert!(!verify(RFC_SECRET, "0818040", now));
        assert!(!verify(RFC_SECRET, "08180a", now));
        assert!(!verify(RFC_SECRET, "", now));
        assert!(!verify(b"inny sekret, inny sek", &current, now));
        // Początek epoki: okno "przed zerem" nie powoduje błędu.
        let first = format!("{:06}", code_at(RFC_SECRET, 0));
        assert!(verify(RFC_SECRET, &first, 5));
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
        assert_eq!(base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn otpauth_uri_is_escaped() {
        assert_eq!(
            otpauth_uri(RFC_SECRET, "Menedżer sesji", "plik z hostami"),
            "otpauth://totp/Mened%C5%BCer%20sesji:plik%20z%20hostami?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Mened%C5%BCer%20sesji&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_work_once_in_any_spelling() {
        let codes = vec![
            recovery_code(&[0, 1, 2, 3, 4, 5, 6]),
            recovery_code(&[9; 7]),
        ];
        assert_eq!(codes[0], "AAAQE-AYEAU");
        assert_eq!(codes[0].len(), RECOVERY_LEN + 1);
        let mut totp = Totp::new(RFC_SECRET.to_vec(), &codes);
        // W dokumencie są skróty, nie kody.
        assert!(
            totp.recovery
                .iter()
                .all(|h| h.len() == 64 && !codes.contains(h))
        );
        assert!(totp.has_recovery("aaaqe ayeau"));
        assert!(totp.has_recovery(" AAAQEAYEAU "));
        assert!(!totp.has_recovery("AAAQE-AYEAV"));
        assert!(!totp.has_recovery(""));
        assert!(!totp.has_recovery("AAAQE"));
        assert!(totp.use_recovery("aaaqe-ayeau"));
        assert!(!totp.use_recovery("AAAQE-AYEAU"));
        assert_eq!(totp.recovery.len(), 1);
        assert!(totp.use_recovery(&codes[1]));
        assert!(totp.recovery.is_empty());
        // Kod TOTP nie jest kodem zapasowym i odwrotnie.
        assert!(!totp.has_recovery("081804"));
        assert!(!totp.verify("AAAQE-AYEAU", 59));
    }

    #[test]
    fn debug_hides_secret_and_empty_mfa_is_not_serialized() {
        let totp = Totp::new(RFC_SECRET.to_vec(), &["AAAQE-AYEAU".into()]);
        let shown = format!("{totp:?}");
        assert!(!shown.contains("49") && !shown.contains("12345"), "{shown}");
        assert!(shown.contains("***"));
        // Dokument bez dodatkowego składnika serializuje się bez pola `mfa` (jak starsze pliki).
        let plain = Document::default();
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("mfa"), "{json}");
        // Starszy plik bez pola czyta się jako brak składnika.
        let old: Document = serde_json::from_str("{}").unwrap();
        assert!(old.mfa.is_empty());
        // Z włączonym TOTP pole jest zapisywane i wraca bez zmian.
        let mut doc = Document::default();
        doc.mfa.totp = Some(totp);
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"mfa\""));
        let back: Document = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
        assert!(!format!("{doc:?}").contains("12345"));
    }
}
