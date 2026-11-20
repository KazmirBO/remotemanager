//! Klucze prywatne SSH: dekodowanie (także zaszyfrowanych), import do pliku hostów w postaci
//! OpenSSH bez hasła i odczyt pliku klucza z limitem rozmiaru. Materiał klucza ani hasło nie
//! trafiają do `Debug` ani do komunikatów błędów.

use std::io::Read;
use std::sync::Arc;

use russh::keys::ssh_key::{self, LineEnding};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

/// Limit tekstu klucza i pliku klucza.
pub const MAX_KEY_TEXT: usize = 64 * 1024;

/// Odszyfrowany klucz prywatny gotowy do logowania. `Debug` nie pokazuje materiału.
#[derive(Clone)]
pub struct SecretKey(pub(crate) Arc<PrivateKey>);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.info();
        write!(f, "SecretKey({} {})", info.algorithm, info.fingerprint)
    }
}

impl SecretKey {
    /// Algorytm i odcisk klucza publicznego.
    pub fn info(&self) -> KeyInfo {
        KeyInfo {
            algorithm: self.0.algorithm().to_string(),
            fingerprint: self.0.fingerprint(HashAlg::Sha256).to_string(),
        }
    }
}

/// Dane klucza publicznego pokazywane użytkownikowi i zapisywane w dzienniku.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// Np. "ssh-ed25519".
    pub algorithm: String,
    /// Np. "SHA256:...".
    pub fingerprint: String,
}

impl KeyInfo {
    pub(crate) fn of_public(key: &russh::keys::PublicKey) -> Self {
        KeyInfo {
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("klucz jest zaszyfrowany i wymaga hasła")]
    NeedsPassphrase,
    #[error("nieprawidłowe hasło klucza")]
    WrongPassphrase,
    #[error("nieobsługiwany albo uszkodzony klucz: {0}")]
    Invalid(String),
    #[error("klucz jest za duży (limit 64 KiB)")]
    TooLarge,
    #[error("nie można odczytać pliku klucza: {0}")]
    Unreadable(String),
}

const PKCS8_ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const PPK_HEADER: &str = "PuTTY-User-Key-File-";
/// Jedyne szyfrowanie PEM (PKCS#5), które czyta russh.
const DEK_AES_128: &str = "DEK-Info: AES-128-CBC,";

/// Co wiadomo o szyfrowaniu klucza z samego tekstu (bez dekodowania).
struct Markers {
    pkcs8_encrypted: bool,
    pkcs8_plain: bool,
    /// Wiersz `DEK-Info:` (zaszyfrowany PEM PKCS#5).
    dek: Option<String>,
    /// Plik PuTTY z szyfrowaniem innym niż `none`.
    ppk_encrypted: bool,
    /// Nagłówek `EC PRIVATE KEY` (stary format PEM klucza ECDSA).
    ec_pem: bool,
}

impl Markers {
    fn of(text: &str) -> Self {
        let ppk = text.trim_start().starts_with(PPK_HEADER);
        let mut m = Markers {
            pkcs8_encrypted: false,
            pkcs8_plain: false,
            dek: None,
            ppk_encrypted: false,
            ec_pem: false,
        };
        for line in text.lines() {
            let line = line.trim();
            if line == PKCS8_ENCRYPTED {
                m.pkcs8_encrypted = true;
            } else if line == "-----BEGIN PRIVATE KEY-----"
                || line == "-----BEGIN EC PRIVATE KEY-----"
            {
                m.ec_pem |= line.contains(" EC ");
                m.pkcs8_plain = true;
            } else if line.starts_with("DEK-Info:") {
                m.dek = Some(line.to_owned());
            } else if ppk && let Some(v) = line.strip_prefix("Encryption:") {
                m.ppk_encrypted = v.trim() != "none";
            }
        }
        m
    }

    fn encrypted(&self) -> bool {
        self.pkcs8_encrypted || self.dek.is_some() || self.ppk_encrypted
    }
}

/// Opis błędu russh bez treści klucza (komunikaty PuTTY potrafią cytować wiersze pliku).
fn describe(e: &russh::keys::Error) -> String {
    use russh::keys::Error as E;
    let text = match e {
        E::SshKey(ssh_key::Error::Ppk(_)) => {
            "nieprawidłowy albo nieobsługiwany plik PuTTY (.ppk)".to_owned()
        }
        E::CouldNotReadKey => "nie rozpoznano formatu klucza".to_owned(),
        E::Decode(_) => "nieprawidłowe kodowanie base64".to_owned(),
        other => other.to_string(),
    };
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

fn classify(e: russh::keys::Error, m: &Markers, with_pass: bool) -> KeyError {
    use russh::keys::Error as E;
    match &e {
        E::KeyIsEncrypted => return KeyError::NeedsPassphrase,
        E::SshKey(ssh_key::Error::Ppk(p)) if p.to_string() == "private key is encrypted" => {
            return KeyError::NeedsPassphrase;
        }
        _ => {}
    }
    if !with_pass {
        return KeyError::Invalid(describe(&e));
    }
    let wrong = match &e {
        E::SshKey(ssh_key::Error::Crypto) | E::Unpad(_) => true,
        E::SshKey(ssh_key::Error::Ppk(p)) => p.to_string() == "incorrect MAC",
        E::Pkcs8(_) | E::Der(_) | E::Sec1(_) | E::Spki(_) if m.pkcs8_encrypted => true,
        E::Pkcs1(_) | E::Der(_) | E::Rsa(_) if m.dek.is_some() => true,
        // Nieobsługiwany algorytm to nie złe hasło.
        E::UnknownAlgorithm(_) | E::UnsupportedKeyType { .. } => false,
        // Nierozpoznany błąd przy podanym haśle i zaszyfrowanym nagłówku: najpewniej złe hasło.
        _ => m.encrypted(),
    };
    if wrong {
        KeyError::WrongPassphrase
    } else {
        KeyError::Invalid(describe(&e))
    }
}

/// Dekoduje klucz (OpenSSH, PKCS#8, PKCS#5/PKCS#1 PEM, PuTTY .ppk), także zaszyfrowany.
/// Puste hasło (`Some("")`) traktuje jak `None`.
pub fn parse_key(text: &str, passphrase: Option<&str>) -> Result<SecretKey, KeyError> {
    if text.len() > MAX_KEY_TEXT {
        return Err(KeyError::TooLarge);
    }
    // BOM (UTF-8 z Notatnika Windows) i wiodące puste wiersze kończyłyby się błędem formatu.
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let passphrase = passphrase.filter(|p| !p.is_empty());
    let m = Markers::of(text);
    if passphrase.is_none() && (m.pkcs8_encrypted || m.ppk_encrypted) {
        // russh nie zwraca tu `KeyIsEncrypted`.
        return Err(KeyError::NeedsPassphrase);
    }
    if let Some(dek) = &m.dek
        && !dek.starts_with(DEK_AES_128)
    {
        return Err(KeyError::Invalid(
            "nieobsługiwane szyfrowanie klucza PEM (obsługiwane jest tylko AES-128-CBC)".into(),
        ));
    }
    // Biblioteka nie odszyfrowuje klucza ECDSA w starym formacie PEM, także z dobrym hasłem,
    // więc pytanie o hasło wracałoby w kółko. Mówimy od razu, co z takim kluczem zrobić.
    if m.ec_pem && m.dek.is_some() {
        return Err(KeyError::Invalid(
            "zaszyfrowany klucz ECDSA w starym formacie PEM nie jest obsługiwany; zapisz go w formacie OpenSSH poleceniem ssh-keygen -p -f <plik>".into(),
        ));
    }
    // Hasło podane do niezaszyfrowanego PKCS#8 kończyłoby się błędem dekodowania.
    let pass = if m.pkcs8_plain && !m.pkcs8_encrypted {
        None
    } else {
        passphrase
    };
    let key =
        russh::keys::decode_secret_key(text, pass).map_err(|e| classify(e, &m, pass.is_some()))?;
    if key.is_encrypted() {
        return Err(KeyError::NeedsPassphrase);
    }
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. } => {}
        other => {
            return Err(KeyError::Invalid(format!(
                "nieobsługiwany algorytm klucza {other}"
            )));
        }
    }
    Ok(SecretKey(Arc::new(key)))
}

/// Import do pliku hostów: dekoduje jak `parse_key` i zwraca odszyfrowany tekst OpenSSH (LF)
/// oraz dane klucza publicznego.
pub fn import_key(
    text: &str,
    passphrase: Option<&str>,
) -> Result<(Zeroizing<String>, KeyInfo), KeyError> {
    let key = parse_key(text, passphrase)?;
    let openssh = key
        .0
        .to_openssh(LineEnding::LF)
        .map_err(|e| KeyError::Invalid(e.to_string()))?;
    Ok((openssh, key.info()))
}

/// Czyta plik klucza z limitem `MAX_KEY_TEXT` do bufora `Zeroizing`. Plik większy -> `TooLarge`,
/// błąd odczytu albo treść spoza UTF-8 -> `Unreadable`.
pub fn read_key_file(path: &std::path::Path) -> Result<Zeroizing<String>, KeyError> {
    let unreadable = |e: std::io::Error| KeyError::Unreadable(e.to_string());
    let not_regular = || KeyError::Unreadable("to nie jest zwykły plik".into());
    // Nazwany potok zablokowałby otwarcie bez limitu czasu, więc typ sprawdzamy przed `open`.
    if !std::fs::metadata(path).map_err(unreadable)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    if meta.len() > MAX_KEY_TEXT as u64 {
        return Err(KeyError::TooLarge);
    }
    // Bufor od razu na cały limit, żeby wzrost wektora nie zostawiał niewyzerowanych kopii.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_KEY_TEXT + 64));
    file.take(MAX_KEY_TEXT as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(unreadable)?;
    if buf.len() > MAX_KEY_TEXT {
        return Err(KeyError::TooLarge);
    }
    let text = std::str::from_utf8(&buf)
        .map_err(|_| KeyError::Unreadable("plik nie jest tekstem UTF-8".into()))?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const PASS: &str = "haslo-klucza";

    /// Plik PuTTY bez materiału klucza: sam nagłówek i wiersze, na których testy sprawdzają nasze
    /// rozpoznawanie szyfrowania i opis błędu. Prawdziwych kluczy prywatnych nie trzymamy w
    /// repozytorium; pozostałe formaty testy generują w locie przez `ssh-keygen`.
    fn ppk_stub(encryption: &str, tail: &str) -> String {
        format!(
            "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: {encryption}\nComment: test\n{tail}\n"
        )
    }

    fn keygen() -> Option<PathBuf> {
        std::env::var_os("PATH")?
            .to_string_lossy()
            .split(':')
            .map(|d| Path::new(d).join("ssh-keygen"))
            .find(|p| p.is_file())
    }

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir() -> Dir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mrm-ssh-keys-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }

    /// Generuje klucz `ssh-keygen` z podanymi argumentami; zwraca (tekst klucza, odcisk).
    fn generate(kg: &Path, dir: &Path, name: &str, args: &[&str]) -> (String, String) {
        let p = dir.join(name);
        let out = Command::new(kg)
            .arg("-q")
            .args(args)
            .arg("-f")
            .arg(&p)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let fp = Command::new(kg)
            .arg("-lf")
            .arg(p.with_extension("pub"))
            .output()
            .unwrap();
        let fp = String::from_utf8(fp.stdout).unwrap();
        let fp = fp.split_whitespace().nth(1).unwrap().to_owned();
        (std::fs::read_to_string(&p).unwrap(), fp)
    }

    /// Klucze zaszyfrowane hasłem `PASS` w trzech formatach: OpenSSH, PEM PKCS#5, PKCS#8.
    fn encrypted(kg: &Path, dir: &Path) -> Vec<(&'static str, String, String)> {
        [
            ("enc", vec!["-t", "ed25519", "-N", PASS]),
            (
                "rsa_pem_enc",
                vec!["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", PASS],
            ),
            (
                "ecdsa_p8_enc",
                vec!["-t", "ecdsa", "-b", "256", "-m", "PKCS8", "-N", PASS],
            ),
        ]
        .into_iter()
        .map(|(name, args)| {
            let (text, fp) = generate(kg, dir, name, &args);
            (name, text, fp)
        })
        .collect()
    }

    #[test]
    fn encrypted_keys_need_and_check_passphrase() {
        let Some(kg) = keygen() else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let dir = temp_dir();
        for (name, text, fp) in encrypted(&kg, &dir.0) {
            assert_eq!(
                parse_key(&text, None).err(),
                Some(KeyError::NeedsPassphrase),
                "{name}"
            );
            assert_eq!(
                parse_key(&text, Some("")).err(),
                Some(KeyError::NeedsPassphrase),
                "{name}: puste hasło"
            );
            assert_eq!(
                parse_key(&text, Some("zle-haslo")).err(),
                Some(KeyError::WrongPassphrase),
                "{name}"
            );
            let key = parse_key(&text, Some(PASS)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(key.info().fingerprint, fp, "{name}");
        }
    }

    #[test]
    fn plain_formats_parse_and_ignore_passphrase() {
        let Some(kg) = keygen() else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let dir = temp_dir();
        for (name, args, alg) in [
            ("ed", vec!["-t", "ed25519", "-N", ""], "ssh-ed25519"),
            ("rsa", vec!["-t", "rsa", "-b", "2048", "-N", ""], "ssh-rsa"),
            (
                "rsa_pem",
                vec!["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", ""],
                "ssh-rsa",
            ),
            (
                "ecdsa_p8",
                vec!["-t", "ecdsa", "-b", "256", "-m", "PKCS8", "-N", ""],
                "ecdsa-sha2-nistp256",
            ),
        ] {
            let (text, fp) = generate(&kg, &dir.0, name, &args);
            for pass in [None, Some("niepotrzebne")] {
                let info = parse_key(&text, pass)
                    .unwrap_or_else(|e| panic!("{name} {pass:?}: {e}"))
                    .info();
                assert_eq!(info.fingerprint, fp, "{name}");
                assert_eq!(info.algorithm, alg, "{name}");
            }
        }
    }

    #[test]
    fn encrypted_ec_pem_is_reported_as_unsupported() {
        let Some(kg) = keygen() else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let dir = temp_dir();
        let (text, _) = generate(
            &kg,
            &dir.0,
            "ec_pem_enc",
            &["-t", "ecdsa", "-b", "256", "-m", "PEM", "-N", PASS],
        );
        assert!(text.contains("BEGIN EC PRIVATE KEY") && text.contains("DEK-Info:"));
        // Ani brak hasła, ani dobre hasło nie kończy się prośbą o hasło.
        for pass in [None, Some(PASS), Some("zle")] {
            let Err(KeyError::Invalid(msg)) = parse_key(&text, pass) else {
                panic!("oczekiwano Invalid dla {pass:?}");
            };
            assert!(msg.contains("ssh-keygen -p"), "{msg}");
        }
        // Ten sam klucz bez hasła działa dalej.
        let (plain, fp) = generate(
            &kg,
            &dir.0,
            "ec_pem",
            &["-t", "ecdsa", "-b", "256", "-m", "PEM", "-N", ""],
        );
        assert_eq!(parse_key(&plain, None).unwrap().info().fingerprint, fp);
    }

    #[test]
    fn leading_bom_and_blank_lines_are_ignored() {
        let Some(kg) = keygen() else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let dir = temp_dir();
        let (text, fp) = generate(&kg, &dir.0, "ed", &["-t", "ed25519", "-N", ""]);
        for prefix in ["\u{feff}", "\n\n  ", "\u{feff}\r\n \r\n"] {
            let info = parse_key(&format!("{prefix}{text}"), None)
                .unwrap_or_else(|e| panic!("{prefix:?}: {e}"))
                .info();
            assert_eq!(info.fingerprint, fp);
        }
    }

    #[test]
    fn import_gives_plain_openssh_with_same_fingerprint() {
        let Some(kg) = keygen() else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let dir = temp_dir();
        for (name, text, fp) in encrypted(&kg, &dir.0) {
            let (openssh, info) = import_key(&text, Some(PASS)).unwrap();
            assert!(
                openssh.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
                "{name}"
            );
            assert!(!openssh.contains('\r'));
            assert_eq!(info.fingerprint, fp, "{name}");
            let again = parse_key(&openssh, None).expect("klucz po imporcie bez hasła");
            assert_eq!(again.info(), info, "{name}");
        }
    }

    #[test]
    fn ppk_encryption_is_recognised_from_the_header() {
        // Zaszyfrowany plik PuTTY bez hasła: prośba o hasło jeszcze przed dekodowaniem.
        assert_eq!(
            parse_key(&ppk_stub("aes256-cbc", "Public-Lines: 0"), None).err(),
            Some(KeyError::NeedsPassphrase)
        );
        // Uszkodzony plik to nie "złe hasło", także gdy hasło podano.
        assert!(matches!(
            parse_key(&ppk_stub("aes256-cbc", "Public-Lines: 0"), Some(PASS)),
            Err(KeyError::Invalid(_))
        ));
        assert!(matches!(
            parse_key(&ppk_stub("none", "Public-Lines: 0"), None),
            Err(KeyError::Invalid(_))
        ));
    }

    #[test]
    fn garbage_and_oversized_are_rejected() {
        assert!(matches!(
            parse_key("to nie jest klucz", None),
            Err(KeyError::Invalid(_))
        ));
        assert!(matches!(
            parse_key(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
                None
            ),
            Err(KeyError::Invalid(_))
        ));
        let big = "A".repeat(MAX_KEY_TEXT + 1);
        assert_eq!(parse_key(&big, None).err(), Some(KeyError::TooLarge));
        assert_eq!(import_key(&big, None).err(), Some(KeyError::TooLarge));
    }

    #[test]
    fn ppk_errors_do_not_quote_file_lines() {
        let broken = ppk_stub("none", "Prywatne-tajne-wiersze-xyz");
        let Err(KeyError::Invalid(msg)) = parse_key(&broken, None) else {
            panic!("oczekiwano Invalid");
        };
        assert!(!msg.contains("xyz"), "{msg}");
    }

    #[test]
    fn unsupported_pem_cipher_is_invalid() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
                    DEK-Info: DES-EDE3-CBC,0011223344556677\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(matches!(
            parse_key(text, Some(PASS)),
            Err(KeyError::Invalid(_))
        ));
    }

    #[test]
    fn read_key_file_limits_size() {
        let dir = temp_dir();
        let p = dir.0.join("duzy");
        std::fs::write(&p, vec![b'A'; MAX_KEY_TEXT + 1]).unwrap();
        assert_eq!(read_key_file(&p).err(), Some(KeyError::TooLarge));
        let p = dir.0.join("rowno");
        std::fs::write(&p, vec![b'A'; MAX_KEY_TEXT]).unwrap();
        assert_eq!(read_key_file(&p).unwrap().len(), MAX_KEY_TEXT);
        let p = dir.0.join("binarny");
        std::fs::write(&p, [0xff, 0xfe, 0x00]).unwrap();
        assert!(matches!(read_key_file(&p), Err(KeyError::Unreadable(_))));
        // Katalog (jak potok FIFO) nie jest zwykłym plikiem.
        assert!(matches!(
            read_key_file(&dir.0),
            Err(KeyError::Unreadable(_))
        ));
        assert!(matches!(
            read_key_file(&dir.0.join("nie-ma")),
            Err(KeyError::Unreadable(_))
        ));
    }

    #[test]
    fn debug_hides_key_material() {
        let Some(kg) = keygen() else {
            eprintln!("brak ssh-keygen, test pominięty");
            return;
        };
        let dir = temp_dir();
        let (text, fingerprint) = generate(&kg, &dir.0, "debug", &["-t", "ed25519", "-N", ""]);
        let key = parse_key(&text, None).unwrap();
        let (openssh, _) = import_key(&text, None).unwrap();
        let body: Vec<&str> = openssh
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert!(!body.is_empty());
        let auth = crate::Auth::Key {
            key: key.clone(),
            origin: crate::KeyOrigin::File("~/.ssh/id_test".into()),
        };
        for shown in [format!("{key:?}"), format!("{auth:?}")] {
            for line in &body {
                assert!(!shown.contains(line), "{shown}");
            }
        }
        assert_eq!(
            format!("{key:?}"),
            format!("SecretKey(ssh-ed25519 {fingerprint})")
        );
        assert_eq!(
            format!("{auth:?}"),
            "Auth::Key(File(\"~/.ssh/id_test\"), ***)"
        );
    }
}
