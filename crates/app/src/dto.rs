//! Typy wymieniane z frontendem. Hasła nigdy nie opuszczają backendu: widok ma tylko `has_password`.

use model::{CardRedirect, Fields, Folder, Host, Id, LinkProfile, Protocol, Settings, StoredKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct FieldsIo {
    pub port: Option<u16>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub jump_host: Option<Id>,
    pub terminal_scheme: Option<String>,
    pub rdp_multimon: Option<bool>,
    pub rdp_kerberos: Option<bool>,
    pub rdp_kdc: Option<String>,
    pub rdp_profile: Option<LinkProfile>,
    /// Przekierowanie kluczy bezpieczeństwa (WebAuthn) do sesji RDP; `None` dziedziczy.
    #[serde(default)]
    pub rdp_webauthn: Option<bool>,
    /// Przekierowanie czytników kart inteligentnych do sesji RDP; `None` dziedziczy.
    #[serde(default)]
    pub rdp_smartcard: Option<CardRedirect>,
    /// Tylko wyjście.
    #[serde(default)]
    pub has_password: bool,
    /// Tylko wejście: niepusty = ustaw nowe hasło.
    #[serde(default)]
    pub password: Option<String>,
    /// Tylko wejście: usuń zapisane hasło.
    #[serde(default)]
    pub clear_password: bool,
    /// Ścieżka do pliku klucza; `None` dziedziczy. Wejście i wyjście.
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    /// Tylko wyjście: klucz zapisany w pliku hostów na tym poziomie.
    #[serde(default)]
    pub has_ssh_key: bool,
    /// Tylko wyjście.
    #[serde(default)]
    pub ssh_key_algorithm: Option<String>,
    /// Tylko wyjście.
    #[serde(default)]
    pub ssh_key_fingerprint: Option<String>,
    /// Tylko wejście: niepusty = zaimportuj nowy klucz (tekst).
    #[serde(default)]
    pub ssh_key: Option<String>,
    /// Tylko wejście: hasło importowanego klucza (używane raz, nie zapisywane).
    #[serde(default)]
    pub ssh_key_passphrase: Option<String>,
    /// Tylko wejście: usuń zapisany klucz.
    #[serde(default)]
    pub clear_ssh_key: bool,
}

impl std::fmt::Debug for FieldsIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mask = |o: &Option<String>| o.as_ref().map(|_| "***");
        f.debug_struct("FieldsIo")
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("jump_host", &self.jump_host)
            .field("terminal_scheme", &self.terminal_scheme)
            .field("rdp_multimon", &self.rdp_multimon)
            .field("rdp_kerberos", &self.rdp_kerberos)
            .field("rdp_kdc", &self.rdp_kdc)
            .field("rdp_profile", &self.rdp_profile)
            .field("rdp_webauthn", &self.rdp_webauthn)
            .field("rdp_smartcard", &self.rdp_smartcard)
            .field("has_password", &self.has_password)
            .field("password", &mask(&self.password))
            .field("clear_password", &self.clear_password)
            .field("ssh_key_path", &self.ssh_key_path)
            .field("has_ssh_key", &self.has_ssh_key)
            .field("ssh_key_algorithm", &self.ssh_key_algorithm)
            .field("ssh_key_fingerprint", &self.ssh_key_fingerprint)
            .field("ssh_key", &mask(&self.ssh_key))
            .field("ssh_key_passphrase", &mask(&self.ssh_key_passphrase))
            .field("clear_ssh_key", &self.clear_ssh_key)
            .finish()
    }
}

const PATH_ERROR: &str = "Ścieżka klucza musi być bezwzględna albo zaczynać się od ~/.";

/// Sprawdza ścieżkę klucza: `~/` albo ścieżka bezwzględna, bez znaków sterujących. Plik hostów bywa
/// zsynchronizowany między Linuksem a Windows, więc na każdym systemie przechodzą obie konwencje
/// (`/home/ja/klucz`, `C:\Users\ja\klucz`, `\\serwer\udział`). Inaczej hosta ze ścieżką wpisaną na jednym
/// systemie nie dałoby się zapisać na drugim, nawet po zmianie innego pola. Ścieżka, która na danej
/// maszynie nie istnieje, jest przy łączeniu pomijana.
pub fn valid_key_path(p: &str) -> bool {
    if p.len() > 4096 || p.chars().any(char::is_control) {
        return false;
    }
    let b = p.as_bytes();
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    p.starts_with("~/")
        || p.starts_with("~\\")
        || p.starts_with('/')
        || p.starts_with("\\\\")
        || drive
}

impl FieldsIo {
    pub fn view(f: &Fields) -> Self {
        Self {
            port: f.port,
            username: f.username.clone(),
            domain: f.domain.clone(),
            jump_host: f.jump_host,
            terminal_scheme: f.terminal_scheme.clone(),
            rdp_multimon: f.rdp_multimon,
            rdp_kerberos: f.rdp_kerberos,
            rdp_kdc: f.rdp_kdc.clone(),
            rdp_profile: f.rdp_profile,
            rdp_webauthn: f.rdp_webauthn,
            rdp_smartcard: f.rdp_smartcard,
            has_password: f.password.is_some(),
            password: None,
            clear_password: false,
            ssh_key_path: f.ssh_key_path.clone(),
            has_ssh_key: f.ssh_key.is_some(),
            ssh_key_algorithm: f.ssh_key.as_ref().map(|k| k.algorithm.clone()),
            ssh_key_fingerprint: f.ssh_key.as_ref().map(|k| k.fingerprint.clone()),
            ssh_key: None,
            ssh_key_passphrase: None,
            clear_ssh_key: false,
        }
    }

    /// Poza blokadą dokumentu (KDF klucza bywa wolny): sprawdza ścieżkę i importuje klucz z wejścia.
    /// Zabiera z `self` pola `ssh_key` i `ssh_key_passphrase` (bufory w `Zeroizing`).
    pub fn prepare(&mut self) -> Result<Option<StoredKey>, String> {
        let text = self.ssh_key.take().map(Zeroizing::new);
        let pass = self.ssh_key_passphrase.take().map(Zeroizing::new);
        let path = self
            .ssh_key_path
            .take()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty());
        if let Some(p) = &path
            && !valid_key_path(p)
        {
            return Err(PATH_ERROR.into());
        }
        self.ssh_key_path = path;
        // Usunięcie zapisanego klucza wygrywa z wklejonym tekstem: nie importujemy go (błąd
        // importu nie może blokować usuwania), a bufory znikają razem z `text` i `pass`.
        if self.clear_ssh_key {
            return Ok(None);
        }
        let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
            return Ok(None);
        };
        let pass = pass
            .as_deref()
            .map(String::as_str)
            .filter(|p| !p.is_empty());
        match ssh::import_key(&text, pass) {
            Ok((openssh, info)) => Ok(Some(StoredKey {
                openssh: openssh.to_string(),
                algorithm: info.algorithm,
                fingerprint: info.fingerprint,
            })),
            Err(ssh::KeyError::NeedsPassphrase) => Err(
                "KEY_NEEDS_PASSPHRASE:Klucz jest zaszyfrowany. Podaj hasło klucza, aby go zaimportować."
                    .into(),
            ),
            Err(ssh::KeyError::WrongPassphrase) => {
                Err("KEY_BAD_PASSPHRASE:Nieprawidłowe hasło klucza.".into())
            }
            Err(ssh::KeyError::TooLarge) => {
                Err("KEY_INVALID:Klucz jest za duży (limit 64 KiB).".into())
            }
            Err(ssh::KeyError::Invalid(d) | ssh::KeyError::Unreadable(d)) => {
                Err(format!("KEY_INVALID:Nie można odczytać klucza: {d}"))
            }
        }
    }

    /// Nakłada wejście na istniejące pola, zachowując hasło i klucz, jeśli nie zmieniono.
    /// `imported` pochodzi z `prepare`.
    pub fn apply(self, existing: &Fields, imported: Option<StoredKey>) -> Fields {
        let ssh_key = if self.clear_ssh_key {
            None
        } else if let Some(k) = imported {
            Some(k)
        } else {
            existing.ssh_key.clone()
        };
        let password = if self.clear_password {
            None
        } else {
            match self.password {
                Some(p) if !p.is_empty() => Some(p),
                _ => existing.password.clone(),
            }
        };
        Fields {
            port: self.port,
            username: self.username.filter(|s| !s.is_empty()),
            domain: self.domain.filter(|s| !s.is_empty()),
            password,
            ssh_key,
            ssh_key_path: self.ssh_key_path,
            jump_host: self.jump_host,
            terminal_scheme: self.terminal_scheme.filter(|s| !s.is_empty()),
            rdp_multimon: self.rdp_multimon,
            rdp_kerberos: self.rdp_kerberos,
            rdp_kdc: self.rdp_kdc.filter(|s| !s.is_empty()),
            rdp_profile: self.rdp_profile,
            rdp_webauthn: self.rdp_webauthn,
            rdp_smartcard: self.rdp_smartcard,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FolderView {
    pub id: Id,
    pub name: String,
    pub parent: Option<Id>,
    pub fields: FieldsIo,
}

impl From<&Folder> for FolderView {
    fn from(f: &Folder) -> Self {
        Self {
            id: f.id,
            name: f.name.clone(),
            parent: f.parent,
            fields: FieldsIo::view(&f.fields),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HostView {
    pub id: Id,
    pub name: String,
    pub address: String,
    pub protocol: Protocol,
    pub folder: Option<Id>,
    pub favorite: bool,
    pub notes: String,
    pub fields: FieldsIo,
}

impl From<&Host> for HostView {
    fn from(h: &Host) -> Self {
        Self {
            id: h.id,
            name: h.name.clone(),
            address: h.address.clone(),
            protocol: h.protocol,
            folder: h.folder,
            favorite: h.favorite,
            notes: h.notes.clone(),
            fields: FieldsIo::view(&h.fields),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DocView {
    pub folders: Vec<FolderView>,
    pub hosts: Vec<HostView>,
    pub settings: Settings,
    pub trusted_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct FolderInput {
    pub id: Option<Id>,
    pub name: String,
    pub parent: Option<Id>,
    pub fields: FieldsIo,
}

#[derive(Debug, Deserialize)]
pub struct HostInput {
    pub id: Option<Id>,
    pub name: String,
    pub address: String,
    pub protocol: Protocol,
    pub folder: Option<Id>,
    pub notes: String,
    pub fields: FieldsIo,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_kept_set_or_cleared() {
        let existing = Fields {
            password: Some("stare".into()),
            ..Default::default()
        };
        let keep = FieldsIo::default().apply(&existing, None);
        assert_eq!(keep.password.as_deref(), Some("stare"));
        let empty = FieldsIo {
            password: Some(String::new()),
            ..Default::default()
        }
        .apply(&existing, None);
        assert_eq!(empty.password.as_deref(), Some("stare"));
        let set = FieldsIo {
            password: Some("nowe".into()),
            ..Default::default()
        }
        .apply(&existing, None);
        assert_eq!(set.password.as_deref(), Some("nowe"));
        let clear = FieldsIo {
            clear_password: true,
            password: Some("x".into()),
            ..Default::default()
        }
        .apply(&existing, None);
        assert_eq!(clear.password, None);
    }

    #[test]
    fn rdp_smartcard_goes_both_ways() {
        let io: FieldsIo = serde_json::from_str(r#"{"rdp_smartcard":"neutral"}"#).unwrap();
        assert_eq!(io.rdp_smartcard, Some(CardRedirect::Neutral));
        let applied = io.apply(&Fields::default(), None);
        assert_eq!(applied.rdp_smartcard, Some(CardRedirect::Neutral));
        let json = serde_json::to_string(&FieldsIo::view(&applied)).unwrap();
        assert!(json.contains(r#""rdp_smartcard":"neutral""#), "{json}");
        // Frontend sprzed tej funkcji nie przysyła pola: to dziedziczenie, czyli wyłączone.
        let none: FieldsIo = serde_json::from_str("{}").unwrap();
        assert_eq!(none.apply(&applied, None).rdp_smartcard, None);
    }

    #[test]
    fn rdp_profile_goes_both_ways() {
        let io: FieldsIo = serde_json::from_str(r#"{"rdp_profile":"slow"}"#).unwrap();
        assert_eq!(io.rdp_profile, Some(LinkProfile::Slow));
        let applied = io.apply(&Fields::default(), None);
        assert_eq!(applied.rdp_profile, Some(LinkProfile::Slow));
        let json = serde_json::to_string(&FieldsIo::view(&applied)).unwrap();
        assert!(json.contains(r#""rdp_profile":"slow""#), "{json}");
        // Brak pola z frontendu to dziedziczenie, a w widoku `null`.
        let none: FieldsIo = serde_json::from_str(r#"{"rdp_profile":null}"#).unwrap();
        assert_eq!(none.apply(&applied, None).rdp_profile, None);
        let json = serde_json::to_string(&FieldsIo::view(&Fields::default())).unwrap();
        assert!(json.contains(r#""rdp_profile":null"#));
    }

    #[test]
    fn view_never_contains_password() {
        let f = Fields {
            password: Some("tajne".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&FieldsIo::view(&f)).unwrap();
        assert!(!json.contains("tajne"));
        assert!(json.contains("\"has_password\":true"));
    }

    fn stored() -> StoredKey {
        StoredKey {
            openssh: "-----BEGIN OPENSSH PRIVATE KEY-----\nsekretny\n".into(),
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
        }
    }

    #[test]
    fn ssh_key_is_imported_kept_or_cleared() {
        let old = StoredKey {
            fingerprint: "SHA256:stary".into(),
            ..stored()
        };
        let existing = Fields {
            ssh_key: Some(old.clone()),
            ..Default::default()
        };
        let keep = FieldsIo::default().apply(&existing, None);
        assert_eq!(keep.ssh_key, Some(old.clone()));
        let new = FieldsIo::default().apply(&existing, Some(stored()));
        assert_eq!(new.ssh_key, Some(stored()));
        let clear = FieldsIo {
            clear_ssh_key: true,
            ..Default::default()
        }
        .apply(&existing, None);
        assert_eq!(clear.ssh_key, None);
        let clear_wins = FieldsIo {
            clear_ssh_key: true,
            ..Default::default()
        }
        .apply(&existing, Some(stored()));
        assert_eq!(clear_wins.ssh_key, None);
    }

    #[test]
    fn view_never_contains_ssh_key() {
        let f = Fields {
            ssh_key: Some(stored()),
            ..Default::default()
        };
        let json = serde_json::to_string(&FieldsIo::view(&f)).unwrap();
        assert!(!json.contains("BEGIN OPENSSH"), "{json}");
        assert!(!json.contains("sekretny"), "{json}");
        assert!(json.contains("\"has_ssh_key\":true"));
        assert!(json.contains("SHA256:abc"));
        assert!(json.contains("ssh-ed25519"));
    }

    #[test]
    fn key_path_accepts_both_systems_conventions() {
        for ok in [
            "~/.ssh/id_ed25519",
            "~\\.ssh\\id_ed25519",
            "/home/ja/.ssh/id",
            "C:\\Users\\ja\\.ssh\\id",
            "c:/Users/ja/.ssh/id",
            "\\\\serwer\\udzial\\id",
        ] {
            assert!(valid_key_path(ok), "{ok}");
        }
        for bad in ["id_ed25519", ".ssh/id", "~id", "C:id", "", "/home/ja/\nid"] {
            assert!(!valid_key_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn ssh_key_path_goes_both_ways() {
        let mut io: FieldsIo =
            serde_json::from_str(r#"{"ssh_key_path":"  ~/.ssh/id_ed25519 "}"#).unwrap();
        assert_eq!(io.prepare().unwrap(), None);
        let applied = io.apply(&Fields::default(), None);
        assert_eq!(applied.ssh_key_path.as_deref(), Some("~/.ssh/id_ed25519"));
        let json = serde_json::to_string(&FieldsIo::view(&applied)).unwrap();
        assert!(
            json.contains(r#""ssh_key_path":"~/.ssh/id_ed25519""#),
            "{json}"
        );
        let mut none: FieldsIo = serde_json::from_str(r#"{"ssh_key_path":null}"#).unwrap();
        none.prepare().unwrap();
        assert_eq!(none.apply(&applied, None).ssh_key_path, None);
        let mut blank: FieldsIo = serde_json::from_str(r#"{"ssh_key_path":"  "}"#).unwrap();
        blank.prepare().unwrap();
        assert_eq!(blank.ssh_key_path, None);
    }

    #[test]
    fn prepare_skips_import_when_clearing() {
        // Zły tekst nie blokuje usuwania zapisanego klucza, a pola wejściowe są zabrane.
        let mut io = FieldsIo {
            ssh_key: Some("to nie jest klucz".into()),
            ssh_key_passphrase: Some("x".into()),
            clear_ssh_key: true,
            ..Default::default()
        };
        assert_eq!(io.prepare(), Ok(None));
        assert!(io.ssh_key.is_none() && io.ssh_key_passphrase.is_none());
    }

    #[test]
    fn prepare_rejects_relative_path() {
        for p in ["klucz", ".ssh/id", "~x/id", "/a/\u{7}b"] {
            let mut io = FieldsIo {
                ssh_key_path: Some(p.into()),
                ..Default::default()
            };
            let e = io.prepare().unwrap_err();
            assert!(e.starts_with("Ścieżka klucza"), "{p}: {e}");
        }
        let mut long = FieldsIo {
            ssh_key_path: Some(format!("/{}", "a".repeat(4096))),
            ..Default::default()
        };
        assert!(long.prepare().is_err());
    }

    fn keygen(dir: &std::path::Path, name: &str, pass: &str) -> Option<String> {
        let path = dir.join(name);
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", pass, "-f"])
            .arg(&path)
            .status()
            .ok()?
            .success();
        ok.then(|| std::fs::read_to_string(path).unwrap())
    }

    #[test]
    fn prepare_reports_key_errors() {
        let dir = std::env::temp_dir().join(format!("mrm-dto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (Some(plain), Some(enc)) = (
            keygen(&dir, "plain", ""),
            keygen(&dir, "enc", "haslo-klucza"),
        ) else {
            return;
        };
        let run = |text: &str, pass: Option<&str>| {
            FieldsIo {
                ssh_key: Some(text.into()),
                ssh_key_passphrase: pass.map(Into::into),
                ..Default::default()
            }
            .prepare()
        };
        let k = run(&plain, None).unwrap().unwrap();
        assert!(k.openssh.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(k.fingerprint.starts_with("SHA256:"));
        assert!(
            run(&enc, None)
                .unwrap_err()
                .starts_with("KEY_NEEDS_PASSPHRASE:")
        );
        assert!(
            run(&enc, Some("zle"))
                .unwrap_err()
                .starts_with("KEY_BAD_PASSPHRASE:")
        );
        assert!(run(&enc, Some("haslo-klucza")).unwrap().is_some());
        assert!(run("smieci", None).unwrap_err().starts_with("KEY_INVALID:"));
        assert!(run("   ", None).unwrap().is_none());
        // Zły klucz niczego nie wnosi: `apply` nie jest wołane, a istniejący klucz zostaje.
        let big = "a".repeat(ssh::MAX_KEY_TEXT + 1);
        assert!(run(&big, None).unwrap_err().starts_with("KEY_INVALID:"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fields_io_debug_hides_secrets() {
        let io = FieldsIo {
            password: Some("tajne-haslo".into()),
            ssh_key: Some("tajny-klucz".into()),
            ssh_key_passphrase: Some("tajna-fraza".into()),
            ..Default::default()
        };
        let d = format!("{io:?}");
        assert!(
            !d.contains("tajne-haslo") && !d.contains("tajny-klucz") && !d.contains("tajna-fraza")
        );
        assert!(d.contains("***"));
    }
}
