//! Typy wymieniane z frontendem. Hasła nigdy nie opuszczają backendu: widok ma tylko `has_password`.

use model::{CardRedirect, Fields, Folder, Host, Id, LinkProfile, Protocol, Settings};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
        }
    }

    /// Nakłada wejście na istniejące pola, zachowując hasło, jeśli nie zmieniono.
    pub fn apply(self, existing: &Fields) -> Fields {
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
        let keep = FieldsIo::default().apply(&existing);
        assert_eq!(keep.password.as_deref(), Some("stare"));
        let empty = FieldsIo {
            password: Some(String::new()),
            ..Default::default()
        }
        .apply(&existing);
        assert_eq!(empty.password.as_deref(), Some("stare"));
        let set = FieldsIo {
            password: Some("nowe".into()),
            ..Default::default()
        }
        .apply(&existing);
        assert_eq!(set.password.as_deref(), Some("nowe"));
        let clear = FieldsIo {
            clear_password: true,
            password: Some("x".into()),
            ..Default::default()
        }
        .apply(&existing);
        assert_eq!(clear.password, None);
    }

    #[test]
    fn rdp_smartcard_goes_both_ways() {
        let io: FieldsIo = serde_json::from_str(r#"{"rdp_smartcard":"neutral"}"#).unwrap();
        assert_eq!(io.rdp_smartcard, Some(CardRedirect::Neutral));
        let applied = io.apply(&Fields::default());
        assert_eq!(applied.rdp_smartcard, Some(CardRedirect::Neutral));
        let json = serde_json::to_string(&FieldsIo::view(&applied)).unwrap();
        assert!(json.contains(r#""rdp_smartcard":"neutral""#), "{json}");
        // Frontend sprzed tej funkcji nie przysyła pola: to dziedziczenie, czyli wyłączone.
        let none: FieldsIo = serde_json::from_str("{}").unwrap();
        assert_eq!(none.apply(&applied).rdp_smartcard, None);
    }

    #[test]
    fn rdp_profile_goes_both_ways() {
        let io: FieldsIo = serde_json::from_str(r#"{"rdp_profile":"slow"}"#).unwrap();
        assert_eq!(io.rdp_profile, Some(LinkProfile::Slow));
        let applied = io.apply(&Fields::default());
        assert_eq!(applied.rdp_profile, Some(LinkProfile::Slow));
        let json = serde_json::to_string(&FieldsIo::view(&applied)).unwrap();
        assert!(json.contains(r#""rdp_profile":"slow""#), "{json}");
        // Brak pola z frontendu to dziedziczenie, a w widoku `null`.
        let none: FieldsIo = serde_json::from_str(r#"{"rdp_profile":null}"#).unwrap();
        assert_eq!(none.apply(&applied).rdp_profile, None);
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
}
