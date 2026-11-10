//! Konfiguracja lokalna dla tej maszyny (poza zaszyfrowanym plikiem, który się synchronizuje).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Folder synchronizacji pliku z hostami.
    #[serde(default)]
    pub sync_folder: Option<PathBuf>,
    /// Skrót pliku z ostatniej udanej synchronizacji.
    #[serde(default)]
    pub sync_base: Option<String>,
    /// Udostępnia schowek sesjom RDP (w obie strony). Domyślnie włączone.
    #[serde(default = "default_true")]
    pub rdp_clipboard: bool,
    /// Zapisuje wyjście sesji SSH do plików w katalogu danych (`logs/`).
    #[serde(default)]
    pub log_sessions: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sync_folder: None,
            sync_base: None,
            rdp_clipboard: true,
            log_sessions: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_defaults_on_garbage() {
        let dir = std::env::temp_dir().join(format!("mrm-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        assert_eq!(Config::load(&p), Config::default());
        let c = Config {
            sync_folder: Some("/x".into()),
            sync_base: Some("abc".into()),
            rdp_clipboard: false,
            log_sessions: true,
        };
        assert!(
            Config::default().rdp_clipboard,
            "schowek jest domyślnie włączony"
        );
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p), c);
        std::fs::write(&p, b"{nie json").unwrap();
        assert_eq!(Config::load(&p), Config::default());
        let _ = std::fs::remove_dir_all(dir);
    }
}
