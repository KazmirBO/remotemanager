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
    /// Wczytuje konfigurację. Brak pliku daje wartości domyślne. Plik, który istnieje, ale nie da się
    /// go użyć (zły JSON, niepoprawny UTF-8, błąd odczytu), jest odkładany jako `config.json.bad`,
    /// żeby pierwszy zapis nie zatarł np. folderu synchronizacji, a drugi element wyniku opisuje
    /// problem do dziennika diagnostycznego.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        // Odczyt bajtów, a nie tekstu: niepoprawny UTF-8 ma trafić do tej samej ścieżki co zły JSON.
        let problem = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(c) => return (c, None),
                Err(e) => format!("uszkodzona konfiguracja ({e})"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Self::default(), None),
            Err(e) => format!("nie można odczytać konfiguracji ({e})"),
        };
        let mut bad = path.as_os_str().to_owned();
        bad.push(".bad");
        let kept = std::fs::rename(path, PathBuf::from(&bad)).is_ok();
        (
            Self::default(),
            Some(format!(
                "{problem}, użyto wartości domyślnych{}",
                if kept {
                    "; poprzedni plik zachowano jako config.json.bad"
                } else {
                    ""
                }
            )),
        )
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        drop(f);
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
        assert_eq!(Config::load(&p), (Config::default(), None));
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
        assert_eq!(Config::load(&p), (c, None));
        std::fs::write(&p, b"{nie json").unwrap();
        let (loaded, warning) = Config::load(&p);
        assert_eq!(loaded, Config::default());
        assert!(warning.unwrap().contains("config.json.bad"));
        assert_eq!(
            std::fs::read(dir.join("config.json.bad")).unwrap(),
            b"{nie json"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn file_that_is_not_utf8_is_kept_aside_too() {
        let dir = std::env::temp_dir().join(format!("mrm-cfg-utf8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        let broken = [b'{', 0xff, 0xfe, b'}'];
        std::fs::write(&p, broken).unwrap();
        let (loaded, warning) = Config::load(&p);
        assert_eq!(loaded, Config::default());
        assert!(warning.unwrap().contains("config.json.bad"));
        assert_eq!(std::fs::read(dir.join("config.json.bad")).unwrap(), broken);
        // Zapis wartości domyślnych nie rusza odłożonego pliku.
        loaded.save(&p).unwrap();
        assert_eq!(std::fs::read(dir.join("config.json.bad")).unwrap(), broken);
        let _ = std::fs::remove_dir_all(dir);
    }
}
