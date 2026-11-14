//! Dziennik sesji: wyjście terminala zapisywane do pliku (tylko dane z serwera, nie to, co wpisujesz).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Zamienia nazwę hosta na bezpieczną nazwę pliku.
pub fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('.').to_owned();
    if s.is_empty() {
        "sesja".into()
    } else {
        s.chars().take(64).collect()
    }
}

/// Otwiera nowy plik `logs/<host>-<czas>-<znacznik>.log` w katalogu danych. Znacznik (np. początek
/// identyfikatora sesji) rozróżnia dwie sesje z tym samym hostem otwarte w tej samej sekundzie.
/// Na Unix katalog dostaje tryb 0700, a plik 0600, bo wyjście terminala może zawierać sekrety.
pub fn open(data_dir: &Path, host: &str, tag: &str) -> io::Result<File> {
    let dir = data_dir.join("logs");
    fs::create_dir_all(&dir)?;
    // Katalog mógł już istnieć z szerszymi uprawnieniami, więc tryb ustawiamy zawsze.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(dir.join(format!("{}-{secs}-{}.log", sanitize(host), sanitize(tag))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sanitize_blocks_path_tricks() {
        assert_eq!(sanitize("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize("db-01.firma"), "db-01.firma");
        assert_eq!(sanitize("..."), "sesja");
        assert_eq!(sanitize(""), "sesja");
        assert_eq!(sanitize("żółć host"), "żółć_host");
        assert!(sanitize(&"a".repeat(500)).len() <= 64);
    }

    #[test]
    fn open_creates_file_inside_logs_dir() {
        let dir = std::env::temp_dir().join(format!("mrm-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut f = open(&dir, "../zły/host", "a1").unwrap();
        f.write_all(b"dane").unwrap();
        // Druga sesja z tym samym hostem w tej samej sekundzie dostaje osobny plik.
        open(&dir, "../zły/host", "b2").unwrap();
        let entries: Vec<_> = fs::read_dir(dir.join("logs"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.starts_with(dir.join("logs"))));
        let with_data = entries
            .iter()
            .find(|e| e.to_string_lossy().ends_with("-a1.log"))
            .unwrap();
        assert_eq!(fs::read(with_data).unwrap(), b"dane");
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mrm-log-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let f = open(&dir, "host", "p1").unwrap();
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(dir.join("logs")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Katalog utworzony wcześniej z szerokimi uprawnieniami też ma zostać zawężony.
        fs::set_permissions(dir.join("logs"), fs::Permissions::from_mode(0o755)).unwrap();
        open(&dir, "host", "p2").unwrap();
        assert_eq!(
            fs::metadata(dir.join("logs")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(dir);
    }
}
