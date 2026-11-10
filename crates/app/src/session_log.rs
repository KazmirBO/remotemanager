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

/// Otwiera nowy plik `logs/<host>-<czas>.log` w katalogu danych.
pub fn open(data_dir: &Path, host: &str) -> io::Result<File> {
    let dir = data_dir.join("logs");
    fs::create_dir_all(&dir)?;
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(dir.join(format!("{}-{secs}.log", sanitize(host))))
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
        let mut f = open(&dir, "../zły/host").unwrap();
        f.write_all(b"dane").unwrap();
        let entries: Vec<_> = fs::read_dir(dir.join("logs"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].starts_with(dir.join("logs")));
        assert_eq!(fs::read(&entries[0]).unwrap(), b"dane");
        let _ = fs::remove_dir_all(dir);
    }
}
