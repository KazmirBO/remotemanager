//! Eksport i import hostów: zaszyfrowany plik `.mrmx` z wybranymi kategoriami danych.
//!
//! Hasła i klucze nie przechodzą przez interfejs: przy imporcie frontend przekazuje zaszyfrowane
//! bajty pliku i hasło pliku, a z powrotem dostaje tylko liczby i listę kategorii. Dane z pliku są
//! niezaufane, więc przed scaleniem przechodzą te same kontrole co formularz hosta, a dane klucza
//! SSH (algorytm, odcisk) są wyliczane od nowa zamiast brane z pliku.

use std::io::Write;
use std::path::{Path, PathBuf};

use model::transfer::{self, Existing, Package, Parts, Report, Summary};
use model::{Fields, Id, StoredKey};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use vault::KdfParams;
use zeroize::Zeroizing;

use crate::dto::{COMMAND_ERROR, FONT_ERROR, PATH_ERROR, TERM_ERROR, valid_key_path};
use crate::state::AppState;

/// Największy przyjmowany plik importu. Frontend przekazuje bajty jako tablicę JSON, więc limit
/// chroni też przed gigantycznym komunikatem.
pub const MAX_IMPORT_FILE: usize = 4 * 1024 * 1024;
const EXTENSION: &str = "mrmx";
const MIN_PASSWORD: usize = 8;

fn blocking_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Dzień kalendarzowy (UTC) z liczby sekund od początku epoki, bez dodatkowych bibliotek.
fn civil_date(secs: u64) -> (i64, u32, u32) {
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn default_name() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_date(secs);
    format!("hosty-{y:04}-{m:02}-{d:02}.{EXTENSION}")
}

/// Podpowiedź ścieżki pliku eksportu: katalog pobranych plików, a gdy system go nie podaje,
/// katalog domowy.
#[tauri::command]
pub fn export_default_path(app: tauri::AppHandle) -> String {
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .unwrap_or_default();
    dir.join(default_name()).to_string_lossy().into_owned()
}

/// Ścieżka docelowa z pola formularza: bezwzględna, w istniejącym katalogu, z rozszerzeniem `.mrmx`
/// (dopisywanym, gdy go brak).
fn export_path(raw: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("Podaj ścieżkę pliku eksportu.".into());
    }
    if raw.len() > 4096 || raw.chars().any(char::is_control) {
        return Err("Ścieżka pliku eksportu zawiera niedozwolone znaki.".into());
    }
    let mut path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("Ścieżka pliku eksportu musi być bezwzględna.".into());
    }
    if path.file_name().is_none() || raw.ends_with(['/', '\\']) {
        return Err("Podaj nazwę pliku eksportu, nie sam katalog.".into());
    }
    let has_ext = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(EXTENSION));
    if !has_ext {
        let mut name = path.file_name().unwrap_or_default().to_owned();
        name.push(format!(".{EXTENSION}"));
        path.set_file_name(name);
    }
    match path.parent() {
        Some(dir) if dir.is_dir() => Ok(path),
        _ => Err("Katalog pliku eksportu nie istnieje.".into()),
    }
}

/// Zapisuje nowy plik: nie nadpisuje istniejącego i nie podąża za dowiązaniem (`create_new`),
/// na Unix z uprawnieniami tylko dla właściciela. Po błędzie zapisu niepełny plik jest usuwany.
fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => {
            "Plik o tej nazwie już istnieje. Podaj inną nazwę.".to_string()
        }
        _ => format!("Nie można utworzyć pliku eksportu: {e}"),
    })?;
    let res = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    res.map_err(|e| {
        let _ = std::fs::remove_file(path);
        format!("Nie można zapisać pliku eksportu: {e}")
    })
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExportDone {
    /// Ścieżka zapisanego pliku (z dopisanym rozszerzeniem).
    pub path: String,
    pub folders: usize,
    pub hosts: usize,
    pub trusted_keys: usize,
}

async fn export_to(
    state: &AppState,
    path: &str,
    password: Zeroizing<String>,
    parts: Parts,
    folder: Option<Id>,
    kdf: KdfParams,
) -> Result<ExportDone, String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err("Hasło pliku eksportu musi mieć co najmniej 8 znaków.".into());
    }
    let path = export_path(path)?;
    let pkg = state
        .read(|doc| {
            transfer::export(doc, folder, parts)
                .map_err(|e| format!("Nie można wyeksportować: {e}."))
        })
        .await?;
    if pkg.folders.is_empty() && pkg.hosts.is_empty() {
        return Err("Nie ma czego eksportować: lista hostów jest pusta.".into());
    }
    let done = ExportDone {
        path: path.to_string_lossy().into_owned(),
        folders: pkg.folders.len(),
        hosts: pkg.hosts.len(),
        trusted_keys: pkg.trusted_keys.len(),
    };
    // KDF jest celowo wolny, więc szyfrowanie i zapis idą poza wątkami asynchronicznymi.
    tokio::task::spawn_blocking(move || {
        let data = vault::seal_export(&password, kdf, &pkg).map_err(|e| e.to_string())?;
        write_new(&path, &data)
    })
    .await
    .map_err(blocking_err)??;
    state.log(format!(
        "eksport: zapisano {} hostów i {} katalogów",
        done.hosts, done.folders
    ));
    Ok(done)
}

/// Eksportuje całą listę (`folder == None`) albo jeden katalog z zawartością do nowego pliku.
#[tauri::command]
pub async fn export_hosts(
    state: State<'_, AppState>,
    path: String,
    password: String,
    parts: Parts,
    folder: Option<Id>,
) -> Result<ExportDone, String> {
    export_to(
        &state,
        &path,
        Zeroizing::new(password),
        parts,
        folder,
        KdfParams::DEFAULT,
    )
    .await
}

/// Pusty tekst to brak wartości, tak jak w formularzu.
fn non_empty(v: &mut Option<String>) {
    if v.as_ref().is_some_and(|s| s.trim().is_empty()) {
        *v = None;
    }
}

/// Doprowadza pola z pliku do postaci, jaką zapisałby formularz, i odrzuca wartości, których
/// formularz by nie przyjął. Dane klucza SSH (algorytm, odcisk) wylicza z samego klucza: plik
/// mógłby podać cudzy odcisk przy innym kluczu.
fn clean_fields(f: &mut Fields) -> Result<(), String> {
    non_empty(&mut f.username);
    non_empty(&mut f.domain);
    non_empty(&mut f.terminal_scheme);
    non_empty(&mut f.rdp_kdc);
    non_empty(&mut f.ssh_key_path);
    non_empty(&mut f.ssh_term);
    non_empty(&mut f.ssh_login_command);
    if f.password.as_ref().is_some_and(String::is_empty) {
        f.password = None;
    }
    if let Some(p) = &mut f.ssh_key_path {
        *p = p.trim().to_owned();
        if !valid_key_path(p) {
            return Err(PATH_ERROR.into());
        }
    }
    if let Some(t) = &mut f.ssh_term {
        *t = t.trim().to_owned();
        if !ssh::valid_term(t) {
            return Err(TERM_ERROR.into());
        }
    }
    if f.terminal_font_size.is_some_and(|n| !(9..=32).contains(&n)) {
        return Err(FONT_ERROR.into());
    }
    if let Some(c) = &mut f.ssh_login_command {
        *c = c.trim().to_owned();
        if !ssh::valid_login_command(c) {
            return Err(COMMAND_ERROR.into());
        }
    }
    if f.port == Some(0) {
        return Err("Port musi być liczbą od 1 do 65535.".into());
    }
    if let Some(k) = &f.ssh_key {
        let (openssh, info) = ssh::import_key(&k.openssh, None)
            .map_err(|_| "nie można odczytać zapisanego klucza SSH".to_string())?;
        f.ssh_key = Some(StoredKey {
            openssh: openssh.to_string(),
            algorithm: info.algorithm,
            fingerprint: info.fingerprint,
        });
    }
    Ok(())
}

fn clean(pkg: &mut Package) -> Result<(), String> {
    for f in &mut pkg.folders {
        clean_fields(&mut f.fields)
            .map_err(|e| format!("Plik zawiera nieprawidłowe dane katalogu {}: {e}", f.name))?;
    }
    for h in &mut pkg.hosts {
        clean_fields(&mut h.fields)
            .map_err(|e| format!("Plik zawiera nieprawidłowe dane hosta {}: {e}", h.name))?;
    }
    Ok(())
}

fn import_err(e: transfer::Error) -> String {
    format!("Nie można zaimportować: {e}.")
}

/// Rodzaj pliku importu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    /// Zaszyfrowany plik eksportu.
    #[default]
    Mrmx,
    /// Jawna lista hostów (nazwa, adres, protokół, katalog), bez haseł i opcji.
    Csv,
}

/// Lista hostów z pliku CSV jako pakiet importu. Hasło nie jest używane.
fn csv_package(data: &[u8]) -> Result<Package, String> {
    let text = std::str::from_utf8(data).map_err(|_| {
        "Plik CSV nie jest zapisany w kodowaniu UTF-8. Zapisz go jako UTF-8 i spróbuj ponownie."
            .to_string()
    })?;
    model::csv::package_from_csv(text).map_err(|e| format!("Nie można odczytać pliku CSV: {e}."))
}

/// Odszyfrowuje (plik eksportu) albo czyta (CSV) i sprawdza plik importu. Komunikaty nie zawierają
/// treści pliku (błąd odczytu struktury mógłby przytoczyć wartość pola).
fn open_package(data: &[u8], password: &str, format: FileFormat) -> Result<Package, String> {
    if data.len() > MAX_IMPORT_FILE {
        return Err("Plik jest za duży na plik importu hostów (limit 4 MiB).".into());
    }
    if format == FileFormat::Csv {
        let mut pkg = csv_package(data)?;
        transfer::check(&pkg).map_err(import_err)?;
        clean(&mut pkg)?;
        return Ok(pkg);
    }
    let mut pkg: Package = vault::open_export(data, password).map_err(|e| match e {
        vault::Error::NotExport if vault::looks_like_vault(data) => {
            "To jest plik z hostami, a nie plik eksportu. Plik z hostami przenosi się przez synchronizację albo kopię zapasową.".to_string()
        }
        vault::Error::NotExport => "To nie jest plik eksportu hostów.".to_string(),
        vault::Error::Decrypt => {
            "Nieprawidłowe hasło pliku eksportu albo plik jest uszkodzony.".to_string()
        }
        vault::Error::Serde(_) => {
            "Plik eksportu ma nieznaną strukturę (być może pochodzi z nowszej wersji programu)."
                .to_string()
        }
        vault::Error::Truncated => "Plik eksportu jest uszkodzony albo obcięty.".to_string(),
        other => format!("Nie można odczytać pliku eksportu: {other}."),
    })?;
    transfer::check(&pkg).map_err(import_err)?;
    clean(&mut pkg)?;
    Ok(pkg)
}

async fn open_blocking(
    data: Vec<u8>,
    password: Zeroizing<String>,
    format: FileFormat,
) -> Result<Package, String> {
    tokio::task::spawn_blocking(move || open_package(&data, &password, format))
        .await
        .map_err(blocking_err)?
}

async fn preview_as(
    state: &AppState,
    data: Vec<u8>,
    password: Zeroizing<String>,
    format: FileFormat,
) -> Result<Summary, String> {
    let pkg = open_blocking(data, password, format).await?;
    state.read(|doc| Ok(transfer::summarize(doc, &pkg))).await
}

/// Podgląd importu: kategorie obecne w pliku i liczba nowych oraz już istniejących elementów.
#[tauri::command]
pub async fn import_preview(
    state: State<'_, AppState>,
    data: Vec<u8>,
    password: String,
    format: Option<FileFormat>,
) -> Result<Summary, String> {
    preview_as(
        &state,
        data,
        Zeroizing::new(password),
        format.unwrap_or_default(),
    )
    .await
}

async fn import_as(
    state: &AppState,
    data: Vec<u8>,
    password: Zeroizing<String>,
    format: FileFormat,
    parts: Parts,
    existing: Existing,
) -> Result<Report, String> {
    let pkg = open_blocking(data, password, format).await?;
    let report = state
        .mutate(|doc| {
            let before = doc.tree.clone();
            let report = transfer::import(doc, &pkg, parts, existing).map_err(import_err)?;
            // Scalanie nie może zostawić cyklu bastionów ani bastionu, który nie jest hostem SSH.
            crate::commands::check_jumps(&before, &doc.tree)
                .map_err(|e| format!("Import przerwany. {e}"))?;
            Ok(report)
        })
        .await?;
    state.log(format!(
        "import: dodano {} hostów i {} katalogów, zaktualizowano {} hostów i {} katalogów, zaufane klucze: {}",
        report.hosts_added,
        report.folders_added,
        report.hosts_updated,
        report.folders_updated,
        report.trusted_added
    ));
    Ok(report)
}

/// Importuje plik eksportu albo listę CSV: bierze kategorie wybrane w `parts` (i obecne w pliku),
/// a elementy już istniejące pomija albo aktualizuje. Cały import to jedna mutacja dokumentu.
#[tauri::command]
pub async fn import_hosts(
    state: State<'_, AppState>,
    data: Vec<u8>,
    password: String,
    format: Option<FileFormat>,
    parts: Parts,
    existing: Existing,
) -> Result<Report, String> {
    import_as(
        &state,
        data,
        Zeroizing::new(password),
        format.unwrap_or_default(),
        parts,
        existing,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Unlocked;
    use model::{Document, Protocol, TrustedKey};
    use vault::Vault;

    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;

    /// Podgląd i import zaszyfrowanego pliku eksportu (większość testów).
    async fn preview(
        state: &AppState,
        data: Vec<u8>,
        password: Zeroizing<String>,
    ) -> Result<Summary, String> {
        preview_as(state, data, password, FileFormat::Mrmx).await
    }

    async fn import_from(
        state: &AppState,
        data: Vec<u8>,
        password: Zeroizing<String>,
        parts: Parts,
        existing: Existing,
    ) -> Result<Report, String> {
        import_as(state, data, password, FileFormat::Mrmx, parts, existing).await
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-transfer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn state_with(dir: &Path, doc: Document) -> AppState {
        let path = dir.join("hosts.mrm");
        let vault = Vault::create(&path, "haslo-glowne", FAST, &doc).unwrap();
        let state = AppState::new(path);
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        state
    }

    fn pass(p: &str) -> Zeroizing<String> {
        Zeroizing::new(p.to_owned())
    }

    /// Katalog Produkcja z bastionem i bazą (hasło, port, bastion) oraz zaufany klucz bazy.
    fn sample() -> (Document, Id, Id, Id) {
        let mut doc = Document::default();
        let prod = doc.tree.add_folder("Produkcja", None).unwrap();
        let bastion = doc
            .tree
            .add_host("bastion", "bastion.example", Protocol::Ssh, Some(prod))
            .unwrap();
        let db = doc
            .tree
            .add_host("db", "10.0.0.5", Protocol::Ssh, Some(prod))
            .unwrap();
        let h = doc.tree.hosts.iter_mut().find(|h| h.id == db).unwrap();
        h.notes = "baza".into();
        h.fields.username = Some("postgres".into());
        h.fields.password = Some("sekret-bazy".into());
        h.fields.port = Some(2222);
        h.fields.jump_host = Some(bastion);
        doc.trusted_keys.push(TrustedKey {
            protocol: Protocol::Ssh,
            host: "10.0.0.5".into(),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:db".into(),
        });
        (doc, prod, bastion, db)
    }

    #[test]
    fn civil_date_matches_known_days() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert_eq!(civil_date(951_782_400), (2000, 2, 29));
        assert_eq!(civil_date(1_795_132_800), (2026, 11, 20));
        assert_eq!(civil_date(1_795_219_199), (2026, 11, 20));
        assert_eq!(civil_date(1_798_761_600), (2027, 1, 1));
        assert!(default_name().starts_with("hosty-") && default_name().ends_with(".mrmx"));
    }

    #[test]
    fn export_path_requires_absolute_file_in_existing_directory() {
        let d = dir("sciezka");
        let ok = export_path(&d.join("lista.mrmx").to_string_lossy()).unwrap();
        assert_eq!(ok, d.join("lista.mrmx"));
        // Rozszerzenie jest dopisywane, wielkość liter istniejącego nie ma znaczenia.
        let ext = export_path(&format!("  {}  ", d.join("lista").to_string_lossy())).unwrap();
        assert_eq!(ext, d.join("lista.mrmx"));
        let ext = export_path(&d.join("lista.json").to_string_lossy()).unwrap();
        assert_eq!(ext, d.join("lista.json.mrmx"));
        let upper = export_path(&d.join("LISTA.MRMX").to_string_lossy()).unwrap();
        assert_eq!(upper, d.join("LISTA.MRMX"));
        assert!(export_path("").is_err());
        assert!(export_path("lista.mrmx").is_err());
        assert!(export_path(&d.join("brak").join("lista.mrmx").to_string_lossy()).is_err());
        assert!(export_path(&format!("{}/", d.to_string_lossy())).is_err());
        assert!(export_path(&format!("{}\n", d.join("a\nb").to_string_lossy())).is_err());
    }

    #[tokio::test]
    async fn export_then_import_moves_only_selected_parts() {
        let d = dir("obieg");
        let (doc, prod, bastion, db) = sample();
        let source = state_with(&d, doc).await;
        let target_dir = dir("obieg-cel");
        let target = state_with(&target_dir, Document::default()).await;

        let file = d.join("lista").to_string_lossy().into_owned();
        let done = export_to(&source, &file, pass("haslo-pliku"), Parts::ALL, None, FAST)
            .await
            .unwrap();
        assert_eq!((done.folders, done.hosts, done.trusted_keys), (1, 2, 1));
        assert!(done.path.ends_with("lista.mrmx"));
        let data = std::fs::read(&done.path).unwrap();
        assert_eq!(&data[..4], b"MRMX");
        // Sekrety nie leżą w pliku jawnie.
        let text = String::from_utf8_lossy(&data);
        assert!(!text.contains("sekret-bazy") && !text.contains("postgres"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&done.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Drugi eksport pod tą samą nazwą nie nadpisuje pliku.
        let again = export_to(&source, &file, pass("haslo-pliku"), Parts::ALL, None, FAST).await;
        assert!(again.unwrap_err().contains("już istnieje"));
        assert_eq!(std::fs::read(&done.path).unwrap(), data);

        // Podgląd: wszystko nowe, kategorie z pliku.
        let sum = preview(&target, data.clone(), pass("haslo-pliku"))
            .await
            .unwrap();
        assert_eq!((sum.folders_new, sum.hosts_new, sum.trusted_new), (1, 2, 1));
        assert_eq!(sum.parts, Parts::ALL);
        // Podgląd niczego nie zmienia.
        target
            .read(|doc| {
                assert_eq!(*doc, Document::default());
                Ok(())
            })
            .await
            .unwrap();

        // Import bez haseł i bez zaufanych kluczy.
        let parts = Parts {
            passwords: false,
            trusted_keys: false,
            ..Parts::ALL
        };
        let report = import_from(
            &target,
            data.clone(),
            pass("haslo-pliku"),
            parts,
            Existing::Skip,
        )
        .await
        .unwrap();
        assert_eq!((report.folders_added, report.hosts_added), (1, 2));
        assert_eq!(report.trusted_added, 0);
        target
            .read(|doc| {
                let h = doc.tree.host(db).unwrap();
                assert_eq!(h.folder, Some(prod));
                assert_eq!(h.notes, "baza");
                assert_eq!(h.fields.username.as_deref(), Some("postgres"));
                assert_eq!(h.fields.port, Some(2222));
                assert_eq!(h.fields.jump_host, Some(bastion));
                assert_eq!(h.fields.password, None);
                assert!(doc.trusted_keys.is_empty());
                assert_eq!(doc.tree.jump_chain(db).unwrap(), vec![bastion]);
                Ok(())
            })
            .await
            .unwrap();
        // Import trafił na dysk: po ponownym otwarciu pliku hosty są na miejscu.
        let (_, reopened) = Vault::open::<Document>(&target.path, "haslo-glowne").unwrap();
        assert_eq!(reopened.tree.hosts.len(), 2);

        // Ponowny import z aktualizacją i hasłami: nic nowego, hasło dochodzi.
        let report = import_from(
            &target,
            data,
            pass("haslo-pliku"),
            Parts::ALL,
            Existing::Update,
        )
        .await
        .unwrap();
        assert_eq!((report.folders_added, report.hosts_added), (0, 0));
        assert_eq!(report.hosts_updated, 1);
        assert_eq!(report.trusted_added, 1);
        target
            .read(|doc| {
                assert_eq!(
                    doc.tree.host(db).unwrap().fields.password.as_deref(),
                    Some("sekret-bazy")
                );
                assert_eq!(doc.tree.hosts.len(), 2);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn export_of_one_folder_and_refusals() {
        let d = dir("katalog");
        let (mut doc, prod, _, _) = sample();
        doc.tree
            .add_host("luzem", "pc.example", Protocol::Rdp, None)
            .unwrap();
        let state = state_with(&d, doc).await;
        let file = d.join("prod.mrmx").to_string_lossy().into_owned();
        let done = export_to(
            &state,
            &file,
            pass("haslo-pliku"),
            Parts::default(),
            Some(prod),
            FAST,
        )
        .await
        .unwrap();
        assert_eq!((done.folders, done.hosts, done.trusted_keys), (1, 2, 0));
        // Za krótkie hasło, nieistniejący katalog drzewa, pusta lista.
        let short = export_to(&state, &file, pass("krotkie"), Parts::ALL, None, FAST).await;
        assert!(short.unwrap_err().contains("co najmniej 8"));
        let other = d.join("inny.mrmx").to_string_lossy().into_owned();
        let missing = export_to(
            &state,
            &other,
            pass("haslo-pliku"),
            Parts::ALL,
            Some(Id::new_v4()),
            FAST,
        )
        .await;
        assert!(missing.unwrap_err().contains("nie ma takiego katalogu"));
        assert!(!Path::new(&other).exists());
        let empty_dir = dir("katalog-pusty");
        let empty = state_with(&empty_dir, Document::default()).await;
        let nothing = export_to(&empty, &other, pass("haslo-pliku"), Parts::ALL, None, FAST).await;
        assert!(nothing.unwrap_err().contains("Nie ma czego"));
        assert!(!Path::new(&other).exists());
        // Zablokowany plik z hostami: eksport i import odmawiają.
        *state.inner.lock().await = None;
        let locked = export_to(&state, &other, pass("haslo-pliku"), Parts::ALL, None, FAST).await;
        assert!(locked.unwrap_err().contains("zablokowany"));
        let data = std::fs::read(&done.path).unwrap();
        let locked = import_from(
            &state,
            data,
            pass("haslo-pliku"),
            Parts::ALL,
            Existing::Skip,
        )
        .await;
        assert!(locked.unwrap_err().contains("zablokowany"));
    }

    fn sealed(pkg: &Package) -> Vec<u8> {
        vault::seal_export("haslo-pliku", FAST, pkg).unwrap()
    }

    #[tokio::test]
    async fn bad_files_are_refused_and_document_is_untouched() {
        let d = dir("zle");
        let (doc, _, _, db) = sample();
        let state = state_with(&d, Document::default()).await;
        let good = transfer::export(&doc, None, Parts::ALL).unwrap();
        let try_import = |data: Vec<u8>, password: &'static str| {
            let state = &state;
            async move {
                import_from(state, data, pass(password), Parts::ALL, Existing::Skip)
                    .await
                    .unwrap_err()
            }
        };
        // Złe hasło, uszkodzenie, nie ten rodzaj pliku, za duży plik.
        let e = try_import(sealed(&good), "inne-haslo").await;
        assert!(e.contains("Nieprawidłowe hasło pliku eksportu"), "{e}");
        let mut broken = sealed(&good);
        *broken.last_mut().unwrap() ^= 1;
        let e = try_import(broken, "haslo-pliku").await;
        assert!(e.contains("Nieprawidłowe hasło pliku eksportu"), "{e}");
        let e = try_import(b"zwykly tekst, nie eksport".to_vec(), "haslo-pliku").await;
        assert!(e.contains("To nie jest plik eksportu"), "{e}");
        let e = try_import(std::fs::read(&state.path).unwrap(), "haslo-glowne").await;
        assert!(e.contains("To jest plik z hostami"), "{e}");
        let e = try_import(vec![0; MAX_IMPORT_FILE + 1], "haslo-pliku").await;
        assert!(e.contains("za duży"), "{e}");
        let e = try_import(sealed(&good)[..40].to_vec(), "haslo-pliku").await;
        assert!(e.contains("uszkodzony albo obcięty"), "{e}");
        // Poprawnie zaszyfrowany plik z błędną zawartością: komunikat bez treści pliku.
        let odd = vault::seal_export(
            "haslo-pliku",
            FAST,
            &serde_json::json!({"format": "sekret"}),
        )
        .unwrap();
        let e = try_import(odd, "haslo-pliku").await;
        assert!(
            e.contains("nieznaną strukturę") && !e.contains("sekret"),
            "{e}"
        );
        let mut newer = good.clone();
        newer.format = transfer::FORMAT + 1;
        let e = try_import(sealed(&newer), "haslo-pliku").await;
        assert!(e.contains("nowszej wersji"), "{e}");
        // Wartości, których formularz by nie przyjął.
        let with = |change: fn(&mut Fields)| {
            let mut p = good.clone();
            change(&mut p.hosts.iter_mut().find(|h| h.id == db).unwrap().fields);
            sealed(&p)
        };
        let e = try_import(
            with(|f| f.ssh_term = Some("zly term".into())),
            "haslo-pliku",
        )
        .await;
        assert!(e.contains("hosta db") && e.contains("Typ terminala"), "{e}");
        let e = try_import(
            with(|f| f.ssh_login_command = Some("a\u{1b}[2J".into())),
            "haslo-pliku",
        )
        .await;
        assert!(e.contains("Polecenie po zalogowaniu"), "{e}");
        let e = try_import(
            with(|f| f.ssh_key_path = Some("wzgledna/sciezka".into())),
            "haslo-pliku",
        )
        .await;
        assert!(e.contains("Ścieżka klucza"), "{e}");
        let e = try_import(with(|f| f.terminal_font_size = Some(200)), "haslo-pliku").await;
        assert!(e.contains("Rozmiar czcionki"), "{e}");
        let e = try_import(with(|f| f.port = Some(0)), "haslo-pliku").await;
        assert!(e.contains("Port"), "{e}");
        let e = try_import(
            with(|f| {
                f.ssh_key = Some(StoredKey {
                    openssh: "to nie jest klucz".into(),
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: "SHA256:zmyslony".into(),
                })
            }),
            "haslo-pliku",
        )
        .await;
        assert!(
            e.contains("klucza SSH") && !e.contains("to nie jest klucz"),
            "{e}"
        );
        // Bastion, który nie jest hostem SSH, przerywa import.
        let mut rdp_jump = good.clone();
        let bastion = rdp_jump
            .hosts
            .iter_mut()
            .find(|h| h.name == "bastion")
            .unwrap();
        bastion.protocol = Protocol::Rdp;
        let e = try_import(sealed(&rdp_jump), "haslo-pliku").await;
        assert!(
            e.contains("Import przerwany") && e.contains("bastion"),
            "{e}"
        );
        // Po wszystkich odmowach dokument jest nietknięty, a plik nie był zapisywany.
        state
            .read(|doc| {
                assert_eq!(*doc, Document::default());
                Ok(())
            })
            .await
            .unwrap();
        assert!(!vault::backup_file(&state.path, 1).exists());
    }

    #[tokio::test]
    async fn empty_text_fields_from_file_become_unset() {
        let d = dir("puste");
        let (doc, _, _, db) = sample();
        let state = state_with(&d, Document::default()).await;
        let mut pkg = transfer::export(&doc, None, Parts::ALL).unwrap();
        let f = &mut pkg.hosts.iter_mut().find(|h| h.id == db).unwrap().fields;
        f.username = Some("  ".into());
        f.password = Some(String::new());
        f.ssh_term = Some(" vt100 ".into());
        f.ssh_login_command = Some("  sudo -i ".into());
        import_from(
            &state,
            sealed(&pkg),
            pass("haslo-pliku"),
            Parts::ALL,
            Existing::Skip,
        )
        .await
        .unwrap();
        state
            .read(|doc| {
                let f = &doc.tree.host(db).unwrap().fields;
                assert_eq!(f.username, None);
                assert_eq!(f.password, None);
                assert_eq!(f.ssh_term.as_deref(), Some("vt100"));
                assert_eq!(f.ssh_login_command.as_deref(), Some("sudo -i"));
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn csv_list_is_previewed_imported_and_refreshed_without_password() {
        let d = dir("csv");
        let state = state_with(&d, Document::default()).await;
        let csv = "nazwa,adres,protokol,katalog\n\
            SRV-DC01,srv-dc01.example.com,rdp,Serwery/Kontrolery\n\
            jump,jump.example.com,ssh,Serwery\n";
        let sum = preview_as(&state, csv.as_bytes().to_vec(), pass(""), FileFormat::Csv)
            .await
            .unwrap();
        assert_eq!((sum.folders_new, sum.hosts_new), (2, 2));
        assert_eq!(sum.parts, Parts::default());
        // Zaznaczone kategorie nie mają znaczenia: lista ich nie zawiera.
        let r = import_as(
            &state,
            csv.as_bytes().to_vec(),
            pass(""),
            FileFormat::Csv,
            Parts::ALL,
            Existing::Skip,
        )
        .await
        .unwrap();
        assert_eq!((r.folders_added, r.hosts_added), (2, 2));
        let dc = model::csv::host_id("srv-dc01.example.com");
        state
            .mutate(|doc| {
                let h = doc.tree.hosts.iter_mut().find(|h| h.id == dc).unwrap();
                assert_eq!(h.protocol, Protocol::Rdp);
                h.fields.password = Some("moje-haslo".into());
                Ok(())
            })
            .await
            .unwrap();
        // Odświeżona lista: zmieniona nazwa i nowy host; hasło ustawione lokalnie zostaje.
        let refreshed = "nazwa;adres;protokol;katalog\r\n\
            DC-01;srv-dc01.example.com;rdp;Serwery/Kontrolery\r\n\
            jump;jump.example.com;ssh;Serwery\r\n\
            nowy;nowy.example.com;rdp;Serwery\r\n";
        let sum = preview_as(
            &state,
            refreshed.as_bytes().to_vec(),
            pass(""),
            FileFormat::Csv,
        )
        .await
        .unwrap();
        assert_eq!((sum.hosts_new, sum.hosts_existing), (1, 2));
        let r = import_as(
            &state,
            refreshed.as_bytes().to_vec(),
            pass(""),
            FileFormat::Csv,
            Parts::default(),
            Existing::Update,
        )
        .await
        .unwrap();
        assert_eq!((r.hosts_added, r.hosts_updated), (1, 1));
        state
            .read(|doc| {
                let h = doc.tree.host(dc).unwrap();
                assert_eq!(h.name, "DC-01");
                assert_eq!(h.fields.password.as_deref(), Some("moje-haslo"));
                assert_eq!(doc.tree.hosts.len(), 3);
                Ok(())
            })
            .await
            .unwrap();
        // Błędy: zły wiersz, brak kolumny, nie UTF-8, plik eksportu podany jako CSV.
        let bad = |text: &'static [u8]| {
            let state = &state;
            async move {
                preview_as(state, text.to_vec(), pass(""), FileFormat::Csv)
                    .await
                    .unwrap_err()
            }
        };
        let e = bad(b"nazwa,adres,protokol\na,a.example,telnet\n").await;
        assert!(e.contains("wiersz 2") && e.contains("ssh albo rdp"), "{e}");
        let e = bad(b"nazwa,adres\na,a.example\n").await;
        assert!(e.contains("brak kolumny protokol"), "{e}");
        let e = bad(b"nazwa,adres,protokol\n\xff\xfe,a.example,ssh\n").await;
        assert!(e.contains("UTF-8"), "{e}");
        let e = bad(b"MRMX\x01\x00\x00binarne").await;
        assert!(e.contains("Nie można odczytać pliku CSV"), "{e}");
        // Lista CSV podana jako plik eksportu też jest odrzucana czytelnie.
        let e = preview(&state, csv.as_bytes().to_vec(), pass("cokolwiek"))
            .await
            .unwrap_err();
        assert!(e.contains("To nie jest plik eksportu"), "{e}");
    }

    /// Klucz generowany w locie przez `ssh-keygen` (bez kluczy w repozytorium); bez programu test
    /// się pomija.
    fn generated_key(dir: &Path) -> Option<String> {
        let file = dir.join("klucz");
        let out = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
            .arg(&file)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| std::fs::read_to_string(&file).ok())
            .flatten()
    }

    #[tokio::test]
    async fn key_fingerprint_is_recomputed_not_taken_from_file() {
        let d = dir("klucz");
        let Some(text) = generated_key(&d) else {
            return eprintln!("pominięto: brak ssh-keygen");
        };
        let (_, real) = ssh::import_key(&text, None).unwrap();
        let (doc, _, _, db) = sample();
        let state = state_with(&d, Document::default()).await;
        let mut pkg = transfer::export(&doc, None, Parts::ALL).unwrap();
        pkg.hosts
            .iter_mut()
            .find(|h| h.id == db)
            .unwrap()
            .fields
            .ssh_key = Some(StoredKey {
            openssh: text,
            algorithm: "ssh-rsa".into(),
            fingerprint: "SHA256:podstawiony".into(),
        });
        import_from(
            &state,
            sealed(&pkg),
            pass("haslo-pliku"),
            Parts::ALL,
            Existing::Skip,
        )
        .await
        .unwrap();
        state
            .read(|doc| {
                let k = doc.tree.host(db).unwrap().fields.ssh_key.clone().unwrap();
                assert_eq!(k.algorithm, real.algorithm);
                assert_eq!(k.fingerprint, real.fingerprint);
                Ok(())
            })
            .await
            .unwrap();
    }
}
