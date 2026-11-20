//! Eksport i import hostów: pakiet z wybranymi kategoriami danych oraz scalanie go z dokumentem
//! po identyfikatorach.
//!
//! Pakiet zawiera katalogi i hosty (z identyfikatorami) oraz, opcjonalnie, zaufane klucze hostów.
//! Nie zawiera ustawień programu ani ustawień domyślnych drzewa. Te same kategorie wybiera się przy
//! eksporcie (co trafia do pakietu) i przy imporcie (co z pakietu jest brane); import nigdy nie
//! bierze kategorii, której pakiet nie zawiera.
//!
//! Pakiet pochodzi z zewnątrz, więc `import` niczego w nim nie zakłada: sprawdza limity, powtórzone
//! identyfikatory, puste nazwy i cykle katalogów, a odwołania do nieistniejących katalogów
//! i bastionów usuwa. Wartości pól zależne od innych modułów (typ terminala, klucz SSH) sprawdza
//! warstwa aplikacji przed wywołaniem `import`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{Document, Fields, Folder, Host, Id, TrustedKey};

/// Wersja formatu pakietu.
pub const FORMAT: u32 = 1;
/// Najwięcej katalogów i hostów łącznie w jednym pakiecie.
pub const MAX_ITEMS: usize = 20_000;
/// Najwięcej zaufanych kluczy w jednym pakiecie.
pub const MAX_TRUSTED: usize = 50_000;
/// Najdłuższa nazwa albo adres (w znakach).
pub const MAX_NAME: usize = 1024;
/// Najdłuższa notatka hosta (w bajtach).
pub const MAX_NOTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("nie ma takiego katalogu")]
    NoFolder,
    #[error("plik pochodzi z nowszej wersji programu (format {0})")]
    UnsupportedFormat(u32),
    #[error("plik zawiera za dużo elementów")]
    TooLarge,
    #[error("plik zawiera powtórzony identyfikator")]
    DuplicateId,
    #[error("plik zawiera element bez nazwy albo adresu, albo z niedozwolonymi znakami")]
    BadName,
    #[error("import utworzyłby cykl katalogów")]
    FolderCycle,
}

/// Kategorie danych wybierane przy eksporcie i imporcie. Nazwy, adresy, protokół i struktura
/// katalogów są przenoszone zawsze.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Parts {
    /// Nazwy użytkowników i domeny.
    pub usernames: bool,
    /// Hasła.
    pub passwords: bool,
    /// Klucze prywatne SSH zapisane w pliku z hostami.
    pub ssh_keys: bool,
    /// Ścieżki plików kluczy SSH (zależne od maszyny).
    pub key_paths: bool,
    /// Opcje połączenia: port, bastion, typ terminala, starsze algorytmy, opcje RDP, schemat
    /// i rozmiar czcionki terminala.
    pub options: bool,
    /// Polecenie po zalogowaniu.
    pub login_command: bool,
    /// Notatki hostów.
    pub notes: bool,
    /// Zaufane klucze hostów SSH i certyfikaty RDP.
    pub trusted_keys: bool,
}

impl Parts {
    pub const ALL: Self = Self {
        usernames: true,
        passwords: true,
        ssh_keys: true,
        key_paths: true,
        options: true,
        login_command: true,
        notes: true,
        trusted_keys: true,
    };

    /// Część wspólna: kategoria wybrana i obecna w pakiecie.
    pub fn and(self, other: Self) -> Self {
        Self {
            usernames: self.usernames && other.usernames,
            passwords: self.passwords && other.passwords,
            ssh_keys: self.ssh_keys && other.ssh_keys,
            key_paths: self.key_paths && other.key_paths,
            options: self.options && other.options,
            login_command: self.login_command && other.login_command,
            notes: self.notes && other.notes,
            trusted_keys: self.trusted_keys && other.trusted_keys,
        }
    }
}

/// Składa pola z dwóch źródeł: kategorie wybrane w `parts` pochodzą z `file`, pozostałe z `local`.
/// Kategoria jest zastępowana w całości, także pustymi wartościami. Rozłożenie `Fields` na pola jest
/// wyczerpujące, więc nowe pole dziedziczone nie skompiluje się bez przypisania do kategorii.
fn mix(local: &Fields, file: &Fields, parts: Parts) -> Fields {
    fn pick<T: Clone>(from_file: bool, local: &Option<T>, file: &Option<T>) -> Option<T> {
        if from_file {
            file.clone()
        } else {
            local.clone()
        }
    }
    let Fields {
        port,
        username,
        domain,
        password,
        ssh_key,
        ssh_key_path,
        ssh_term,
        ssh_legacy,
        jump_host,
        terminal_scheme,
        rdp_multimon,
        rdp_kerberos,
        rdp_kdc,
        rdp_profile,
        rdp_webauthn,
        rdp_smartcard,
        terminal_font_size,
        ssh_login_command,
    } = file;
    Fields {
        port: pick(parts.options, &local.port, port),
        username: pick(parts.usernames, &local.username, username),
        domain: pick(parts.usernames, &local.domain, domain),
        password: pick(parts.passwords, &local.password, password),
        ssh_key: pick(parts.ssh_keys, &local.ssh_key, ssh_key),
        ssh_key_path: pick(parts.key_paths, &local.ssh_key_path, ssh_key_path),
        ssh_term: pick(parts.options, &local.ssh_term, ssh_term),
        ssh_legacy: pick(parts.options, &local.ssh_legacy, ssh_legacy),
        jump_host: pick(parts.options, &local.jump_host, jump_host),
        terminal_scheme: pick(parts.options, &local.terminal_scheme, terminal_scheme),
        rdp_multimon: pick(parts.options, &local.rdp_multimon, rdp_multimon),
        rdp_kerberos: pick(parts.options, &local.rdp_kerberos, rdp_kerberos),
        rdp_kdc: pick(parts.options, &local.rdp_kdc, rdp_kdc),
        rdp_profile: pick(parts.options, &local.rdp_profile, rdp_profile),
        rdp_webauthn: pick(parts.options, &local.rdp_webauthn, rdp_webauthn),
        rdp_smartcard: pick(parts.options, &local.rdp_smartcard, rdp_smartcard),
        terminal_font_size: pick(parts.options, &local.terminal_font_size, terminal_font_size),
        ssh_login_command: pick(
            parts.login_command,
            &local.ssh_login_command,
            ssh_login_command,
        ),
    }
}

/// Zostawia w polach tylko wybrane kategorie.
fn keep(fields: &Fields, parts: Parts) -> Fields {
    mix(&Fields::default(), fields, parts)
}

/// Zawartość pliku eksportu. Celowo bez `Debug`: pakiet niesie hasła, klucze i polecenia, których
/// nie wolno logować.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub format: u32,
    /// Kategorie obecne w pakiecie.
    #[serde(default)]
    pub parts: Parts,
    /// Katalog, od którego zaczynał się eksport częściowy. Przy imporcie taki katalog, jeśli już
    /// istnieje, zostaje tam, gdzie jest (w pakiecie nie ma jego katalogu nadrzędnego).
    #[serde(default)]
    pub root: Option<Id>,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub trusted_keys: Vec<TrustedKey>,
}

/// Buduje pakiet z całego drzewa (`root == None`) albo z jednego katalogu z zawartością.
pub fn export(doc: &Document, root: Option<Id>, parts: Parts) -> Result<Package, Error> {
    let tree = &doc.tree;
    let inside: Option<HashSet<Id>> = match root {
        None => None,
        Some(r) => {
            tree.folder(r).ok_or(Error::NoFolder)?;
            let mut set = HashSet::from([r]);
            loop {
                let before = set.len();
                for f in &tree.folders {
                    if f.parent.is_some_and(|p| set.contains(&p)) {
                        set.insert(f.id);
                    }
                }
                if set.len() == before {
                    break;
                }
            }
            Some(set)
        }
    };
    let folders: Vec<Folder> = tree
        .folders
        .iter()
        .filter(|f| inside.as_ref().is_none_or(|s| s.contains(&f.id)))
        .map(|f| Folder {
            id: f.id,
            name: f.name.clone(),
            parent: if root == Some(f.id) { None } else { f.parent },
            fields: keep(&f.fields, parts),
        })
        .collect();
    let hosts: Vec<Host> = tree
        .hosts
        .iter()
        .filter(|h| {
            inside
                .as_ref()
                .is_none_or(|s| h.folder.is_some_and(|f| s.contains(&f)))
        })
        .map(|h| Host {
            id: h.id,
            name: h.name.clone(),
            address: h.address.clone(),
            protocol: h.protocol,
            folder: h.folder,
            favorite: h.favorite,
            notes: if parts.notes {
                h.notes.clone()
            } else {
                String::new()
            },
            fields: keep(&h.fields, parts),
        })
        .collect();
    let trusted_keys = if parts.trusted_keys {
        doc.trusted_keys
            .iter()
            .filter(|k| {
                // Eksport częściowy niesie tylko klucze eksportowanych hostów.
                inside.is_none()
                    || hosts.iter().any(|h| {
                        h.protocol == k.protocol && h.address.eq_ignore_ascii_case(&k.host)
                    })
            })
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    Ok(Package {
        format: FORMAT,
        parts,
        root,
        folders,
        hosts,
        trusted_keys,
    })
}

fn good_name(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= MAX_NAME && !s.chars().any(char::is_control)
}

/// Sprawdza pakiet niezależnie od dokumentu: wersję formatu, limity, powtórzone identyfikatory,
/// nazwy i adresy.
pub fn check(pkg: &Package) -> Result<(), Error> {
    if pkg.format != FORMAT {
        return Err(Error::UnsupportedFormat(pkg.format));
    }
    if pkg.folders.len() + pkg.hosts.len() > MAX_ITEMS || pkg.trusted_keys.len() > MAX_TRUSTED {
        return Err(Error::TooLarge);
    }
    let mut seen = HashSet::new();
    if !pkg.folders.iter().all(|f| seen.insert(f.id)) {
        return Err(Error::DuplicateId);
    }
    let mut seen = HashSet::new();
    if !pkg.hosts.iter().all(|h| seen.insert(h.id)) {
        return Err(Error::DuplicateId);
    }
    if !pkg.folders.iter().all(|f| good_name(&f.name)) {
        return Err(Error::BadName);
    }
    if !pkg
        .hosts
        .iter()
        .all(|h| good_name(&h.name) && good_name(&h.address) && h.notes.len() <= MAX_NOTES)
    {
        return Err(Error::BadName);
    }
    if !pkg
        .trusted_keys
        .iter()
        .all(|k| good_name(&k.host) && good_name(&k.algorithm) && good_name(&k.fingerprint))
    {
        return Err(Error::BadName);
    }
    Ok(())
}

/// Podgląd importu: co pakiet zawiera i ile z tego już jest w dokumencie.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Kategorie obecne w pakiecie.
    pub parts: Parts,
    pub folders_new: usize,
    pub folders_existing: usize,
    pub hosts_new: usize,
    pub hosts_existing: usize,
    /// Zaufane klucze, których dokument jeszcze nie ma (bez kolidujących).
    pub trusted_new: usize,
}

/// Czy klucz z pakietu koliduje z zapamiętanym: ten sam host, port i algorytm, inny odcisk.
fn conflicts(doc: &Document, key: &TrustedKey) -> bool {
    doc.trusted(key.protocol, &key.host, key.port)
        .iter()
        .any(|k| k.algorithm == key.algorithm && k.fingerprint != key.fingerprint)
}

fn known(doc: &Document, key: &TrustedKey) -> bool {
    doc.trusted(key.protocol, &key.host, key.port)
        .iter()
        .any(|k| k.algorithm == key.algorithm && k.fingerprint == key.fingerprint)
}

pub fn summarize(doc: &Document, pkg: &Package) -> Summary {
    let folders_existing = pkg
        .folders
        .iter()
        .filter(|f| doc.tree.folder(f.id).is_some())
        .count();
    let hosts_existing = pkg
        .hosts
        .iter()
        .filter(|h| doc.tree.host(h.id).is_some())
        .count();
    let trusted_new = if pkg.parts.trusted_keys {
        pkg.trusted_keys
            .iter()
            .filter(|k| !known(doc, k) && !conflicts(doc, k))
            .count()
    } else {
        0
    };
    Summary {
        parts: pkg.parts,
        folders_new: pkg.folders.len() - folders_existing,
        folders_existing,
        hosts_new: pkg.hosts.len() - hosts_existing,
        hosts_existing,
        trusted_new,
    }
}

/// Co zrobić z katalogiem albo hostem, który już jest w dokumencie (ten sam identyfikator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Existing {
    /// Zostaw bez zmian.
    Skip,
    /// Zastąp nazwę, adres, protokół, położenie i wybrane kategorie danymi z pakietu.
    Update,
}

/// Wynik importu.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    pub folders_added: usize,
    pub folders_updated: usize,
    pub hosts_added: usize,
    pub hosts_updated: usize,
    /// Istniejące elementy pominięte albo niezmienione przez aktualizację.
    pub unchanged: usize,
    pub trusted_added: usize,
    /// Zaufane klucze pominięte, bo dokument ma dla tego hosta inny odcisk.
    pub trusted_conflicts: usize,
    /// Odwołania do bastionów, których nie ma ani w pakiecie, ani w dokumencie.
    pub jumps_dropped: usize,
}

/// Scala pakiet z dokumentem. Nowe elementy są dodawane z identyfikatorami z pakietu, istniejące
/// (ten sam identyfikator) są pomijane albo aktualizowane. Bierze tylko kategorie wybrane
/// w `parts` i obecne w pakiecie; przy aktualizacji pozostałe kategorie zostają lokalne, tak samo
/// jak oznaczenie ulubionego. Przy błędzie dokument może być częściowo zmieniony, więc wywołujący
/// pracuje na kopii (`AppState::mutate`).
pub fn import(
    doc: &mut Document,
    pkg: &Package,
    parts: Parts,
    existing: Existing,
) -> Result<Report, Error> {
    check(pkg)?;
    let parts = parts.and(pkg.parts);
    let mut report = Report::default();
    let pkg_folders: HashSet<Id> = pkg.folders.iter().map(|f| f.id).collect();
    let local_folders: HashSet<Id> = doc.tree.folders.iter().map(|f| f.id).collect();
    // Katalog nadrzędny spoza pakietu i spoza dokumentu oznacza najwyższy poziom.
    let place =
        |id: Option<Id>| id.filter(|p| pkg_folders.contains(p) || local_folders.contains(p));

    for f in &pkg.folders {
        let parent = place(f.parent);
        match doc.tree.folders.iter_mut().find(|l| l.id == f.id) {
            Some(local) => {
                if existing == Existing::Skip {
                    report.unchanged += 1;
                    continue;
                }
                let before = local.clone();
                local.name = f.name.trim().to_owned();
                if pkg.root != Some(f.id) {
                    local.parent = parent;
                }
                local.fields = mix(&local.fields, &f.fields, parts);
                if *local == before {
                    report.unchanged += 1;
                } else {
                    report.folders_updated += 1;
                }
            }
            None => {
                doc.tree.folders.push(Folder {
                    id: f.id,
                    name: f.name.trim().to_owned(),
                    parent,
                    fields: keep(&f.fields, parts),
                });
                report.folders_added += 1;
            }
        }
    }

    for h in &pkg.hosts {
        let folder = place(h.folder);
        match doc.tree.hosts.iter_mut().find(|l| l.id == h.id) {
            Some(local) => {
                if existing == Existing::Skip {
                    report.unchanged += 1;
                    continue;
                }
                let before = local.clone();
                local.name = h.name.trim().to_owned();
                local.address = h.address.trim().to_owned();
                local.protocol = h.protocol;
                local.folder = folder;
                if parts.notes {
                    local.notes = h.notes.clone();
                }
                local.fields = mix(&local.fields, &h.fields, parts);
                if *local == before {
                    report.unchanged += 1;
                } else {
                    report.hosts_updated += 1;
                }
            }
            None => {
                doc.tree.hosts.push(Host {
                    id: h.id,
                    name: h.name.trim().to_owned(),
                    address: h.address.trim().to_owned(),
                    protocol: h.protocol,
                    folder,
                    favorite: h.favorite,
                    notes: if parts.notes {
                        h.notes.clone()
                    } else {
                        String::new()
                    },
                    fields: keep(&h.fields, parts),
                });
                report.hosts_added += 1;
            }
        }
    }

    // Cykl mógł przyjść w samym pakiecie albo powstać z połączenia jego struktury z lokalną.
    for f in &doc.tree.folders {
        let mut seen = HashSet::from([f.id]);
        let mut cur = f.parent;
        while let Some(p) = cur {
            if !seen.insert(p) {
                return Err(Error::FolderCycle);
            }
            cur = doc.tree.folder(p).and_then(|x| x.parent);
        }
    }

    // Bastion, którego nie ma po scaleniu, znika z elementów pochodzących z pakietu.
    let hosts: HashSet<Id> = doc.tree.hosts.iter().map(|h| h.id).collect();
    let pkg_hosts: HashSet<Id> = pkg.hosts.iter().map(|h| h.id).collect();
    let mut drop_missing = |fields: &mut Fields| {
        if fields.jump_host.is_some_and(|j| !hosts.contains(&j)) {
            fields.jump_host = None;
            report.jumps_dropped += 1;
        }
    };
    for f in doc
        .tree
        .folders
        .iter_mut()
        .filter(|f| pkg_folders.contains(&f.id))
    {
        drop_missing(&mut f.fields);
    }
    for h in doc
        .tree
        .hosts
        .iter_mut()
        .filter(|h| pkg_hosts.contains(&h.id))
    {
        drop_missing(&mut h.fields);
    }

    if parts.trusted_keys {
        for k in &pkg.trusted_keys {
            if known(doc, k) {
                continue;
            }
            if conflicts(doc, k) {
                report.trusted_conflicts += 1;
                continue;
            }
            doc.trusted_keys.push(k.clone());
            report.trusted_added += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Protocol, StoredKey};

    /// Dokument: katalog Firma z podkatalogiem Produkcja (bastion i db w środku), host luzem.
    struct Sample {
        doc: Document,
        firma: Id,
        prod: Id,
        bastion: Id,
        db: Id,
        luzem: Id,
    }

    fn sample() -> Sample {
        let mut doc = Document::default();
        let t = &mut doc.tree;
        let firma = t.add_folder("Firma", None).unwrap();
        let prod = t.add_folder("Produkcja", Some(firma)).unwrap();
        let bastion = t
            .add_host("bastion", "bastion.example", Protocol::Ssh, Some(prod))
            .unwrap();
        let db = t
            .add_host("db", "10.0.0.5", Protocol::Ssh, Some(prod))
            .unwrap();
        let luzem = t
            .add_host("pulpit", "pc.example", Protocol::Rdp, None)
            .unwrap();
        t.folders[0].fields.username = Some("admin".into());
        t.folders[1].fields.jump_host = Some(bastion);
        let h = t.hosts.iter_mut().find(|h| h.id == db).unwrap();
        h.favorite = true;
        h.notes = "baza główna".into();
        h.fields = Fields {
            port: Some(2222),
            username: Some("postgres".into()),
            domain: Some("FIRMA".into()),
            password: Some("tajne".into()),
            ssh_key: Some(StoredKey {
                openssh: "KLUCZ".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:abc".into(),
            }),
            ssh_key_path: Some("~/.ssh/id".into()),
            ssh_term: Some("vt100".into()),
            ssh_login_command: Some("sudo -i".into()),
            ..Default::default()
        };
        doc.trusted_keys.push(TrustedKey {
            protocol: Protocol::Ssh,
            host: "10.0.0.5".into(),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:db".into(),
        });
        doc.trusted_keys.push(TrustedKey {
            protocol: Protocol::Rdp,
            host: "pc.example".into(),
            port: 3389,
            algorithm: "x509".into(),
            fingerprint: "SHA256:pc".into(),
        });
        Sample {
            doc,
            firma,
            prod,
            bastion,
            db,
            luzem,
        }
    }

    fn host(doc: &Document, id: Id) -> &Host {
        doc.tree.host(id).unwrap()
    }

    #[test]
    fn every_field_belongs_to_exactly_one_category() {
        let all = Fields::all_set();
        assert_eq!(keep(&all, Parts::ALL), all);
        assert_eq!(keep(&all, Parts::default()), Fields::default());
        // Kategorie rozłączne: suma pól zostawionych przez każdą z osobna daje wszystkie pola,
        // a żadne pole nie zostaje w dwóch kategoriach.
        let single = [
            Parts {
                usernames: true,
                ..Default::default()
            },
            Parts {
                passwords: true,
                ..Default::default()
            },
            Parts {
                ssh_keys: true,
                ..Default::default()
            },
            Parts {
                key_paths: true,
                ..Default::default()
            },
            Parts {
                options: true,
                ..Default::default()
            },
            Parts {
                login_command: true,
                ..Default::default()
            },
        ];
        let count = |f: &Fields| serde_json::to_value(f).unwrap().as_object().unwrap().len();
        let total: usize = single.iter().map(|p| count(&keep(&all, *p))).sum();
        assert_eq!(total, count(&all));
        // Notatki i zaufane klucze nie dotyczą pól dziedziczonych.
        let other = Parts {
            notes: true,
            trusted_keys: true,
            ..Default::default()
        };
        assert_eq!(keep(&all, other), Fields::default());
    }

    #[test]
    fn export_without_secrets_carries_no_secret_text() {
        let s = sample();
        let parts = Parts {
            usernames: true,
            options: true,
            ..Default::default()
        };
        let pkg = export(&s.doc, None, parts).unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        for secret in [
            "tajne",
            "KLUCZ",
            "~/.ssh/id",
            "sudo -i",
            "baza główna",
            "SHA256:db",
        ] {
            assert!(!json.contains(secret), "{secret} w pakiecie");
        }
        assert!(json.contains("postgres") && json.contains("FIRMA") && json.contains("vt100"));
        assert_eq!(pkg.folders.len(), 2);
        assert_eq!(pkg.hosts.len(), 3);
        assert!(pkg.trusted_keys.is_empty());
        assert_eq!(pkg.parts, parts);
    }

    #[test]
    fn export_of_folder_takes_subtree_and_its_trusted_keys() {
        let s = sample();
        let pkg = export(&s.doc, Some(s.prod), Parts::ALL).unwrap();
        assert_eq!(pkg.root, Some(s.prod));
        assert_eq!(pkg.folders.len(), 1);
        assert_eq!(pkg.folders[0].parent, None);
        let ids: HashSet<Id> = pkg.hosts.iter().map(|h| h.id).collect();
        assert_eq!(ids, HashSet::from([s.bastion, s.db]));
        assert!(!ids.contains(&s.luzem));
        assert_eq!(pkg.trusted_keys.len(), 1);
        assert_eq!(pkg.trusted_keys[0].host, "10.0.0.5");
        // Katalog nadrzędny bierze też podkatalogi.
        let pkg = export(&s.doc, Some(s.firma), Parts::default()).unwrap();
        assert_eq!(pkg.folders.len(), 2);
        assert_eq!(pkg.hosts.len(), 2);
        assert_eq!(
            export(&s.doc, Some(Id::new_v4()), Parts::ALL).err(),
            Some(Error::NoFolder)
        );
    }

    #[test]
    fn import_into_empty_document_recreates_selected_parts() {
        let s = sample();
        let pkg = export(&s.doc, None, Parts::ALL).unwrap();
        let mut doc = Document::default();
        let parts = Parts {
            usernames: true,
            options: true,
            notes: true,
            ..Default::default()
        };
        let before = summarize(&doc, &pkg);
        assert_eq!((before.folders_new, before.hosts_new), (2, 3));
        assert_eq!((before.folders_existing, before.hosts_existing), (0, 0));
        assert_eq!(before.trusted_new, 2);
        let r = import(&mut doc, &pkg, parts, Existing::Skip).unwrap();
        assert_eq!((r.folders_added, r.hosts_added), (2, 3));
        assert_eq!(r.trusted_added, 0);
        let db = host(&doc, s.db);
        assert_eq!(db.folder, Some(s.prod));
        assert!(db.favorite);
        assert_eq!(db.notes, "baza główna");
        assert_eq!(db.fields.username.as_deref(), Some("postgres"));
        assert_eq!(db.fields.port, Some(2222));
        assert_eq!(db.fields.password, None);
        assert_eq!(db.fields.ssh_key, None);
        assert_eq!(db.fields.ssh_key_path, None);
        assert_eq!(db.fields.ssh_login_command, None);
        assert_eq!(doc.tree.folder(s.prod).unwrap().parent, Some(s.firma));
        assert_eq!(
            doc.tree.folder(s.prod).unwrap().fields.jump_host,
            Some(s.bastion)
        );
        assert!(doc.trusted_keys.is_empty());
        // Dziedziczenie i łańcuch bastionów działają na zaimportowanym drzewie.
        assert_eq!(doc.tree.jump_chain(s.db).unwrap(), vec![s.bastion]);
        // Wszystko wybrane: dokument równy źródłowemu poza ustawieniami domyślnymi drzewa.
        let mut full = Document::default();
        import(&mut full, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!(full.tree.folders, s.doc.tree.folders);
        assert_eq!(full.tree.hosts, s.doc.tree.hosts);
        assert_eq!(full.trusted_keys, s.doc.trusted_keys);
    }

    #[test]
    fn import_never_takes_a_category_missing_from_the_package() {
        let s = sample();
        let pkg = export(
            &s.doc,
            None,
            Parts {
                usernames: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Lokalnie ten sam host ma własne hasło i port.
        let mut doc = s.doc.clone();
        let local = doc.tree.hosts.iter_mut().find(|h| h.id == s.db).unwrap();
        local.fields.password = Some("moje".into());
        local.fields.port = Some(5432);
        local.fields.username = Some("ja".into());
        // Użytkownik zaznaczył wszystko, ale pakiet ma tylko nazwy użytkowników.
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Update).unwrap();
        let db = host(&doc, s.db);
        assert_eq!(db.fields.username.as_deref(), Some("postgres"));
        assert_eq!(db.fields.password.as_deref(), Some("moje"));
        assert_eq!(db.fields.port, Some(5432));
        assert_eq!(db.notes, "baza główna");
        assert_eq!(r.hosts_updated, 1);
        assert_eq!(r.hosts_added + r.folders_added, 0);
    }

    #[test]
    fn existing_items_are_skipped_or_updated_and_reimport_adds_nothing() {
        let s = sample();
        let pkg = export(&s.doc, None, Parts::ALL).unwrap();
        // Odbiorca ma już to drzewo, ale zmienił nazwę, hasło, ulubione i przeniósł hosta.
        let mut doc = s.doc.clone();
        {
            let h = doc.tree.hosts.iter_mut().find(|h| h.id == s.db).unwrap();
            h.name = "moja baza".into();
            h.favorite = false;
            h.folder = None;
            h.fields.password = Some("moje".into());
        }
        let changed = doc.clone();
        let sum = summarize(&doc, &pkg);
        assert_eq!((sum.folders_existing, sum.hosts_existing), (2, 3));
        assert_eq!((sum.folders_new, sum.hosts_new, sum.trusted_new), (0, 0, 0));
        // Pomijanie niczego nie zmienia.
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!(doc, changed);
        assert_eq!(r.unchanged, 5);
        // Aktualizacja bez haseł: nazwa i położenie z pakietu, hasło i ulubione lokalne.
        let parts = Parts {
            passwords: false,
            ..Parts::ALL
        };
        let r = import(&mut doc, &pkg, parts, Existing::Update).unwrap();
        assert_eq!((r.hosts_updated, r.unchanged), (1, 4));
        let db = host(&doc, s.db);
        assert_eq!(db.name, "db");
        assert_eq!(db.folder, Some(s.prod));
        assert_eq!(db.fields.password.as_deref(), Some("moje"));
        assert!(!db.favorite);
        // Ponowny import tego samego pliku nie dodaje niczego i niczego nie zmienia.
        let again = doc.clone();
        let r = import(&mut doc, &pkg, parts, Existing::Update).unwrap();
        assert_eq!(doc, again);
        assert_eq!(r.unchanged, 5);
        assert_eq!(doc.tree.hosts.len(), 3);
        assert_eq!(doc.tree.folders.len(), 2);
    }

    #[test]
    fn update_replaces_whole_category_including_empty_values() {
        let s = sample();
        let pkg = export(&s.doc, None, Parts::ALL).unwrap();
        let mut doc = s.doc.clone();
        // Lokalnie bastion dostał hasło i port, których pakiet nie ma.
        let b = doc
            .tree
            .hosts
            .iter_mut()
            .find(|h| h.id == s.bastion)
            .unwrap();
        b.fields.password = Some("lokalne".into());
        b.fields.port = Some(22022);
        let parts = Parts {
            passwords: true,
            ..Default::default()
        };
        import(&mut doc, &pkg, parts, Existing::Update).unwrap();
        let b = host(&doc, s.bastion);
        assert_eq!(b.fields.password, None);
        assert_eq!(b.fields.port, Some(22022));
    }

    #[test]
    fn partial_package_keeps_existing_root_in_place_and_adds_new_root_at_top() {
        let s = sample();
        let pkg = export(&s.doc, Some(s.prod), Parts::default()).unwrap();
        // Odbiorca ma ten katalog w innym miejscu: aktualizacja go nie przenosi.
        let mut doc = s.doc.clone();
        let other = doc.tree.add_folder("Inne", None).unwrap();
        doc.tree.move_folder(s.prod, Some(other)).unwrap();
        import(&mut doc, &pkg, Parts::default(), Existing::Update).unwrap();
        assert_eq!(doc.tree.folder(s.prod).unwrap().parent, Some(other));
        // Odbiorca bez tego katalogu dostaje go na najwyższym poziomie.
        let mut empty = Document::default();
        let r = import(&mut empty, &pkg, Parts::default(), Existing::Skip).unwrap();
        assert_eq!((r.folders_added, r.hosts_added), (1, 2));
        assert_eq!(empty.tree.folder(s.prod).unwrap().parent, None);
        assert_eq!(host(&empty, s.db).folder, Some(s.prod));
    }

    #[test]
    fn missing_bastion_and_missing_parent_are_dropped() {
        let s = sample();
        // Sam host db z bastionem ustawionym wprost i katalogiem, którego odbiorca nie ma.
        let mut pkg = export(&s.doc, None, Parts::ALL).unwrap();
        pkg.folders.clear();
        pkg.hosts.retain(|h| h.id == s.db);
        pkg.hosts[0].fields.jump_host = Some(s.bastion);
        let mut doc = Document::default();
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!(r.jumps_dropped, 1);
        let db = host(&doc, s.db);
        assert_eq!(db.fields.jump_host, None);
        assert_eq!(db.folder, None);
        // Odbiorca, który ma bastion o tym identyfikatorze, zachowuje odwołanie.
        let mut doc = Document::default();
        doc.tree.hosts.push(host(&s.doc, s.bastion).clone());
        doc.tree.hosts[0].folder = None;
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!(r.jumps_dropped, 0);
        assert_eq!(host(&doc, s.db).fields.jump_host, Some(s.bastion));
    }

    #[test]
    fn folder_cycle_from_package_or_from_merge_is_rejected() {
        let s = sample();
        // Cykl w samym pakiecie.
        let mut pkg = export(&s.doc, None, Parts::default()).unwrap();
        let firma = pkg.folders.iter_mut().find(|f| f.id == s.firma).unwrap();
        firma.parent = Some(s.prod);
        let mut doc = Document::default();
        assert_eq!(
            import(&mut doc, &pkg, Parts::default(), Existing::Skip).err(),
            Some(Error::FolderCycle)
        );
        // Cykl z połączenia: lokalnie Firma leży w Produkcji, pakiet mówi odwrotnie.
        let pkg = export(&s.doc, None, Parts::default()).unwrap();
        let mut doc = Document::default();
        doc.tree.folders.push(Folder {
            id: s.prod,
            name: "Produkcja".into(),
            parent: None,
            fields: Fields::default(),
        });
        doc.tree.folders.push(Folder {
            id: s.firma,
            name: "Firma".into(),
            parent: Some(s.prod),
            fields: Fields::default(),
        });
        // Pominięcie istniejących zostawia lokalną strukturę: bez cyklu.
        let mut skip = doc.clone();
        import(&mut skip, &pkg, Parts::default(), Existing::Skip).unwrap();
        // Aktualizacja przenosi katalogi według pakietu: Produkcja do Firmy, Firma na górę.
        let mut update = doc.clone();
        import(&mut update, &pkg, Parts::default(), Existing::Update).unwrap();
        assert_eq!(update.tree.folder(s.firma).unwrap().parent, None);
        assert_eq!(update.tree.folder(s.prod).unwrap().parent, Some(s.firma));
        // Pakiet częściowy nie rusza położenia swojego katalogu głównego, więc gdy lokalnie
        // Firma leży w Produkcji, a pakiet (od Firmy) wkłada Produkcję do Firmy, powstaje cykl.
        let pkg = export(&s.doc, Some(s.firma), Parts::default()).unwrap();
        let mut cyc = doc.clone();
        assert_eq!(
            import(&mut cyc, &pkg, Parts::default(), Existing::Update).err(),
            Some(Error::FolderCycle)
        );
    }

    #[test]
    fn trusted_keys_are_added_once_and_conflicts_keep_local() {
        let s = sample();
        let pkg = export(&s.doc, None, Parts::ALL).unwrap();
        let mut doc = Document::default();
        // Odbiorca zna już ten host pod innym odciskiem.
        doc.trusted_keys.push(TrustedKey {
            protocol: Protocol::Ssh,
            host: "10.0.0.5".into(),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:inny".into(),
        });
        assert_eq!(summarize(&doc, &pkg).trusted_new, 1);
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!((r.trusted_added, r.trusted_conflicts), (1, 1));
        assert_eq!(doc.trusted_keys.len(), 2);
        assert_eq!(
            doc.trusted(Protocol::Ssh, "10.0.0.5", 2222)[0].fingerprint,
            "SHA256:inny"
        );
        let r = import(&mut doc, &pkg, Parts::ALL, Existing::Skip).unwrap();
        assert_eq!((r.trusted_added, r.trusted_conflicts), (0, 1));
        assert_eq!(doc.trusted_keys.len(), 2);
    }

    #[test]
    fn check_rejects_bad_packages() {
        let s = sample();
        let good = export(&s.doc, None, Parts::ALL).unwrap();
        assert_eq!(check(&good), Ok(()));
        let mut p = good.clone();
        p.format = FORMAT + 1;
        assert_eq!(check(&p), Err(Error::UnsupportedFormat(FORMAT + 1)));
        let mut p = good.clone();
        p.hosts.push(p.hosts[0].clone());
        assert_eq!(check(&p), Err(Error::DuplicateId));
        let mut p = good.clone();
        p.folders.push(p.folders[0].clone());
        assert_eq!(check(&p), Err(Error::DuplicateId));
        let mut p = good.clone();
        p.hosts[0].name = "  ".into();
        assert_eq!(check(&p), Err(Error::BadName));
        let mut p = good.clone();
        p.hosts[0].address = "a\nb".into();
        assert_eq!(check(&p), Err(Error::BadName));
        let mut p = good.clone();
        p.folders[0].name = "x".repeat(MAX_NAME + 1);
        assert_eq!(check(&p), Err(Error::BadName));
        let mut p = good.clone();
        p.hosts[0].notes = "x".repeat(MAX_NOTES + 1);
        assert_eq!(check(&p), Err(Error::BadName));
        let mut p = good.clone();
        let one = p.hosts[0].clone();
        p.hosts = (0..=MAX_ITEMS)
            .map(|_| Host {
                id: Id::new_v4(),
                ..one.clone()
            })
            .collect();
        assert_eq!(check(&p), Err(Error::TooLarge));
        // Błędny pakiet nie przechodzi też przez import.
        let mut doc = Document::default();
        let mut p = good.clone();
        p.format = 0;
        assert_eq!(
            import(&mut doc, &p, Parts::ALL, Existing::Skip).err(),
            Some(Error::UnsupportedFormat(0))
        );
        assert_eq!(doc, Document::default());
    }

    #[test]
    fn package_survives_json_and_old_readers_fields_default() {
        let s = sample();
        let pkg = export(&s.doc, Some(s.prod), Parts::ALL).unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        let back: Package = serde_json::from_str(&json).unwrap();
        assert!(back == pkg);
        // Minimalny pakiet: brakujące listy i kategorie są puste.
        let min: Package = serde_json::from_str(r#"{"format":1}"#).unwrap();
        assert_eq!(min.parts, Parts::default());
        assert!(min.folders.is_empty() && min.hosts.is_empty() && min.trusted_keys.is_empty());
        assert_eq!(min.root, None);
    }
}
