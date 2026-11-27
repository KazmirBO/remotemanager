//! Porównanie dwóch wersji dokumentu (lokalnej i z folderu synchronizacji) do pokazania
//! użytkownikowi przed synchronizacją.
//!
//! Elementy są dopasowywane po identyfikatorach. Wynik nazywa różnice, ale nie niesie wartości pól
//! dziedziczonych: zmiana hasła, klucza albo polecenia jest tylko nazwą kategorii. Nazwy, adresy,
//! protokół i położenie interfejs zna i tak, więc dla nich wynik podaje obie wartości.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::transfer::{FieldPart, differing};
use crate::{Document, Folder, Host, Id, Protocol, Tree};

/// Po której stronie jest element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Tylko w wersji lokalnej.
    LocalOnly,
    /// Tylko w wersji z folderu.
    RemoteOnly,
    /// Po obu stronach, ale różny.
    Changed,
}

/// Jedna różnica w elemencie, który jest po obu stronach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Name {
        local: String,
        remote: String,
    },
    Address {
        local: String,
        remote: String,
    },
    Protocol {
        local: Protocol,
        remote: Protocol,
    },
    /// Położenie w drzewie: ścieżka katalogów, pusta na najwyższym poziomie.
    Location {
        local: String,
        remote: String,
    },
    Favorite,
    Notes,
    /// Kategoria pól dziedziczonych; bez wartości, bo może to być hasło albo klucz.
    Part {
        part: FieldPart,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    pub id: Id,
    /// Nazwa lokalna, a dla elementu tylko z folderu nazwa z folderu.
    pub name: String,
    /// Ścieżka katalogów po tej samej stronie co nazwa; pusta na najwyższym poziomie.
    pub path: String,
    /// Tylko hosty.
    pub address: Option<String>,
    /// Tylko hosty.
    pub protocol: Option<Protocol>,
    pub side: Side,
    /// Puste dla elementów istniejących tylko po jednej stronie.
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DocDiff {
    pub folders: Vec<Item>,
    pub hosts: Vec<Item>,
    /// Kategorie ustawień domyślnych drzewa, które się różnią.
    pub defaults: Vec<FieldPart>,
    pub trusted_local_only: usize,
    pub trusted_remote_only: usize,
    pub settings_differ: bool,
    /// Różni się wymóg dodatkowego składnika przy otwieraniu pliku (bez szczegółów).
    pub mfa_differ: bool,
}

impl DocDiff {
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty()
            && self.hosts.is_empty()
            && self.defaults.is_empty()
            && self.trusted_local_only == 0
            && self.trusted_remote_only == 0
            && !self.settings_differ
            && !self.mfa_differ
    }
}

/// Ścieżka nazw katalogów od najwyższego poziomu; odporna na cykl w danych.
fn folder_path(tree: &Tree, folder: Option<Id>) -> String {
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = folder;
    while let Some(id) = cur {
        if !seen.insert(id) {
            break;
        }
        let Some(f) = tree.folder(id) else { break };
        names.push(f.name.as_str());
        cur = f.parent;
    }
    names.reverse();
    names.join(" / ")
}

fn parts(a: &crate::Fields, b: &crate::Fields) -> impl Iterator<Item = Change> {
    differing(a, b)
        .into_iter()
        .map(|part| Change::Part { part })
}

fn folder_changes(local: &Tree, l: &Folder, remote: &Tree, r: &Folder) -> Vec<Change> {
    let mut out = Vec::new();
    if l.name != r.name {
        out.push(Change::Name {
            local: l.name.clone(),
            remote: r.name.clone(),
        });
    }
    if l.parent != r.parent {
        out.push(Change::Location {
            local: folder_path(local, l.parent),
            remote: folder_path(remote, r.parent),
        });
    }
    out.extend(parts(&l.fields, &r.fields));
    out
}

fn host_changes(local: &Tree, l: &Host, remote: &Tree, r: &Host) -> Vec<Change> {
    let mut out = Vec::new();
    if l.name != r.name {
        out.push(Change::Name {
            local: l.name.clone(),
            remote: r.name.clone(),
        });
    }
    if l.address != r.address {
        out.push(Change::Address {
            local: l.address.clone(),
            remote: r.address.clone(),
        });
    }
    if l.protocol != r.protocol {
        out.push(Change::Protocol {
            local: l.protocol,
            remote: r.protocol,
        });
    }
    if l.folder != r.folder {
        out.push(Change::Location {
            local: folder_path(local, l.folder),
            remote: folder_path(remote, r.folder),
        });
    }
    if l.favorite != r.favorite {
        out.push(Change::Favorite);
    }
    if l.notes != r.notes {
        out.push(Change::Notes);
    }
    out.extend(parts(&l.fields, &r.fields));
    out
}

fn folder_item(tree: &Tree, f: &Folder, side: Side, changes: Vec<Change>) -> Item {
    Item {
        id: f.id,
        name: f.name.clone(),
        path: folder_path(tree, f.parent),
        address: None,
        protocol: None,
        side,
        changes,
    }
}

fn host_item(tree: &Tree, h: &Host, side: Side, changes: Vec<Change>) -> Item {
    Item {
        id: h.id,
        name: h.name.clone(),
        path: folder_path(tree, h.folder),
        address: Some(h.address.clone()),
        protocol: Some(h.protocol),
        side,
        changes,
    }
}

fn sort(items: &mut [Item]) {
    items.sort_by_cached_key(|i| (i.path.to_lowercase(), i.name.to_lowercase(), i.id));
}

/// Różnice między wersją lokalną a wersją z folderu.
pub fn diff(local: &Document, remote: &Document) -> DocDiff {
    let (lt, rt) = (&local.tree, &remote.tree);

    let remote_folders: HashMap<Id, &Folder> = rt.folders.iter().map(|f| (f.id, f)).collect();
    let local_folder_ids: HashSet<Id> = lt.folders.iter().map(|f| f.id).collect();
    let mut folders = Vec::new();
    for l in &lt.folders {
        match remote_folders.get(&l.id) {
            None => folders.push(folder_item(lt, l, Side::LocalOnly, Vec::new())),
            Some(r) => {
                let changes = folder_changes(lt, l, rt, r);
                if !changes.is_empty() {
                    folders.push(folder_item(lt, l, Side::Changed, changes));
                }
            }
        }
    }
    for r in rt
        .folders
        .iter()
        .filter(|r| !local_folder_ids.contains(&r.id))
    {
        folders.push(folder_item(rt, r, Side::RemoteOnly, Vec::new()));
    }
    sort(&mut folders);

    let remote_hosts: HashMap<Id, &Host> = rt.hosts.iter().map(|h| (h.id, h)).collect();
    let local_host_ids: HashSet<Id> = lt.hosts.iter().map(|h| h.id).collect();
    let mut hosts = Vec::new();
    for l in &lt.hosts {
        match remote_hosts.get(&l.id) {
            None => hosts.push(host_item(lt, l, Side::LocalOnly, Vec::new())),
            Some(r) => {
                let changes = host_changes(lt, l, rt, r);
                if !changes.is_empty() {
                    hosts.push(host_item(lt, l, Side::Changed, changes));
                }
            }
        }
    }
    for r in rt.hosts.iter().filter(|r| !local_host_ids.contains(&r.id)) {
        hosts.push(host_item(rt, r, Side::RemoteOnly, Vec::new()));
    }
    sort(&mut hosts);

    DocDiff {
        folders,
        hosts,
        defaults: differing(&lt.defaults, &rt.defaults),
        trusted_local_only: local
            .trusted_keys
            .iter()
            .filter(|k| !remote.trusted_keys.contains(k))
            .count(),
        trusted_remote_only: remote
            .trusted_keys
            .iter()
            .filter(|k| !local.trusted_keys.contains(k))
            .count(),
        settings_differ: local.settings != remote.settings,
        mfa_differ: local.mfa != remote.mfa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fields, StoredKey, TrustedKey};

    struct Sample {
        doc: Document,
        firma: Id,
        prod: Id,
        db: Id,
        web: Id,
    }

    fn sample() -> Sample {
        let mut doc = Document::default();
        let t = &mut doc.tree;
        let firma = t.add_folder("Firma", None).unwrap();
        let prod = t.add_folder("Produkcja", Some(firma)).unwrap();
        let db = t
            .add_host("db", "10.0.0.5", Protocol::Ssh, Some(prod))
            .unwrap();
        let web = t
            .add_host("web", "10.0.0.6", Protocol::Ssh, Some(prod))
            .unwrap();
        let h = t.hosts.iter_mut().find(|h| h.id == db).unwrap();
        h.fields.password = Some("stare-haslo".into());
        h.fields.username = Some("postgres".into());
        doc.trusted_keys.push(TrustedKey {
            protocol: Protocol::Ssh,
            host: "10.0.0.5".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:db".into(),
        });
        Sample {
            doc,
            firma,
            prod,
            db,
            web,
        }
    }

    fn host_mut(doc: &mut Document, id: Id) -> &mut Host {
        doc.tree.hosts.iter_mut().find(|h| h.id == id).unwrap()
    }

    #[test]
    fn identical_documents_have_no_differences() {
        let s = sample();
        let d = diff(&s.doc, &s.doc.clone());
        assert!(d.is_empty());
        assert_eq!(d, DocDiff::default());
    }

    #[test]
    fn items_on_one_side_only() {
        let s = sample();
        let mut remote = s.doc.clone();
        // W folderze: nowy katalog z hostem, a host web usunięty.
        let test = remote.tree.add_folder("Test", Some(s.firma)).unwrap();
        let new = remote
            .tree
            .add_host("nowy", "10.0.1.1", Protocol::Rdp, Some(test))
            .unwrap();
        remote.tree.remove_host(s.web).unwrap();
        let d = diff(&s.doc, &remote);
        assert_eq!(d.folders.len(), 1);
        assert_eq!(d.folders[0].side, Side::RemoteOnly);
        assert_eq!(
            (d.folders[0].name.as_str(), d.folders[0].path.as_str()),
            ("Test", "Firma")
        );
        assert_eq!(d.hosts.len(), 2);
        let only_remote = d.hosts.iter().find(|h| h.id == new).unwrap();
        assert_eq!(only_remote.side, Side::RemoteOnly);
        assert_eq!(only_remote.path, "Firma / Test");
        assert_eq!(only_remote.address.as_deref(), Some("10.0.1.1"));
        assert_eq!(only_remote.protocol, Some(Protocol::Rdp));
        assert!(only_remote.changes.is_empty());
        let only_local = d.hosts.iter().find(|h| h.id == s.web).unwrap();
        assert_eq!(only_local.side, Side::LocalOnly);
        assert_eq!(only_local.path, "Firma / Produkcja");
        // Odwrócenie stron zamienia tylko strony.
        let back = diff(&remote, &s.doc);
        assert_eq!(
            back.hosts.iter().find(|h| h.id == new).unwrap().side,
            Side::LocalOnly
        );
        assert_eq!(
            back.hosts.iter().find(|h| h.id == s.web).unwrap().side,
            Side::RemoteOnly
        );
    }

    #[test]
    fn changed_host_lists_each_kind_of_change_without_secret_values() {
        let s = sample();
        let mut remote = s.doc.clone();
        {
            let h = host_mut(&mut remote, s.db);
            h.name = "baza".into();
            h.address = "10.0.0.50".into();
            h.protocol = Protocol::Rdp;
            h.folder = None;
            h.favorite = true;
            h.notes = "tajna notatka".into();
            h.fields.password = Some("nowe-haslo".into());
            h.fields.port = Some(3390);
            h.fields.ssh_login_command = Some("sudo -i".into());
            h.fields.ssh_key = Some(StoredKey {
                openssh: "KLUCZ".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:x".into(),
            });
        }
        let d = diff(&s.doc, &remote);
        assert!(d.folders.is_empty());
        assert_eq!(d.hosts.len(), 1);
        let item = &d.hosts[0];
        assert_eq!(item.side, Side::Changed);
        // Nazwa, adres i położenie pozycji są lokalne.
        assert_eq!(
            (item.name.as_str(), item.path.as_str()),
            ("db", "Firma / Produkcja")
        );
        assert_eq!(
            item.changes,
            vec![
                Change::Name {
                    local: "db".into(),
                    remote: "baza".into()
                },
                Change::Address {
                    local: "10.0.0.5".into(),
                    remote: "10.0.0.50".into()
                },
                Change::Protocol {
                    local: Protocol::Ssh,
                    remote: Protocol::Rdp
                },
                Change::Location {
                    local: "Firma / Produkcja".into(),
                    remote: String::new()
                },
                Change::Favorite,
                Change::Notes,
                Change::Part {
                    part: FieldPart::Passwords
                },
                Change::Part {
                    part: FieldPart::SshKeys
                },
                Change::Part {
                    part: FieldPart::Options
                },
                Change::Part {
                    part: FieldPart::LoginCommand
                },
            ]
        );
        // W wyniku nie ma żadnej wartości sekretu ani treści notatki czy polecenia.
        let json = serde_json::to_string(&d).unwrap();
        for secret in [
            "stare-haslo",
            "nowe-haslo",
            "KLUCZ",
            "sudo -i",
            "tajna notatka",
            "postgres",
        ] {
            assert!(!json.contains(secret), "{secret} w wyniku: {json}");
        }
        assert!(
            json.contains(r#"{"kind":"part","part":"passwords"}"#),
            "{json}"
        );
        assert!(json.contains(r#""side":"changed""#), "{json}");
    }

    #[test]
    fn changed_folder_defaults_trusted_keys_and_settings() {
        let s = sample();
        let mut remote = s.doc.clone();
        {
            let f = remote
                .tree
                .folders
                .iter_mut()
                .find(|f| f.id == s.prod)
                .unwrap();
            f.name = "Prod".into();
            f.parent = None;
            f.fields.username = Some("admin".into());
        }
        remote.tree.defaults = Fields {
            port: Some(2222),
            ..Default::default()
        };
        remote.trusted_keys.clear();
        remote.trusted_keys.push(TrustedKey {
            protocol: Protocol::Rdp,
            host: "pc".into(),
            port: 3389,
            algorithm: "x509".into(),
            fingerprint: "SHA256:pc".into(),
        });
        remote.settings.theme = "light".into();
        let d = diff(&s.doc, &remote);
        assert_eq!(d.folders.len(), 1);
        assert_eq!(
            d.folders[0].changes,
            vec![
                Change::Name {
                    local: "Produkcja".into(),
                    remote: "Prod".into()
                },
                Change::Location {
                    local: "Firma".into(),
                    remote: String::new()
                },
                Change::Part {
                    part: FieldPart::Usernames
                },
            ]
        );
        // Przeniesienie katalogu nie zmienia hostów w nim (ich katalog to ten sam identyfikator).
        assert!(d.hosts.is_empty());
        assert_eq!(d.defaults, vec![FieldPart::Options]);
        assert_eq!((d.trusted_local_only, d.trusted_remote_only), (1, 1));
        assert!(d.settings_differ);
        assert!(!d.mfa_differ);
        assert!(!d.is_empty());
        // Sam wymóg dodatkowego składnika też jest różnicą, a jego sekret nie trafia do wyniku.
        let mut with_totp = s.doc.clone();
        with_totp.mfa.totp = Some(crate::mfa::Totp::new(b"sekret-totp-12345678".to_vec(), &[]));
        let d = diff(&s.doc, &with_totp);
        assert!(d.mfa_differ && !d.is_empty());
        assert!(d.hosts.is_empty() && d.folders.is_empty());
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("sekret") && !json.contains("115"), "{json}");
    }

    #[test]
    fn output_is_sorted_and_survives_folder_cycle() {
        let s = sample();
        let mut remote = s.doc.clone();
        for name in ["zebra", "Alfa", "beta"] {
            remote
                .tree
                .add_host(name, "x", Protocol::Ssh, None)
                .unwrap();
        }
        let d = diff(&s.doc, &remote);
        let names: Vec<&str> = d.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Alfa", "beta", "zebra"]);
        // Cykl katalogów w danych z folderu nie zapętla porównania.
        let mut cyc = s.doc.clone();
        cyc.tree
            .folders
            .iter_mut()
            .find(|f| f.id == s.firma)
            .unwrap()
            .parent = Some(s.prod);
        let d = diff(&s.doc, &cyc);
        assert_eq!(d.folders.len(), 1);
        assert!(matches!(d.folders[0].changes[0], Change::Location { .. }));
    }
}
