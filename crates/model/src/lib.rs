//! Drzewo katalogów i hostów z dziedziczeniem ustawień.
//!
//! Kolejność rozwiązywania pola: host -> katalog -> katalog nadrzędny -> ... -> ustawienia domyślne
//! -> wartość wbudowana. Pole puste (`None`) oznacza dziedziczenie.

use std::collections::{BTreeMap, HashMap, HashSet};

pub mod link;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type Id = Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("nie ma takiego katalogu")]
    NoFolder(Id),
    #[error("nie ma takiego hosta")]
    NoHost(Id),
    #[error("przeniesienie utworzyłoby cykl katalogów")]
    FolderCycle,
    #[error("cykl w łańcuchu bastionów")]
    JumpCycle,
    #[error("bastion musi być hostem SSH")]
    JumpNotSsh,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Rdp,
}

impl Protocol {
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Rdp => 3389,
        }
    }
}

/// Skąd pochodzi wartość pola.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum Source {
    Host,
    Folder(Id),
    Defaults,
    /// Żadna warstwa nie ustawiła pola (wartość wbudowana albo brak).
    Builtin,
}

macro_rules! fields {
    ($($name:ident : $ty:ty),* $(,)?) => {
        /// Nadpisywalne ustawienia. `None` = dziedzicz.
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        pub struct Fields {
            $(#[serde(default, skip_serializing_if = "Option::is_none")] pub $name: Option<$ty>,)*
        }

        /// Pola ze znanym źródłem wartości, do oznaczania dziedziczenia w interfejsie.
        #[derive(Debug, Clone, Default, PartialEq, Serialize)]
        pub struct Sources {
            $(pub $name: Option<Source>,)*
        }

        #[cfg(test)]
        impl Sources {
            fn all(&self, s: Source) -> bool {
                true $(&& self.$name == Some(s))*
            }
        }

        impl Fields {
            /// Oznacza pola ustawione bezpośrednio (na hoście) jako własne. Lista pól pochodzi z tego
            /// samego makra, więc nowe pole nie może zostać tu pominięte.
            fn mark_own(&self, src: &mut Sources) {
                $(if self.$name.is_some() {
                    src.$name = Some(Source::Host);
                })*
            }

            /// Wszystkie pola ustawione (do testów kompletności).
            #[cfg(test)]
            fn all_set() -> Self {
                Self { $($name: Some(<$ty>::default()),)* }
            }

            /// Uzupełnia puste pola wartościami z `lower`, zapisując źródło w `src`.
            fn fill_from(&mut self, lower: &Fields, origin: Source, src: &mut Sources) {
                $(if self.$name.is_none() {
                    if let Some(v) = &lower.$name {
                        self.$name = Some(v.clone());
                        src.$name = Some(origin);
                    }
                })*
            }
        }
    };
}

fields! {
    port: u16,
    username: String,
    domain: String,
    // Sekret: nie wolno go logować.
    password: String,
    jump_host: Id,
    terminal_scheme: String,
    rdp_multimon: bool,
    rdp_kerberos: bool,
    rdp_kdc: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Folder {
    pub id: Id,
    pub name: String,
    pub parent: Option<Id>,
    #[serde(default)]
    pub fields: Fields,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub id: Id,
    pub name: String,
    pub address: String,
    pub protocol: Protocol,
    pub folder: Option<Id>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub fields: Fields,
}

/// Wynik rozwiązywania dziedziczenia.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resolved {
    pub fields: Fields,
    pub sources: Sources,
    /// Efektywny port (z uwzględnieniem domyślnego portu protokołu).
    pub port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tree {
    #[serde(default)]
    pub defaults: Fields,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub hosts: Vec<Host>,
}

impl Tree {
    pub fn folder(&self, id: Id) -> Option<&Folder> {
        self.folders.iter().find(|f| f.id == id)
    }

    pub fn host(&self, id: Id) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }

    pub fn add_folder(&mut self, name: impl Into<String>, parent: Option<Id>) -> Result<Id> {
        if let Some(p) = parent {
            self.folder(p).ok_or(Error::NoFolder(p))?;
        }
        let id = Uuid::new_v4();
        self.folders.push(Folder {
            id,
            name: name.into(),
            parent,
            fields: Fields::default(),
        });
        Ok(id)
    }

    pub fn add_host(
        &mut self,
        name: impl Into<String>,
        address: impl Into<String>,
        protocol: Protocol,
        folder: Option<Id>,
    ) -> Result<Id> {
        if let Some(f) = folder {
            self.folder(f).ok_or(Error::NoFolder(f))?;
        }
        let id = Uuid::new_v4();
        self.hosts.push(Host {
            id,
            name: name.into(),
            address: address.into(),
            protocol,
            folder,
            favorite: false,
            notes: String::new(),
            fields: Fields::default(),
        });
        Ok(id)
    }

    pub fn move_host(&mut self, host: Id, folder: Option<Id>) -> Result<()> {
        if let Some(f) = folder {
            self.folder(f).ok_or(Error::NoFolder(f))?;
        }
        self.hosts
            .iter_mut()
            .find(|h| h.id == host)
            .ok_or(Error::NoHost(host))?
            .folder = folder;
        Ok(())
    }

    /// Przenosi katalog; odrzuca przeniesienie do samego siebie lub własnego potomka.
    pub fn move_folder(&mut self, folder: Id, parent: Option<Id>) -> Result<()> {
        self.folder(folder).ok_or(Error::NoFolder(folder))?;
        if let Some(p) = parent {
            self.folder(p).ok_or(Error::NoFolder(p))?;
            let mut cur = Some(p);
            let mut seen = HashSet::new();
            while let Some(c) = cur {
                if c == folder {
                    return Err(Error::FolderCycle);
                }
                if !seen.insert(c) {
                    return Err(Error::FolderCycle);
                }
                cur = self.folder(c).and_then(|f| f.parent);
            }
        }
        self.folders
            .iter_mut()
            .find(|f| f.id == folder)
            .expect("sprawdzone")
            .parent = parent;
        Ok(())
    }

    /// Usuwa katalog razem z podkatalogami i hostami w nich. Zwraca usunięte hosty.
    /// Odwołania `jump_host` do usuniętych hostów są czyszczone.
    pub fn remove_folder(&mut self, folder: Id) -> Result<Vec<Host>> {
        self.folder(folder).ok_or(Error::NoFolder(folder))?;
        let mut doomed: HashSet<Id> = HashSet::from([folder]);
        loop {
            let before = doomed.len();
            for f in &self.folders {
                if f.parent.is_some_and(|p| doomed.contains(&p)) {
                    doomed.insert(f.id);
                }
            }
            if doomed.len() == before {
                break;
            }
        }
        self.folders.retain(|f| !doomed.contains(&f.id));
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.hosts)
            .into_iter()
            .partition(|h| h.folder.is_some_and(|f| doomed.contains(&f)));
        self.hosts = kept;
        let gone_ids: HashSet<Id> = gone.iter().map(|h| h.id).collect();
        self.clear_jump_refs(&gone_ids);
        Ok(gone)
    }

    pub fn remove_host(&mut self, host: Id) -> Result<Host> {
        let i = self
            .hosts
            .iter()
            .position(|h| h.id == host)
            .ok_or(Error::NoHost(host))?;
        let h = self.hosts.remove(i);
        self.clear_jump_refs(&HashSet::from([host]));
        Ok(h)
    }

    fn clear_jump_refs(&mut self, gone: &HashSet<Id>) {
        let clear = |f: &mut Fields| {
            if f.jump_host.is_some_and(|j| gone.contains(&j)) {
                f.jump_host = None;
            }
        };
        clear(&mut self.defaults);
        self.folders.iter_mut().for_each(|f| clear(&mut f.fields));
        self.hosts.iter_mut().for_each(|h| clear(&mut h.fields));
    }

    /// Rozwiązuje dziedziczenie dla hosta.
    pub fn resolve(&self, host: Id) -> Result<Resolved> {
        let h = self.host(host).ok_or(Error::NoHost(host))?;
        let mut fields = h.fields.clone();
        let mut sources = Sources::default();
        // Pola ustawione na hoście mają źródło Host.
        h.fields.mark_own(&mut sources);
        let mut seen = HashSet::new();
        let mut cur = h.folder;
        while let Some(fid) = cur {
            if !seen.insert(fid) {
                return Err(Error::FolderCycle);
            }
            let f = self.folder(fid).ok_or(Error::NoFolder(fid))?;
            fields.fill_from(&f.fields, Source::Folder(fid), &mut sources);
            cur = f.parent;
        }
        fields.fill_from(&self.defaults, Source::Defaults, &mut sources);
        // Bastion ustawiony w katalogu obejmuje też sam bastion, jeśli leży w tym katalogu: on łączy
        // się bezpośrednio (inaczej cały katalog dostawałby cykl).
        if fields.jump_host == Some(host) && sources.jump_host != Some(Source::Host) {
            fields.jump_host = None;
            sources.jump_host = None;
        }
        let port = fields.port.unwrap_or_else(|| h.protocol.default_port());
        Ok(Resolved {
            fields,
            sources,
            port,
        })
    }

    /// Łańcuch bastionów od pierwszego (najbliższego klientowi) do ostatniego przed celem.
    pub fn jump_chain(&self, host: Id) -> Result<Vec<Id>> {
        let mut chain = Vec::new();
        let mut seen = HashSet::from([host]);
        let mut cur = self.resolve(host)?.fields.jump_host;
        while let Some(j) = cur {
            if !seen.insert(j) {
                return Err(Error::JumpCycle);
            }
            if self.host(j).ok_or(Error::NoHost(j))?.protocol != Protocol::Ssh {
                return Err(Error::JumpNotSsh);
            }
            chain.push(j);
            cur = self.resolve(j)?.fields.jump_host;
        }
        chain.reverse();
        Ok(chain)
    }

    /// Ścieżka katalogów od korzenia do hosta (nazwy), do wyświetlania.
    pub fn path_of(&self, host: Id) -> Result<Vec<String>> {
        let h = self.host(host).ok_or(Error::NoHost(host))?;
        let mut names = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = h.folder;
        while let Some(fid) = cur {
            if !seen.insert(fid) {
                return Err(Error::FolderCycle);
            }
            let f = self.folder(fid).ok_or(Error::NoFolder(fid))?;
            names.push(f.name.clone());
            cur = f.parent;
        }
        names.reverse();
        Ok(names)
    }

    /// Wyszukiwanie po nazwie, adresie i notatkach (bez rozróżniania wielkości liter).
    pub fn search(&self, query: &str) -> Vec<Id> {
        let q = query.to_lowercase();
        self.hosts
            .iter()
            .filter(|h| {
                h.name.to_lowercase().contains(&q)
                    || h.address.to_lowercase().contains(&q)
                    || h.notes.to_lowercase().contains(&q)
            })
            .map(|h| h.id)
            .collect()
    }

    /// Liczba hostów w katalogu i jego podkatalogach.
    pub fn host_counts(&self) -> HashMap<Id, usize> {
        let mut counts: HashMap<Id, usize> = HashMap::new();
        for h in &self.hosts {
            let mut cur = h.folder;
            let mut seen = HashSet::new();
            while let Some(fid) = cur {
                if !seen.insert(fid) {
                    break;
                }
                *counts.entry(fid).or_default() += 1;
                cur = self.folder(fid).and_then(|f| f.parent);
            }
        }
        counts
    }
}

/// Zaufany klucz hosta SSH albo certyfikat RDP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKey {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

/// Ustawienia aplikacji zapisywane w pliku (synchronizują się razem z hostami).
/// Pola dodane później mają `serde(default)`, żeby starsze pliki dalej się otwierały.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// "dark", "light" albo "system".
    pub theme: String,
    pub terminal_font_size: u8,
    /// Domyślny schemat terminala ("domyslny", "szary" albo "kontrast").
    #[serde(default = "default_terminal_scheme")]
    pub terminal_scheme: String,
    /// Nadpisane skróty: id akcji -> kombinacja, np. "quick_connect" -> "Ctrl+K".
    #[serde(default)]
    pub shortcuts: BTreeMap<String, String>,
}

fn default_terminal_scheme() -> String {
    "domyslny".into()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            terminal_font_size: 13,
            terminal_scheme: default_terminal_scheme(),
            shortcuts: BTreeMap::new(),
        }
    }
}

/// Cała zawartość zaszyfrowanego pliku.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Document {
    #[serde(default)]
    pub tree: Tree,
    #[serde(default)]
    pub trusted_keys: Vec<TrustedKey>,
    #[serde(default)]
    pub settings: Settings,
}

impl Document {
    pub fn trusted(&self, protocol: Protocol, host: &str, port: u16) -> Vec<&TrustedKey> {
        self.trusted_keys
            .iter()
            .filter(|k| {
                k.protocol == protocol && k.host.eq_ignore_ascii_case(host) && k.port == port
            })
            .collect()
    }

    /// Zapamiętuje klucz (zastępując poprzedni dla tego hosta i algorytmu).
    pub fn trust(&mut self, key: TrustedKey) {
        self.trusted_keys.retain(|k| {
            !(k.protocol == key.protocol
                && k.host.eq_ignore_ascii_case(&key.host)
                && k.port == key.port
                && k.algorithm == key.algorithm)
        });
        self.trusted_keys.push(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn tree_with_chain() -> (Tree, Id, Id, Id, Id) {
        let mut t = Tree::default();
        let root = t.add_folder("root", None).unwrap();
        let sub = t.add_folder("sub", Some(root)).unwrap();
        let h = t
            .add_host("srv", "10.0.0.1", Protocol::Ssh, Some(sub))
            .unwrap();
        (t, root, sub, h, Uuid::nil())
    }

    #[test]
    fn host_overrides_folder_overrides_defaults() {
        let (mut t, root, sub, h, _) = tree_with_chain();
        t.defaults.username = Some("def".into());
        t.defaults.domain = Some("DEF".into());
        t.folders
            .iter_mut()
            .find(|f| f.id == root)
            .unwrap()
            .fields
            .username = Some("root-user".into());
        t.folders
            .iter_mut()
            .find(|f| f.id == sub)
            .unwrap()
            .fields
            .domain = Some("SUB".into());
        let r = t.resolve(h).unwrap();
        assert_eq!(r.fields.username.as_deref(), Some("root-user"));
        assert_eq!(r.sources.username, Some(Source::Folder(root)));
        assert_eq!(r.fields.domain.as_deref(), Some("SUB"));
        assert_eq!(r.sources.domain, Some(Source::Folder(sub)));

        t.hosts[0].fields.username = Some("me".into());
        let r = t.resolve(h).unwrap();
        assert_eq!(r.fields.username.as_deref(), Some("me"));
        assert_eq!(r.sources.username, Some(Source::Host));
    }

    #[test]
    fn default_port_follows_protocol_and_source_is_none() {
        let (mut t, _, _, h, _) = tree_with_chain();
        assert_eq!(t.resolve(h).unwrap().port, 22);
        assert_eq!(t.resolve(h).unwrap().sources.port, None);
        t.hosts[0].protocol = Protocol::Rdp;
        assert_eq!(t.resolve(h).unwrap().port, 3389);
    }

    #[test]
    fn folder_cycle_rejected_on_move() {
        let (mut t, root, sub, _, _) = tree_with_chain();
        assert_eq!(t.move_folder(root, Some(sub)), Err(Error::FolderCycle));
        assert_eq!(t.move_folder(root, Some(root)), Err(Error::FolderCycle));
    }

    #[test]
    fn corrupted_folder_cycle_detected_on_resolve() {
        let (mut t, root, sub, h, _) = tree_with_chain();
        t.folders.iter_mut().find(|f| f.id == root).unwrap().parent = Some(sub);
        assert_eq!(t.resolve(h).unwrap_err(), Error::FolderCycle);
    }

    #[test]
    fn jump_chain_ordered_and_cycle_detected() {
        let mut t = Tree::default();
        let a = t.add_host("a", "a", Protocol::Ssh, None).unwrap();
        let b = t.add_host("b", "b", Protocol::Ssh, None).unwrap();
        let c = t.add_host("c", "c", Protocol::Ssh, None).unwrap();
        t.hosts[2].fields.jump_host = Some(b);
        t.hosts[1].fields.jump_host = Some(a);
        assert_eq!(t.jump_chain(c).unwrap(), vec![a, b]);
        t.hosts[0].fields.jump_host = Some(c);
        assert_eq!(t.jump_chain(c).unwrap_err(), Error::JumpCycle);
    }

    #[test]
    fn remove_folder_cascades_and_clears_jump_refs() {
        let (mut t, root, _, h, _) = tree_with_chain();
        let other = t.add_host("o", "o", Protocol::Ssh, None).unwrap();
        t.hosts
            .iter_mut()
            .find(|x| x.id == other)
            .unwrap()
            .fields
            .jump_host = Some(h);
        let gone = t.remove_folder(root).unwrap();
        assert_eq!(gone.len(), 1);
        assert!(t.folders.is_empty());
        assert_eq!(t.host(other).unwrap().fields.jump_host, None);
    }

    #[test]
    fn search_and_counts() {
        let (t, root, sub, _, _) = tree_with_chain();
        assert_eq!(t.search("SRV").len(), 1);
        assert_eq!(t.search("10.0.").len(), 1);
        assert!(t.search("nie ma").is_empty());
        let c = t.host_counts();
        assert_eq!((c[&root], c[&sub]), (1, 1));
    }

    #[test]
    fn trust_replaces_same_host_and_algorithm() {
        let mut d = Document::default();
        let k = |fp: &str| TrustedKey {
            protocol: Protocol::Ssh,
            host: "Srv".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            fingerprint: fp.into(),
        };
        d.trust(k("SHA256:a"));
        d.trust(k("SHA256:b"));
        let t = d.trusted(Protocol::Ssh, "srv", 22);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].fingerprint, "SHA256:b");
        assert!(d.trusted(Protocol::Rdp, "srv", 22).is_empty());
    }

    #[test]
    fn serde_round_trip_skips_empty_fields() {
        let (t, ..) = tree_with_chain();
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("password"));
        assert_eq!(serde_json::from_str::<Tree>(&json).unwrap(), t);
    }

    proptest! {
        /// Port wynika z pierwszej warstwy z ustawioną wartością: host, katalogi od najbliższego, domyślne.
        #[test]
        fn port_resolution_matches_reference(
            host_port in proptest::option::of(1u16..),
            folder_ports in proptest::collection::vec(proptest::option::of(1u16..), 0..6),
            default_port in proptest::option::of(1u16..),
        ) {
            let mut t = Tree::default();
            t.defaults.port = default_port;
            let mut parent = None;
            for (i, p) in folder_ports.iter().enumerate() {
                let id = t.add_folder(format!("f{i}"), parent).unwrap();
                t.folders.last_mut().unwrap().fields.port = *p;
                parent = Some(id);
            }
            let h = t.add_host("h", "h", Protocol::Ssh, parent).unwrap();
            t.hosts[0].fields.port = host_port;
            let expected = host_port
                .or_else(|| folder_ports.iter().rev().copied().flatten().next())
                .or(default_port)
                .unwrap_or(22);
            prop_assert_eq!(t.resolve(h).unwrap().port, expected);
        }
    }

    #[test]
    fn settings_keep_scheme_and_shortcuts_and_read_old_files() {
        let mut st = Settings {
            terminal_scheme: "szary".into(),
            ..Settings::default()
        };
        st.shortcuts
            .insert("quick_connect".into(), "Ctrl+Shift+K".into());
        let back: Settings = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
        // Plik zapisany przed dodaniem pól.
        let old: Settings =
            serde_json::from_str(r#"{"theme":"dark","terminal_font_size":14}"#).unwrap();
        assert_eq!(old.terminal_scheme, "domyslny");
        assert!(old.shortcuts.is_empty());
    }

    #[test]
    fn every_field_set_on_host_has_host_source() {
        let mut t = Tree::default();
        let h = t.add_host("h", "h", Protocol::Ssh, None).unwrap();
        t.hosts[0].fields = Fields::all_set();
        let r = t.resolve(h).unwrap();
        assert!(r.sources.all(Source::Host), "{:?}", r.sources);
    }

    #[test]
    fn bastion_inside_folder_with_that_bastion_connects_directly() {
        let mut t = Tree::default();
        let prod = t.add_folder("Prod", None).unwrap();
        let b = t
            .add_host("bastion", "b", Protocol::Ssh, Some(prod))
            .unwrap();
        let web = t.add_host("web", "w", Protocol::Ssh, Some(prod)).unwrap();
        t.folders[0].fields.jump_host = Some(b);
        assert_eq!(t.jump_chain(b).unwrap(), Vec::<Id>::new());
        assert_eq!(t.resolve(b).unwrap().sources.jump_host, None);
        assert_eq!(t.jump_chain(web).unwrap(), vec![b]);
        // Bastion ustawiony jawnie na sobie samym nadal jest błędem.
        t.hosts[0].fields.jump_host = Some(b);
        assert_eq!(t.jump_chain(b), Err(Error::JumpCycle));
    }

    #[test]
    fn rdp_host_cannot_be_a_bastion() {
        let mut t = Tree::default();
        let r = t.add_host("rdp", "r", Protocol::Rdp, None).unwrap();
        let s = t.add_host("ssh", "s", Protocol::Ssh, None).unwrap();
        t.hosts[1].fields.jump_host = Some(r);
        assert_eq!(t.jump_chain(s), Err(Error::JumpNotSsh));
    }
}
