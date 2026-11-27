//! Lista hostów w pliku CSV jako pakiet importu.
//!
//! Plik ma wiersz nagłówka i kolumny `nazwa`, `adres`, `protokol` oraz opcjonalnie `katalog`
//! (ścieżka katalogów rozdzielona ukośnikiem, np. `Serwery/Bazy`). Separatorem jest przecinek,
//! średnik albo tabulator (rozpoznawany z nagłówka), pola mogą być w cudzysłowach. Taka lista nie
//! niesie haseł ani opcji: pakiet ma tylko nazwy, adresy, protokół i strukturę katalogów.
//!
//! Identyfikatory są wyliczane z adresu hosta i ze ścieżki katalogu, więc ponowny import odświeżonej
//! listy aktualizuje te same hosty zamiast je dublować, także gdy lista powstała innym narzędziem
//! liczącym identyfikatory tak samo.

use std::collections::{BTreeMap, HashSet};

use sha2::{Digest, Sha256};

use crate::transfer::{self, Package, Parts};
use crate::{Fields, Folder, Host, Id, Protocol};

/// Największy przyjmowany tekst CSV (w bajtach).
pub const MAX_CSV: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("plik jest za duży")]
    TooLarge,
    #[error("plik nie jest tekstem w kodowaniu UTF-8 (zapisz go jako UTF-8)")]
    NotText,
    #[error("plik jest pusty albo nie ma wiersza nagłówka")]
    Empty,
    #[error("brak kolumny {0} w nagłówku (wymagane: nazwa, adres, protokol; opcjonalnie: katalog)")]
    MissingColumn(&'static str),
    #[error("wiersz {row}: {reason}")]
    Row { row: usize, reason: &'static str },
    #[error("plik nie zawiera żadnego hosta")]
    NoHosts,
}

/// Stały identyfikator z rodzaju i klucza (bez rozróżniania wielkości liter).
fn stable_id(kind: &str, key: &str) -> Id {
    let digest = Sha256::digest(format!("mrm-import:{kind}:{}", key.to_lowercase()).as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    // Bity wersji i wariantu jak w UUID, żeby wartość była poprawnym identyfikatorem.
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    Id::from_bytes(b)
}

/// Identyfikator hosta z listy: zależy tylko od adresu.
pub fn host_id(address: &str) -> Id {
    stable_id("host", address)
}

/// Identyfikator katalogu z listy: zależy od pełnej ścieżki nazw.
pub fn folder_id(path: &[String]) -> Id {
    stable_id("folder", &path.join("/"))
}

/// Separator z wiersza nagłówka: ten ze średnika, przecinka i tabulatora, który występuje najczęściej
/// poza cudzysłowami.
fn delimiter(header: &str) -> char {
    let mut counts = [(',', 0usize), (';', 0), ('\t', 0)];
    let mut quoted = false;
    for c in header.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted {
            for (d, n) in &mut counts {
                if c == *d {
                    *n += 1;
                }
            }
        }
    }
    counts
        .iter()
        .rev()
        .max_by_key(|(_, n)| *n)
        .map(|(d, _)| *d)
        .unwrap_or(',')
}

/// Dzieli tekst na rekordy i pola. Pole w cudzysłowach może zawierać separator, koniec wiersza
/// i podwojony cudzysłów. Zwraca też numer wiersza pliku, w którym rekord się zaczyna.
fn records(text: &str, delim: char) -> Result<Vec<(usize, Vec<String>)>, Error> {
    let mut out = Vec::new();
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut line = 1usize;
    let mut start = 1usize;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                '\n' => {
                    line += 1;
                    field.push(c);
                }
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            '\r' => {}
            '\n' => {
                fields.push(std::mem::take(&mut field));
                out.push((start, std::mem::take(&mut fields)));
                line += 1;
                start = line;
            }
            c if c == delim => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    if quoted {
        return Err(Error::Row {
            row: start,
            reason: "niezamknięty cudzysłów",
        });
    }
    if !field.is_empty() || !fields.is_empty() {
        fields.push(field);
        out.push((start, fields));
    }
    Ok(out)
}

/// Nazwa kolumny bez wielkości liter i polskich znaków: `Protokół` to `protokol`.
fn column(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace('ó', "o")
        .replace('ł', "l")
}

fn find(header: &[String], names: &[&str]) -> Option<usize> {
    header
        .iter()
        .position(|h| names.contains(&column(h).as_str()))
}

/// Buduje pakiet importu z tekstu CSV.
pub fn package_from_csv(text: &str) -> Result<Package, Error> {
    if text.len() > MAX_CSV {
        return Err(Error::TooLarge);
    }
    let text = text.trim_start_matches('\u{feff}');
    // Znak zerowy to plik binarny albo UTF-16 odczytany jako bajty.
    if text.contains('\0') {
        return Err(Error::NotText);
    }
    let header_line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or(Error::Empty)?;
    let delim = delimiter(header_line);
    let mut rows = records(text, delim)?
        .into_iter()
        .filter(|(_, f)| f.iter().any(|v| !v.trim().is_empty()));
    let (_, header) = rows.next().ok_or(Error::Empty)?;
    let name_col = find(&header, &["nazwa", "name"]).ok_or(Error::MissingColumn("nazwa"))?;
    let addr_col =
        find(&header, &["adres", "address", "host"]).ok_or(Error::MissingColumn("adres"))?;
    let proto_col =
        find(&header, &["protokol", "protocol"]).ok_or(Error::MissingColumn("protokol"))?;
    let folder_col = find(&header, &["katalog", "folder"]);

    // Ścieżka katalogu -> identyfikator; BTreeMap daje stałą kolejność (rodzic przed dzieckiem).
    let mut folders: BTreeMap<Vec<String>, Id> = BTreeMap::new();
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    for (row, fields) in rows {
        let get = |i: usize| fields.get(i).map(|v| v.trim()).unwrap_or("");
        let fail = |reason| Error::Row { row, reason };
        let name = get(name_col);
        let address = get(addr_col);
        if name.is_empty() {
            return Err(fail("brak nazwy"));
        }
        if address.is_empty() {
            return Err(fail("brak adresu"));
        }
        let protocol = match get(proto_col).to_lowercase().as_str() {
            "ssh" => Protocol::Ssh,
            "rdp" => Protocol::Rdp,
            _ => return Err(fail("protokół musi być ssh albo rdp")),
        };
        if !seen.insert(address.to_lowercase()) {
            return Err(fail("adres powtarza się we wcześniejszym wierszu"));
        }
        let path: Vec<String> = folder_col
            .map(get)
            .unwrap_or("")
            .split('/')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        for depth in 1..=path.len() {
            let key = path[..depth].to_vec();
            let id = folder_id(&key);
            folders.entry(key).or_insert(id);
        }
        hosts.push(Host {
            id: host_id(address),
            name: name.to_owned(),
            address: address.to_owned(),
            protocol,
            folder: folders.get(&path).copied(),
            favorite: false,
            notes: String::new(),
            fields: Fields::default(),
        });
    }
    if hosts.is_empty() {
        return Err(Error::NoHosts);
    }
    // Jeden katalog najwyższego poziomu staje się katalogiem głównym pakietu: jeśli odbiorca
    // przeniósł go w inne miejsce drzewa, ponowny import go nie cofnie.
    let mut tops = folders.keys().filter(|k| k.len() == 1);
    let root = match (tops.next(), tops.next()) {
        (Some(only), None) => folders.get(only).copied(),
        _ => None,
    };
    let pkg = Package {
        format: transfer::FORMAT,
        parts: Parts::default(),
        root,
        folders: folders
            .iter()
            .map(|(path, id)| Folder {
                id: *id,
                name: path.last().expect("niepusta ścieżka").clone(),
                parent: (path.len() > 1).then(|| folders[&path[..path.len() - 1]]),
                fields: Fields::default(),
            })
            .collect(),
        hosts,
        trusted_keys: Vec::new(),
    };
    Ok(pkg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;
    use crate::transfer::{Existing, check, import};

    const SAMPLE: &str = "nazwa,adres,protokol,katalog\n\
        SRV-DC01,srv-dc01.example.com,rdp,Serwery/Kontrolery\n\
        SRV-SQL01,srv-sql01.example.com,RDP,Serwery/Bazy/Produkcja\n\
        jump,jump.example.com,ssh,Serwery\n\
        luzem,10.0.0.9,ssh,\n";

    fn folder<'a>(p: &'a Package, name: &str) -> &'a Folder {
        p.folders.iter().find(|f| f.name == name).unwrap()
    }

    fn host<'a>(p: &'a Package, name: &str) -> &'a Host {
        p.hosts.iter().find(|h| h.name == name).unwrap()
    }

    #[test]
    fn builds_hosts_and_folder_tree() {
        let p = package_from_csv(SAMPLE).unwrap();
        assert_eq!(check(&p), Ok(()));
        assert_eq!(p.parts, Parts::default());
        assert_eq!(p.hosts.len(), 4);
        let names: Vec<&str> = p.folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Serwery", "Bazy", "Produkcja", "Kontrolery"]);
        let serwery = folder(&p, "Serwery");
        assert_eq!(serwery.parent, None);
        assert_eq!(folder(&p, "Bazy").parent, Some(serwery.id));
        assert_eq!(folder(&p, "Produkcja").parent, Some(folder(&p, "Bazy").id));
        assert_eq!(folder(&p, "Kontrolery").parent, Some(serwery.id));
        let dc = host(&p, "SRV-DC01");
        assert_eq!(dc.address, "srv-dc01.example.com");
        assert_eq!(dc.protocol, Protocol::Rdp);
        assert_eq!(dc.folder, Some(folder(&p, "Kontrolery").id));
        assert_eq!(host(&p, "SRV-SQL01").protocol, Protocol::Rdp);
        assert_eq!(host(&p, "jump").folder, Some(serwery.id));
        assert_eq!(host(&p, "luzem").folder, None);
        // Jeden katalog najwyższego poziomu jest katalogiem głównym pakietu.
        assert_eq!(p.root, Some(serwery.id));
        // Dwa katalogi najwyższego poziomu: bez katalogu głównego.
        let two = package_from_csv(
            "nazwa,adres,protokol,katalog\na,a.example,ssh,A\nb,b.example,ssh,B\n",
        )
        .unwrap();
        assert_eq!(two.root, None);
    }

    #[test]
    fn identifiers_are_stable_and_match_the_documented_scheme() {
        // Wartości wyliczone niezależnie (SHA-256 z "mrm-import:host:<adres>" i
        // "mrm-import:folder:<ścieżka>", małymi literami): tak samo liczy je narzędzie, którym
        // powstały pierwsze pliki importu, więc zmiana schematu zdublowałaby hosty u użytkowników.
        assert_eq!(
            host_id("srv-01.example.com").to_string(),
            "64d3ae63-7615-8291-bd21-9f38ccba09e1"
        );
        assert_eq!(
            folder_id(&["Serwery".into(), "Bazy".into()]).to_string(),
            "a3c7919e-1ade-87fc-a4fb-ff58d4d3b8a1"
        );
        // Wielkość liter adresu i ścieżki nie zmienia identyfikatora.
        assert_eq!(host_id("SRV-01.Example.COM"), host_id("srv-01.example.com"));
        assert_eq!(
            folder_id(&["SERWERY".into(), "bazy".into()]),
            folder_id(&["Serwery".into(), "Bazy".into()])
        );
        // Ten sam plik daje te same identyfikatory, a kolejność wierszy nie ma znaczenia.
        let a = package_from_csv(SAMPLE).unwrap();
        let reordered = "nazwa,adres,protokol,katalog\n\
            luzem,10.0.0.9,ssh,\n\
            SRV-DC01,srv-dc01.example.com,rdp,Serwery/Kontrolery\n\
            jump,jump.example.com,ssh,Serwery\n\
            SRV-SQL01,srv-sql01.example.com,RDP,Serwery/Bazy/Produkcja\n";
        let b = package_from_csv(reordered).unwrap();
        assert_eq!(host(&a, "jump").id, host(&b, "jump").id);
        assert_eq!(a.folders, b.folders);
    }

    #[test]
    fn reimport_of_refreshed_list_updates_instead_of_duplicating() {
        let mut doc = Document::default();
        let first = package_from_csv(SAMPLE).unwrap();
        let r = import(&mut doc, &first, Parts::default(), Existing::Skip).unwrap();
        assert_eq!((r.hosts_added, r.folders_added), (4, 4));
        // Użytkownik ustawił login na hoście i przeniósł katalog główny pod własny katalog.
        let dc = host(&first, "SRV-DC01").id;
        doc.tree
            .hosts
            .iter_mut()
            .find(|h| h.id == dc)
            .unwrap()
            .fields
            .username = Some("admin".into());
        let mine = doc.tree.add_folder("Moje", None).unwrap();
        doc.tree
            .move_folder(first.root.unwrap(), Some(mine))
            .unwrap();
        // Odświeżona lista: nowy host, zmieniona nazwa jednego, jeden przeniesiony.
        let refreshed = "nazwa;adres;protokol;katalog\r\n\
            DC-01;srv-dc01.example.com;rdp;Serwery/Kontrolery\r\n\
            SRV-SQL01;srv-sql01.example.com;rdp;Serwery/Bazy\r\n\
            jump;jump.example.com;ssh;Serwery\r\n\
            luzem;10.0.0.9;ssh;\r\n\
            nowy;nowy.example.com;rdp;Serwery/Kontrolery\r\n";
        let second = package_from_csv(refreshed).unwrap();
        let r = import(&mut doc, &second, Parts::default(), Existing::Update).unwrap();
        assert_eq!(r.hosts_added, 1);
        assert_eq!(r.hosts_updated, 2);
        assert_eq!(doc.tree.hosts.len(), 5);
        let h = doc.tree.host(dc).unwrap();
        assert_eq!(h.name, "DC-01");
        assert_eq!(h.fields.username.as_deref(), Some("admin"));
        // Katalog główny został tam, gdzie przeniósł go użytkownik.
        assert_eq!(
            doc.tree.folder(first.root.unwrap()).unwrap().parent,
            Some(mine)
        );
    }

    #[test]
    fn accepts_semicolons_tabs_quotes_bom_and_header_variants() {
        let semi = "\u{feff}Nazwa;Adres;Protokół;Katalog\r\n\"Serwer; główny\";srv.example.com;SSH;\"Dział \"\"A\"\"/Bazy\"\r\n";
        let p = package_from_csv(semi).unwrap();
        assert_eq!(p.hosts[0].name, "Serwer; główny");
        assert_eq!(p.hosts[0].protocol, Protocol::Ssh);
        let names: Vec<&str> = p.folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Dział \"A\"", "Bazy"]);
        let tabs = "name\taddress\tprotocol\tfolder\nweb\tweb.example.com\tssh\t A / B \n";
        let p = package_from_csv(tabs).unwrap();
        assert_eq!(p.hosts[0].address, "web.example.com");
        let names: Vec<&str> = p.folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["A", "B"]);
        // Bez kolumny katalogu, inna kolejność kolumn, dodatkowa kolumna, puste wiersze, brak końca wiersza.
        let loose =
            "adres,opis,protokol,nazwa\n\n10.0.0.1,cokolwiek,rdp,pc\n ,, , \n10.0.0.2,,ssh,srv";
        let p = package_from_csv(loose).unwrap();
        assert_eq!(p.hosts.len(), 2);
        assert!(p.folders.is_empty());
        assert_eq!(p.root, None);
        assert_eq!(host(&p, "srv").address, "10.0.0.2");
    }

    #[test]
    fn reports_problems_with_row_numbers() {
        let err = |text: &str| package_from_csv(text).err().unwrap();
        assert_eq!(err(""), Error::Empty);
        assert_eq!(err("\n \n"), Error::Empty);
        assert_eq!(err("nazwa,adres,protokol\n"), Error::NoHosts);
        assert_eq!(err("nazwa,adres\na,b\n"), Error::MissingColumn("protokol"));
        assert_eq!(
            err("adres,protokol\nb,ssh\n"),
            Error::MissingColumn("nazwa")
        );
        assert_eq!(
            err("nazwa,protokol\nb,ssh\n"),
            Error::MissingColumn("adres")
        );
        assert_eq!(
            err("nazwa,adres,protokol\na,a.example,ssh\n,b.example,ssh\n"),
            Error::Row {
                row: 3,
                reason: "brak nazwy"
            }
        );
        assert_eq!(
            err("nazwa,adres,protokol\na,,ssh\n"),
            Error::Row {
                row: 2,
                reason: "brak adresu"
            }
        );
        assert_eq!(
            err("nazwa,adres,protokol\na,a.example,telnet\n"),
            Error::Row {
                row: 2,
                reason: "protokół musi być ssh albo rdp"
            }
        );
        assert_eq!(
            err("nazwa,adres,protokol\na,a.example,ssh\n\nb,A.EXAMPLE,rdp\n"),
            Error::Row {
                row: 4,
                reason: "adres powtarza się we wcześniejszym wierszu"
            }
        );
        assert_eq!(
            err("nazwa,adres,protokol\n\"a,a.example,ssh\n"),
            Error::Row {
                row: 2,
                reason: "niezamknięty cudzysłów"
            }
        );
        assert_eq!(err("n\0a\0z\0w\0a\0"), Error::NotText);
        assert_eq!(err(&"x".repeat(MAX_CSV + 1)), Error::TooLarge);
        // Wiersz w cudzysłowach rozciągnięty na dwa wiersze pliku: numer następnego się zgadza.
        assert_eq!(
            err("nazwa,adres,protokol\n\"a\nb\",a.example,ssh\nc,,ssh\n"),
            Error::Row {
                row: 4,
                reason: "brak adresu"
            }
        );
    }

    #[test]
    fn names_with_control_characters_fail_the_import_check() {
        // Znak sterujący w nazwie przechodzi przez CSV (pole w cudzysłowach), ale nie przez kontrolę
        // pakietu, którą wykonuje import.
        let p = package_from_csv("nazwa,adres,protokol\n\"a\nb\",a.example,ssh\n").unwrap();
        assert_eq!(check(&p), Err(transfer::Error::BadName));
    }
}
