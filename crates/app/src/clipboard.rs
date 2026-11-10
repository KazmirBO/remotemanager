//! Schowek systemowy dla sesji RDP: tekst, HTML, obrazy i pliki w obu kierunkach.
//!
//! Zawartość schowka nigdy nie trafia do dziennika ani do frontendu. Zmiany lokalne wykrywamy
//! odciskiem (tylko gdy okno sesji ma fokus), a dane ustawiane z sesji zdalnej od razu zapisujemy
//! jako "ostatni odcisk", żeby nie odsyłać serwerowi tego, co on sam przysłał.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rdp::clipfmt::{self, Rgba};
use rdp::{ClipKind, ToWorker};

/// Limity przenoszonych danych (takie same rzędy wielkości jak w procesie RDP).
pub const TEXT_LIMIT: usize = 1024 * 1024;
const HTML_LIMIT: usize = 4 * 1024 * 1024;
const IMAGE_LIMIT: usize = 32 * 1024 * 1024;
const MAX_FILES: usize = 5000;

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub text: Option<String>,
    pub html: Option<String>,
    pub image: Option<Rgba>,
    pub files: Vec<PathBuf>,
}

impl Snapshot {
    pub fn kinds(&self) -> Vec<ClipKind> {
        let mut k = Vec::new();
        if self.text.is_some() {
            k.push(ClipKind::Text);
        }
        if self.html.is_some() {
            k.push(ClipKind::Html);
        }
        if self.image.is_some() {
            k.push(ClipKind::Image);
        }
        k
    }

    /// Odcisk do wykrywania zmian (nie jest skrótem kryptograficznym).
    pub fn fingerprint(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.text.hash(&mut h);
        self.html.hash(&mut h);
        if let Some(img) = &self.image {
            (img.width, img.height, img.rgba.len()).hash(&mut h);
            img.rgba.hash(&mut h);
        }
        self.files.hash(&mut h);
        h.finish()
    }

    /// Wiadomość ogłaszająca serwerowi zawartość schowka (pliki mają pierwszeństwo).
    pub fn announcement(&self) -> Option<ToWorker> {
        if !self.files.is_empty() {
            return Some(ToWorker::ClipAnnounceFiles {
                paths: self
                    .files
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect(),
            });
        }
        let kinds = self.kinds();
        (!kinds.is_empty()).then_some(ToWorker::ClipAnnounce { kinds })
    }

    /// Dane w formacie żądanym przez serwer (puste, gdy brak): tekst i HTML jako UTF-8, obraz jako DIB.
    pub fn data_for(&self, kind: ClipKind) -> Vec<u8> {
        match kind {
            ClipKind::Text => self.text.clone().unwrap_or_default().into_bytes(),
            ClipKind::Html => self.html.clone().unwrap_or_default().into_bytes(),
            ClipKind::Image => self
                .image
                .as_ref()
                .and_then(clipfmt::rgba_to_dib)
                .unwrap_or_default(),
        }
    }
}

/// Co pobrać po zmianie zdalnego schowka: pliki, a w przeciwnym razie obraz, HTML albo tekst.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetch {
    Files,
    Kind(ClipKind),
}

impl Fetch {
    pub fn command(&self) -> ToWorker {
        match self {
            Fetch::Files => ToWorker::ClipFetchFiles,
            Fetch::Kind(kind) => ToWorker::ClipFetch { kind: *kind },
        }
    }
}

/// Element gotowy do wstawienia do schowka lokalnego.
#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Text(String),
    Html { html: String, alt: Option<String> },
    Image(Rgba),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Set(Item),
    Fetch(ClipKind),
    Ignore,
}

/// Składa zdalny schowek z kilku pobrań (HTML wymaga jeszcze tekstu zastępczego).
#[derive(Default)]
pub struct RemoteAssembler {
    remote_has_text: bool,
    html: Option<String>,
}

impl RemoteAssembler {
    pub fn on_remote(&mut self, kinds: &[ClipKind], files: bool) -> Option<Fetch> {
        self.html = None;
        self.remote_has_text = kinds.contains(&ClipKind::Text);
        if files {
            Some(Fetch::Files)
        } else if kinds.contains(&ClipKind::Image) {
            Some(Fetch::Kind(ClipKind::Image))
        } else if kinds.contains(&ClipKind::Html) {
            Some(Fetch::Kind(ClipKind::Html))
        } else if kinds.contains(&ClipKind::Text) {
            Some(Fetch::Kind(ClipKind::Text))
        } else {
            None
        }
    }

    pub fn on_blob(&mut self, kind: ClipKind, data: Vec<u8>) -> Outcome {
        match kind {
            ClipKind::Text => {
                let Ok(text) = String::from_utf8(data) else {
                    return Outcome::Ignore;
                };
                if text.is_empty() || text.len() > TEXT_LIMIT {
                    return Outcome::Ignore;
                }
                match self.html.take() {
                    Some(html) => Outcome::Set(Item::Html {
                        html,
                        alt: Some(text),
                    }),
                    None => Outcome::Set(Item::Text(text)),
                }
            }
            ClipKind::Html => {
                let Ok(html) = String::from_utf8(data) else {
                    return Outcome::Ignore;
                };
                if html.is_empty() || html.len() > HTML_LIMIT {
                    return Outcome::Ignore;
                }
                if self.remote_has_text {
                    self.html = Some(html);
                    Outcome::Fetch(ClipKind::Text)
                } else {
                    Outcome::Set(Item::Html { html, alt: None })
                }
            }
            ClipKind::Image => match clipfmt::dib_to_rgba(&data) {
                Some(img) => Outcome::Set(Item::Image(img)),
                None => Outcome::Ignore,
            },
        }
    }
}

// ---- dostęp do schowka systemowego (arboard) ----

pub fn snapshot() -> Snapshot {
    let Ok(mut c) = arboard::Clipboard::new() else {
        return Snapshot::default();
    };
    let files: Vec<PathBuf> = c
        .get()
        .file_list()
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.exists())
        .take(MAX_FILES)
        .collect();
    if !files.is_empty() {
        return Snapshot {
            files,
            ..Default::default()
        };
    }
    Snapshot {
        text: c
            .get_text()
            .ok()
            .filter(|t| !t.is_empty() && t.len() <= TEXT_LIMIT),
        html: c
            .get()
            .html()
            .ok()
            .filter(|h| !h.is_empty() && h.len() <= HTML_LIMIT),
        image: c
            .get_image()
            .ok()
            .filter(|i| i.bytes.len() <= IMAGE_LIMIT)
            .and_then(|i| {
                Some(Rgba {
                    width: u32::try_from(i.width).ok()?,
                    height: u32::try_from(i.height).ok()?,
                    rgba: i.bytes.into_owned(),
                })
            }),
        files: Vec::new(),
    }
}

fn apply_item(item: Item) {
    let Ok(mut c) = arboard::Clipboard::new() else {
        return;
    };
    let _ = match item {
        Item::Text(t) => c.set_text(t),
        Item::Html { html, alt } => c.set().html(html, alt),
        Item::Image(img) => c.set_image(arboard::ImageData {
            width: img.width as usize,
            height: img.height as usize,
            bytes: img.rgba.into(),
        }),
    };
}

fn apply_files(paths: &[PathBuf]) {
    if let Ok(mut c) = arboard::Clipboard::new() {
        let _ = c.set().file_list(paths);
    }
}

/// Stan synchronizacji schowka jednej sesji.
pub struct ClipSync {
    /// Czy okno sesji ma fokus: tylko wtedy ogłaszamy zmiany lokalnego schowka.
    pub watching: AtomicBool,
    last: Mutex<Option<u64>>,
    pub remote: Mutex<RemoteAssembler>,
    download_root: PathBuf,
    counter: AtomicU32,
}

impl ClipSync {
    pub fn new(download_root: PathBuf) -> Self {
        Self {
            watching: AtomicBool::new(false),
            last: Mutex::new(None),
            remote: Mutex::default(),
            download_root,
            counter: AtomicU32::new(0),
        }
    }

    /// Wywoływane po zmianie fokusu: wymusza ponowne ogłoszenie przy następnym sprawdzeniu.
    pub fn reset(&self) {
        *self.last.lock().expect("clip") = None;
    }

    /// Ogłoszenie, jeśli lokalny schowek zmienił się od ostatniego (blokujące, woła się z `spawn_blocking`).
    pub fn local_announcement(&self) -> Option<ToWorker> {
        let snap = snapshot();
        let fp = snap.fingerprint();
        let mut last = self.last.lock().expect("clip");
        if *last == Some(fp) {
            return None;
        }
        *last = Some(fp);
        snap.announcement()
    }

    /// Odpowiedź na prośbę serwera o dane (blokujące).
    pub fn answer(&self, kind: ClipKind) -> ToWorker {
        ToWorker::ClipData {
            kind,
            data: snapshot().data_for(kind),
        }
    }

    /// Ustawia element ze zdalnego schowka i zapamiętuje odcisk, żeby go nie odesłać (blokujące).
    pub fn apply(&self, item: Item) {
        apply_item(item);
        *self.last.lock().expect("clip") = Some(snapshot().fingerprint());
    }

    pub fn apply_files(&self, paths: Vec<PathBuf>) {
        apply_files(&paths);
        *self.last.lock().expect("clip") = Some(snapshot().fingerprint());
    }

    /// Nowy katalog na pobierane pliki; poprzedni z tej sesji jest usuwany, żeby nie rosły w nieskończoność.
    pub fn next_download_dir(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        if n > 0 {
            let _ = std::fs::remove_dir_all(self.download_root.join((n - 1).to_string()));
        }
        self.download_root.join(n.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img() -> Rgba {
        Rgba {
            width: 2,
            height: 1,
            rgba: vec![1, 2, 3, 255, 4, 5, 6, 255],
        }
    }

    #[test]
    fn remote_priority_is_files_image_html_text() {
        let mut a = RemoteAssembler::default();
        let all = [ClipKind::Text, ClipKind::Html, ClipKind::Image];
        assert_eq!(a.on_remote(&all, true), Some(Fetch::Files));
        assert_eq!(a.on_remote(&all, false), Some(Fetch::Kind(ClipKind::Image)));
        assert_eq!(
            a.on_remote(&[ClipKind::Text, ClipKind::Html], false),
            Some(Fetch::Kind(ClipKind::Html))
        );
        assert_eq!(
            a.on_remote(&[ClipKind::Text], false),
            Some(Fetch::Kind(ClipKind::Text))
        );
        assert_eq!(a.on_remote(&[], false), None);
    }

    #[test]
    fn html_with_text_waits_for_text_then_sets_both() {
        let mut a = RemoteAssembler::default();
        a.on_remote(&[ClipKind::Text, ClipKind::Html], false);
        assert_eq!(
            a.on_blob(ClipKind::Html, b"<b>x</b>".to_vec()),
            Outcome::Fetch(ClipKind::Text)
        );
        assert_eq!(
            a.on_blob(ClipKind::Text, "x".as_bytes().to_vec()),
            Outcome::Set(Item::Html {
                html: "<b>x</b>".into(),
                alt: Some("x".into())
            })
        );
        // Po złożeniu kolejny tekst jest zwykłym tekstem.
        assert_eq!(
            a.on_blob(ClipKind::Text, b"y".to_vec()),
            Outcome::Set(Item::Text("y".into()))
        );
    }

    #[test]
    fn html_without_text_is_set_directly() {
        let mut a = RemoteAssembler::default();
        a.on_remote(&[ClipKind::Html], false);
        assert_eq!(
            a.on_blob(ClipKind::Html, b"<i>a</i>".to_vec()),
            Outcome::Set(Item::Html {
                html: "<i>a</i>".into(),
                alt: None
            })
        );
    }

    #[test]
    fn bad_blobs_are_ignored() {
        let mut a = RemoteAssembler::default();
        a.on_remote(&[ClipKind::Text, ClipKind::Image], false);
        assert_eq!(a.on_blob(ClipKind::Text, vec![0xff, 0xfe]), Outcome::Ignore);
        assert_eq!(a.on_blob(ClipKind::Text, Vec::new()), Outcome::Ignore);
        assert_eq!(
            a.on_blob(ClipKind::Text, vec![b'a'; TEXT_LIMIT + 1]),
            Outcome::Ignore
        );
        assert_eq!(a.on_blob(ClipKind::Image, vec![1, 2, 3]), Outcome::Ignore);
    }

    #[test]
    fn image_round_trips_through_dib() {
        let snap = Snapshot {
            image: Some(img()),
            ..Default::default()
        };
        let dib = snap.data_for(ClipKind::Image);
        let mut a = RemoteAssembler::default();
        assert_eq!(
            a.on_blob(ClipKind::Image, dib),
            Outcome::Set(Item::Image(img()))
        );
        assert!(Snapshot::default().data_for(ClipKind::Image).is_empty());
    }

    #[test]
    fn announcements_prefer_files_and_skip_empty() {
        assert_eq!(Snapshot::default().announcement(), None);
        let s = Snapshot {
            text: Some("a".into()),
            image: Some(img()),
            ..Default::default()
        };
        assert_eq!(
            s.announcement(),
            Some(ToWorker::ClipAnnounce {
                kinds: vec![ClipKind::Text, ClipKind::Image]
            })
        );
        let f = Snapshot {
            text: Some("a".into()),
            files: vec!["/tmp/x".into()],
            ..Default::default()
        };
        assert_eq!(
            f.announcement(),
            Some(ToWorker::ClipAnnounceFiles {
                paths: vec!["/tmp/x".into()]
            })
        );
    }

    #[test]
    fn fingerprint_changes_with_content_and_is_stable() {
        let a = Snapshot {
            text: Some("a".into()),
            ..Default::default()
        };
        let b = Snapshot {
            text: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(a.fingerprint(), a.clone().fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
        let mut c = a.clone();
        c.image = Some(img());
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn download_dirs_are_unique_and_previous_is_removed() {
        let root = std::env::temp_dir().join(format!("mrm-dl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let sync = ClipSync::new(root.clone());
        let first = sync.next_download_dir();
        std::fs::create_dir_all(&first).unwrap();
        std::fs::write(first.join("a"), b"x").unwrap();
        let second = sync.next_download_dir();
        assert_ne!(first, second);
        assert!(
            !first.exists(),
            "poprzedni katalog powinien zostać usunięty"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
