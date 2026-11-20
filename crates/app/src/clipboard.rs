//! Schowek systemowy dla sesji RDP: tekst, HTML, obrazy i pliki w obu kierunkach.
//!
//! Zawartość schowka nigdy nie trafia do dziennika ani do frontendu. Zmiany lokalne wykrywamy
//! odciskiem (tylko gdy okno sesji ma fokus), a dane ustawiane z sesji zdalnej od razu zapisujemy
//! jako "ostatni odcisk", żeby nie odsyłać serwerowi tego, co on sam przysłał.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;

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
//
// Cały dostęp idzie przez jeden wątek, który trzyma jedną instancję `arboard::Clipboard` przez cały
// czas działania aplikacji. Na X11 dane wstawione do schowka istnieją tylko, dopóki żyje instancja,
// która je wstawiła (bez menedżera schowka znikały od razu), a na Windows równoległe otwieranie
// schowka z kilku wątków daje błędy i puste odczyty.

enum Req {
    Snapshot(mpsc::Sender<Snapshot>),
    Item(Item, mpsc::Sender<()>),
    Files(Vec<PathBuf>, mpsc::Sender<()>),
    Text(mpsc::Sender<Option<String>>),
}

/// Limit czasu odpowiedzi wątku schowka. Brak odpowiedzi to brak wiedzy o schowku, a nie pusty schowek.
const HOST_TIMEOUT: Duration = Duration::from_secs(5);

/// Pętla wątku obsługującego żądania. Panika w obsłudze jednego żądania (np. w bibliotece schowka
/// na nietypowej zawartości wstawionej przez inny program) nie kończy wątku: to żądanie zostaje bez
/// odpowiedzi, `reset` odtwarza stan, a kolejne żądania działają dalej. Bez tego jedna panika
/// wyłączałaby schowek wszystkich sesji RDP do końca działania aplikacji.
fn serve<R, S>(
    rx: mpsc::Receiver<R>,
    mut state: S,
    handle: impl Fn(&mut S, R),
    reset: impl Fn(&mut S),
) {
    for req in rx {
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(&mut state, req)));
        if outcome.is_err() {
            reset(&mut state);
        }
    }
}

fn handle_req(cb: &mut Option<arboard::Clipboard>, req: Req) {
    if cb.is_none() {
        *cb = arboard::Clipboard::new().ok();
    }
    match (req, cb.as_mut()) {
        (Req::Snapshot(reply), Some(c)) => {
            let _ = reply.send(read_snapshot(c));
        }
        (Req::Snapshot(reply), None) => {
            let _ = reply.send(Snapshot::default());
        }
        (Req::Item(item, reply), Some(c)) => {
            write_item(c, item);
            let _ = reply.send(());
        }
        (Req::Files(paths, reply), Some(c)) => {
            let _ = c.set().file_list(&paths);
            let _ = reply.send(());
        }
        (Req::Text(reply), Some(c)) => {
            let _ = reply.send(c.get_text().ok());
        }
        (Req::Text(reply), None) => {
            let _ = reply.send(None);
        }
        (Req::Item(_, reply) | Req::Files(_, reply), None) => {
            let _ = reply.send(());
        }
    }
}

fn host() -> &'static Mutex<mpsc::Sender<Req>> {
    static HOST: OnceLock<Mutex<mpsc::Sender<Req>>> = OnceLock::new();
    HOST.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Req>();
        std::thread::Builder::new()
            .name("schowek".into())
            // Po panice instancja schowka jest tworzona od nowa przy następnym żądaniu.
            .spawn(move || serve(rx, None, handle_req, |cb| *cb = None))
            .expect("wątek schowka");
        Mutex::new(tx)
    })
}

/// Wysyła żądanie do wątku schowka. `None`, gdy wątek nie odpowiedział w czasie albo żądanie
/// zakończyło się paniką.
fn ask<T>(make: impl FnOnce(mpsc::Sender<T>) -> Req) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    host().lock().expect("schowek").send(make(tx)).ok()?;
    rx.recv_timeout(HOST_TIMEOUT).ok()
}

/// Bieżąca zawartość schowka systemowego (blokujące). `None` oznacza brak odczytu.
pub fn snapshot() -> Option<Snapshot> {
    ask(Req::Snapshot)
}

/// Najdłuższy tekst wklejany ze schowka przez interfejs.
const MAX_PASTE: usize = 1024 * 1024;

/// Tekst ze schowka systemowego dla wklejania prawym przyciskiem (odczyt w WebKitGTK bywa
/// zablokowany, więc idzie przez wątek schowka). Nie zależy od przełącznika schowka RDP, a treść
/// nie trafia do dziennika.
#[tauri::command]
pub async fn read_clipboard_text() -> Result<String, String> {
    let reply = tokio::task::spawn_blocking(|| ask(Req::Text))
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Nie można odczytać schowka.")?;
    let text = reply.unwrap_or_default();
    if text.len() > MAX_PASTE {
        return Err("Tekst w schowku jest za duży do wklejenia (limit 1 MiB).".into());
    }
    Ok(text)
}

/// Co wiadomo o ostatnio widzianej zawartości lokalnego schowka.
#[derive(Default)]
struct Seen {
    /// Odcisk ostatnio ogłoszonej albo wstawionej ze zdalnej sesji zawartości.
    fp: Option<u64>,
    /// Po wstawieniu danych ze zdalnej sesji nie udało się odczytać schowka: następny udany odczyt
    /// jest przyjmowany jako znany bez ogłaszania, żeby dane serwera nie wróciły do niego jako echo.
    adopt_next: bool,
}

impl Seen {
    /// Wynik odczytu schowka; zwraca migawkę, jeśli zawartość jest nowa i trzeba ją ogłosić.
    /// Brak odczytu niczego nie zmienia: potraktowany jak pusty schowek zastąpiłby ogłoszoną
    /// zawartość pustą, a po chwili ogłosił ją drugi raz.
    fn observe(&mut self, snap: Option<Snapshot>) -> Option<Snapshot> {
        let snap = snap?;
        let fp = snap.fingerprint();
        let adopt = std::mem::take(&mut self.adopt_next);
        if adopt || self.fp == Some(fp) {
            self.fp = Some(fp);
            return None;
        }
        self.fp = Some(fp);
        Some(snap)
    }

    /// Po wstawieniu danych ze zdalnej sesji; `after` to odczyt schowka po wstawieniu.
    fn applied(&mut self, after: Option<Snapshot>) {
        match after {
            Some(snap) => {
                self.fp = Some(snap.fingerprint());
                self.adopt_next = false;
            }
            None => self.adopt_next = true,
        }
    }
}

fn read_snapshot(c: &mut arboard::Clipboard) -> Snapshot {
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

fn write_item(c: &mut arboard::Clipboard, item: Item) {
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

/// Stan synchronizacji schowka jednej sesji.
pub struct ClipSync {
    /// Czy okno sesji ma fokus: tylko wtedy ogłaszamy zmiany lokalnego schowka i przyjmujemy zdalne.
    pub watching: AtomicBool,
    /// Ostatnio widziana zawartość schowka. Blokada obejmuje cały odczyt i zapis schowka, żeby
    /// sprawdzanie zmian nie wpadło między wstawienie a zapis odcisku.
    last: Mutex<Seen>,
    /// Migawka z chwili ostatniego ogłoszenia: serwer dostaje dane tylko z niej, nigdy z bieżącego
    /// schowka, więc nie odczyta niczego, co skopiowano później w innym programie.
    announced: Mutex<Option<Snapshot>>,
    /// Zmiana zdalnego schowka, która przyszła bez fokusu; pobieramy ją po powrocie fokusu.
    pending_remote: Mutex<Option<(Vec<ClipKind>, bool)>>,
    pub remote: Mutex<RemoteAssembler>,
    download_root: PathBuf,
    counter: AtomicU32,
}

impl ClipSync {
    pub fn new(download_root: PathBuf) -> Self {
        Self {
            watching: AtomicBool::new(false),
            last: Mutex::default(),
            announced: Mutex::new(None),
            pending_remote: Mutex::new(None),
            remote: Mutex::default(),
            download_root,
            counter: AtomicU32::new(0),
        }
    }

    /// Ogłoszenie, jeśli lokalny schowek zmienił się od ostatniego (blokujące, woła się z `spawn_blocking`).
    /// Ogłoszenie unieważnia odłożoną zmianę zdalną: wygrywa nowsza zmiana lokalna.
    pub fn local_announcement(&self) -> Option<ToWorker> {
        let mut last = self.last.lock().expect("clip");
        let snap = last.observe(snapshot())?;
        let msg = snap.announcement();
        *self.announced.lock().expect("clip") = Some(snap);
        if msg.is_some() {
            *self.pending_remote.lock().expect("clip") = None;
        }
        msg
    }

    /// Zapomina ogłoszoną migawkę (np. po wyłączeniu schowka): serwer nie dostanie już tych danych.
    pub fn forget_announced(&self) {
        *self.announced.lock().expect("clip") = None;
        *self.last.lock().expect("clip") = Seen::default();
    }

    /// Odpowiedź na prośbę serwera o dane: tylko ogłoszone rodzaje z ogłoszonej migawki.
    pub fn answer(&self, kind: ClipKind) -> ToWorker {
        let data = self
            .announced
            .lock()
            .expect("clip")
            .as_ref()
            .filter(|s| s.kinds().contains(&kind))
            .map(|s| s.data_for(kind))
            .unwrap_or_default();
        ToWorker::ClipData { kind, data }
    }

    /// Zdalny schowek się zmienił. Z fokusem zwraca, co pobrać; bez fokusu odkłada zmianę.
    pub fn on_remote(&self, kinds: Vec<ClipKind>, files: bool) -> Option<Fetch> {
        if self.watching.load(Ordering::Relaxed) {
            *self.pending_remote.lock().expect("clip") = None;
            self.remote.lock().expect("clip").on_remote(&kinds, files)
        } else {
            *self.pending_remote.lock().expect("clip") = Some((kinds, files));
            None
        }
    }

    /// Po powrocie fokusu: pobranie odłożonej zmiany zdalnej, jeśli jest.
    pub fn take_pending(&self) -> Option<Fetch> {
        let (kinds, files) = self.pending_remote.lock().expect("clip").take()?;
        self.remote.lock().expect("clip").on_remote(&kinds, files)
    }

    /// Ustawia element ze zdalnego schowka i zapamiętuje odcisk, żeby go nie odesłać (blokujące).
    pub fn apply(&self, item: Item) {
        let mut last = self.last.lock().expect("clip");
        ask(|tx| Req::Item(item, tx));
        last.applied(snapshot());
    }

    pub fn apply_files(&self, paths: Vec<PathBuf>) {
        let mut last = self.last.lock().expect("clip");
        ask(|tx| Req::Files(paths, tx));
        last.applied(snapshot());
    }

    /// Nowy katalog na pobierane pliki; poprzedni z tej sesji jest usuwany, żeby nie rosły w nieskończoność.
    pub fn next_download_dir(&self) -> PathBuf {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        if n > 0 {
            // Usuwanie do 5000 plików trwa: robi to osobny wątek, żeby nie wstrzymywać pętli zdarzeń
            // sesji (obrazu). Proces RDP przerwał już pobieranie do tego katalogu.
            let old = self.download_root.join((n - 1).to_string());
            std::thread::spawn(move || {
                let _ = std::fs::remove_dir_all(old);
            });
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

    fn text(t: &str) -> Snapshot {
        Snapshot {
            text: Some(t.into()),
            ..Default::default()
        }
    }

    #[test]
    fn panic_in_one_request_does_not_stop_the_clipboard_thread() {
        let (tx, rx) = mpsc::channel::<(u32, mpsc::Sender<u32>)>();
        let worker = std::thread::spawn(move || {
            serve(
                rx,
                0u32,
                |served, (n, reply): (u32, mpsc::Sender<u32>)| {
                    assert!(n != 13, "symulowana panika biblioteki schowka");
                    *served += 1;
                    let _ = reply.send(*served);
                },
                |served| *served = 100,
            )
        });
        let ask = |n: u32| {
            let (reply, answer) = mpsc::channel();
            tx.send((n, reply)).unwrap();
            answer.recv_timeout(Duration::from_secs(5)).ok()
        };
        assert_eq!(ask(1), Some(1));
        assert_eq!(ask(13), None, "żądanie z paniką zostaje bez odpowiedzi");
        assert_eq!(ask(2), Some(101), "wątek żyje, a stan został odtworzony");
        drop(tx);
        worker.join().unwrap();
    }

    #[test]
    fn failed_clipboard_read_is_not_an_empty_clipboard() {
        // `Snapshot` celowo nie ma `Debug` (zawartość schowka nie trafia do logów), więc porównujemy tekst.
        let mut seen = Seen::default();
        let mut see = |s: Option<Snapshot>| seen.observe(s).and_then(|s| s.text);
        assert_eq!(see(Some(text("a"))).as_deref(), Some("a"));
        assert_eq!(see(Some(text("a"))), None, "bez zmiany");
        // Brak odczytu (limit czasu) nie zmienia stanu: ta sama zawartość nie jest ogłaszana drugi raz.
        assert_eq!(see(None), None);
        assert_eq!(see(Some(text("a"))), None);
        assert_eq!(see(Some(text("b"))).as_deref(), Some("b"));
    }

    #[test]
    fn remote_item_is_not_echoed_even_when_read_back_fails() {
        let mut seen = Seen::default();
        // Odczyt po wstawieniu się udał: ta zawartość jest znana.
        seen.applied(Some(text("ze zdalnej")));
        assert!(seen.observe(Some(text("ze zdalnej"))).is_none());
        // Odczyt po wstawieniu się nie udał: następny udany odczyt jest przyjmowany bez ogłaszania.
        seen.applied(None);
        assert!(seen.observe(None).is_none());
        assert!(seen.observe(Some(text("ze zdalnej 2"))).is_none());
        let announced = seen.observe(Some(text("lokalna"))).and_then(|s| s.text);
        assert_eq!(announced.as_deref(), Some("lokalna"));
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
        // Usuwanie działa w tle; czekamy najwyżej 5 s.
        let start = std::time::Instant::now();
        while first.exists() && start.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !first.exists(),
            "poprzedni katalog powinien zostać usunięty"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn server_gets_only_announced_kinds_from_announced_snapshot() {
        let sync = ClipSync::new(std::env::temp_dir().join("mrm-clip-answer"));
        let data = |m: ToWorker| match m {
            ToWorker::ClipData { data, .. } => data,
            other => panic!("{other:?}"),
        };
        // Nic nie ogłoszono: serwer nie dostaje niczego.
        assert!(data(sync.answer(ClipKind::Text)).is_empty());
        *sync.announced.lock().unwrap() = Some(Snapshot {
            text: Some("ogłoszony".into()),
            ..Default::default()
        });
        assert_eq!(data(sync.answer(ClipKind::Text)), "ogłoszony".as_bytes());
        assert!(
            data(sync.answer(ClipKind::Html)).is_empty(),
            "rodzaj nieogłoszony"
        );
        sync.forget_announced();
        assert!(data(sync.answer(ClipKind::Text)).is_empty());
    }

    #[test]
    fn remote_change_without_focus_waits_for_focus() {
        let sync = ClipSync::new(std::env::temp_dir().join("mrm-clip-pending"));
        assert_eq!(sync.on_remote(vec![ClipKind::Text], false), None);
        sync.watching.store(true, Ordering::Relaxed);
        assert_eq!(sync.take_pending(), Some(Fetch::Kind(ClipKind::Text)));
        assert_eq!(
            sync.take_pending(),
            None,
            "odłożona zmiana jest pobierana raz"
        );
        assert_eq!(
            sync.on_remote(vec![ClipKind::Image], false),
            Some(Fetch::Kind(ClipKind::Image)),
            "z fokusem pobieramy od razu"
        );
    }
}
