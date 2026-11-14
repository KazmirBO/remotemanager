//! Schowek RDP w procesie: tekst, HTML, obrazy i pliki w obu kierunkach.
//!
//! Dane z serwera są niezaufane: nazwy plików przechodzą przez `safe_relative_path`, liczba
//! elementów i łączny rozmiar są ograniczone, a odczyt lokalnych plików dotyczy wyłącznie
//! ogłoszonych wcześniej elementów (po indeksie, bez dowolnych ścieżek, bez dowiązań symbolicznych).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use ironrdp::cliprdr::backend::CliprdrBackend;
use ironrdp::cliprdr::pdu::{
    ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardFormatName,
    ClipboardGeneralCapabilityFlags, FileContentsFlags, FileContentsRequest, FileContentsResponse,
    FileDescriptor, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::cliprdr::{Client, Cliprdr, CliprdrSvcMessages};
use ironrdp::core::IntoOwned as _;
use ironrdp::session::ActiveStage;
use rdp_proto::clipfmt;
use rdp_proto::{ClipKind, FromWorker, RemoteFile, ToWorker};

/// Największa porcja danych (tekst, HTML, obraz) przenoszona jednym transferem.
const DATA_LIMIT: usize = 32 * 1024 * 1024;
/// Rozmiar jednej porcji przy pobieraniu plików.
const FILE_CHUNK: u32 = 256 * 1024;
/// Największa porcja pliku oddawana serwerowi w jednej odpowiedzi.
const SERVE_CHUNK: usize = 4 * 1024 * 1024;
/// Łączny limit pobieranych plików.
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 5000;
const MAX_DEPTH: usize = 32;
/// Maksymalna długość nazwy z katalogiem w opisie pliku (pole 260 znaków z zerem końcowym).
const MAX_WIRE_NAME: usize = 259;
const FILE_TIMEOUT: Duration = Duration::from_secs(30);
/// Numer formatu "HTML Format" w naszych ogłoszeniach (formaty zarejestrowane zaczynają się od 0xC000).
const HTML_FORMAT_ID: u32 = 0xC0A0;

pub type Out<'a> = dyn FnMut(&[u8]) -> io::Result<()> + 'a;

/// Zdarzenia z kanału schowka do pętli głównej (backend nie ma dostępu do połączenia).
pub enum ClipEvent {
    /// Serwer zgłosił gotowość (Monitor Ready) i czeka na możliwości oraz listę formatów klienta.
    InitRequested,
    /// Serwer przyjął pierwszą listę formatów: kanał jest zainicjowany.
    Ready,
    RemoteFormats(Vec<ClipboardFormat>),
    DataRequest(ClipboardFormatId),
    /// `None` oznacza odmowę serwera.
    DataResponse(Option<Vec<u8>>),
    RemoteFiles(Vec<FileDescriptor>),
    FileRequest(FileContentsRequest),
    FileResponse {
        stream_id: u32,
        data: Vec<u8>,
        error: bool,
    },
}

#[derive(Debug)]
pub struct ClipBackend {
    pub tx: Sender<ClipEvent>,
    pub tmp: String,
}

ironrdp::core::impl_as_any!(ClipBackend);

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        &self.tmp
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
            | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
            | ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS
    }
    fn on_ready(&mut self) {
        let _ = self.tx.send(ClipEvent::Ready);
    }
    fn on_request_format_list(&mut self) {
        let _ = self.tx.send(ClipEvent::InitRequested);
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let _ = self.tx.send(ClipEvent::RemoteFormats(formats.to_vec()));
    }
    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let _ = self.tx.send(ClipEvent::DataRequest(request.format));
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let data = (!response.is_error()).then(|| response.data().to_vec());
        let _ = self.tx.send(ClipEvent::DataResponse(data));
    }
    fn on_remote_file_list(&mut self, files: &[FileDescriptor], _: Option<u32>) {
        let _ = self.tx.send(ClipEvent::RemoteFiles(files.to_vec()));
    }
    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        let _ = self.tx.send(ClipEvent::FileRequest(request));
    }
    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let _ = self.tx.send(ClipEvent::FileResponse {
            stream_id: response.stream_id(),
            data: response.data().to_vec(),
            error: response.is_error(),
        });
    }
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

#[derive(Default)]
struct RemoteFormats {
    text: bool,
    html: Option<ClipboardFormatId>,
    dib: Option<ClipboardFormatId>,
    file_list: Option<ClipboardFormatId>,
}

impl RemoteFormats {
    fn from_list(formats: &[ClipboardFormat]) -> Self {
        let mut r = Self::default();
        for f in formats {
            let name = f.name().map(|n| n.value());
            if f.id() == ClipboardFormatId::CF_UNICODETEXT {
                r.text = true;
            } else if name == Some(ClipboardFormatName::HTML.value()) {
                r.html = Some(f.id());
            } else if name == Some(ClipboardFormatName::FILE_LIST.value()) {
                r.file_list = Some(f.id());
            } else if matches!(
                f.id(),
                ClipboardFormatId::CF_DIB | ClipboardFormatId::CF_DIBV5
            ) {
                // CF_DIB ma pierwszeństwo przed CF_DIBV5 niezależnie od kolejności na liście.
                if f.id() == ClipboardFormatId::CF_DIB || r.dib.is_none() {
                    r.dib = Some(f.id());
                }
            }
        }
        r
    }

    fn kinds(&self) -> Vec<ClipKind> {
        let mut k = Vec::new();
        if self.text {
            k.push(ClipKind::Text);
        }
        if self.html.is_some() {
            k.push(ClipKind::Html);
        }
        if self.dib.is_some() {
            k.push(ClipKind::Image);
        }
        k
    }
}

/// Etap inicjalizacji kanału schowka (MS-RDPECLIP 3.2.5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    /// Serwer nie zgłosił jeszcze gotowości: wszystko, co byśmy wysłali, przepadnie.
    #[default]
    Waiting,
    /// Wysłaliśmy możliwości i pierwszą listę formatów, czekamy na potwierdzenie.
    Initializing,
    Ready,
}

/// Ostatnie ogłoszenie lokalnego schowka od aplikacji.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Announced {
    Formats(Vec<ClipKind>),
    Files(Vec<String>),
}

/// Czy ogłoszenie można już wysłać serwerowi. Przed zgłoszeniem gotowości serwer niczego nie
/// odbiera, a lista plików wymaga zainicjowanego kanału (biblioteka ją wcześniej odrzuca).
fn can_send(phase: Phase, files: bool) -> bool {
    match phase {
        Phase::Waiting => false,
        Phase::Initializing => !files,
        Phase::Ready => true,
    }
}

fn kinds_label(kinds: &[ClipKind], files: bool) -> String {
    let mut names: Vec<&str> = kinds
        .iter()
        .map(|k| match k {
            ClipKind::Text => "tekst",
            ClipKind::Html => "HTML",
            ClipKind::Image => "obraz",
        })
        .collect();
    if files {
        names.push("pliki");
    }
    if names.is_empty() {
        "nic".into()
    } else {
        names.join(", ")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    Data(ClipKind),
    Files,
}

struct LocalEntry {
    path: PathBuf,
    is_dir: bool,
    /// Tożsamość pliku z chwili ogłoszenia (urządzenie, i-węzeł). Przy odczycie porównujemy ją
    /// z otwartym plikiem, więc podmiana ścieżki na dowiązanie po ogłoszeniu nic nie da.
    id: Option<(u64, u64)>,
}

#[cfg(unix)]
fn file_id(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_id(_meta: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Ten sam warunek, którym ironrdp-cliprdr 0.7 (`is_absolute_path`) odrzuca opisy plików przed
/// wysłaniem. Takie opisy musimy pominąć sami, bo inaczej indeksy serwera rozjadą się z `local_files`.
fn wire_looks_absolute(first: &str) -> bool {
    let mut c = first.chars();
    first.starts_with('/')
        || first.starts_with("\\\\")
        || first.starts_with("//")
        || matches!((c.next(), c.next()), (Some(a), Some(':')) if a.is_ascii_alphabetic())
}

struct Planned {
    /// Indeks na liście serwera (lindex).
    index: i32,
    dest: PathBuf,
    size: Option<u64>,
    dir: bool,
}

struct Download {
    dir: PathBuf,
    plan: Vec<Planned>,
    cur: usize,
    pos: u64,
    size: u64,
    out: Option<File>,
    stream: u32,
    awaiting_size: bool,
    written: u64,
    last: Instant,
}

#[derive(Default)]
pub struct ClipState {
    phase: Phase,
    /// Ostatnie ogłoszenie od aplikacji. Trzymane, bo zwykle przychodzi, zanim serwer jest gotowy,
    /// a aplikacja nie powtarza ogłoszenia tej samej zawartości.
    announced: Option<Announced>,
    /// Czy serwer dostał bieżące ogłoszenie.
    in_sync: bool,
    remote: RemoteFormats,
    pending: Option<Pending>,
    local_files: Vec<LocalEntry>,
    remote_files: Vec<FileDescriptor>,
    download: Option<Download>,
    next_stream: u32,
}

fn notice(message: impl Into<String>) {
    crate::emit(&FromWorker::Notice {
        message: message.into(),
    });
}

fn send(
    stage: &ActiveStage,
    out: &mut Out<'_>,
    msgs: CliprdrSvcMessages<Client>,
) -> anyhow::Result<()> {
    let bytes = stage
        .process_svc_processor_messages(msgs)
        .map_err(|e| anyhow!("schowek: {e}"))?;
    out(&bytes).context("schowek: zapis")
}

fn kind_of_format(id: ClipboardFormatId) -> Option<ClipKind> {
    match id {
        ClipboardFormatId::CF_UNICODETEXT => Some(ClipKind::Text),
        ClipboardFormatId::CF_DIB => Some(ClipKind::Image),
        ClipboardFormatId(HTML_FORMAT_ID) => Some(ClipKind::Html),
        _ => None,
    }
}

/// Tekst UTF-16LE zakończony zerem albo bez zera.
fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn encode_clip_payload(kind: ClipKind, data: Vec<u8>) -> Option<FormatDataResponse<'static>> {
    if data.is_empty() || data.len() > DATA_LIMIT {
        return None;
    }
    Some(match kind {
        ClipKind::Text => {
            FormatDataResponse::new_unicode_string(&String::from_utf8_lossy(&data)).into_owned()
        }
        ClipKind::Html => {
            FormatDataResponse::new_data(clipfmt::html_to_cf_html(&String::from_utf8_lossy(&data)))
        }
        ClipKind::Image => FormatDataResponse::new_data(data),
    })
}

impl ClipState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Zdarzenie z kanału schowka od serwera.
    pub fn on_event(
        &mut self,
        ev: ClipEvent,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        match ev {
            ClipEvent::InitRequested => {
                // Odpowiedź na gotowość serwera kończy inicjalizację: biblioteka dokłada do pierwszej
                // listy formatów możliwości klienta. Bez niej schowek nie działa w żadną stronę.
                self.phase = Phase::Initializing;
                let kinds = match &self.announced {
                    Some(Announced::Formats(kinds)) => kinds.clone(),
                    _ => Vec::new(),
                };
                self.send_formats(&kinds, stage, out)?;
                self.in_sync = !matches!(self.announced, Some(Announced::Files(_)));
                crate::log(format!(
                    "schowek: serwer gotowy, wysłano listę formatów ({})",
                    kinds_label(&kinds, false)
                ));
            }
            ClipEvent::Ready => {
                self.phase = Phase::Ready;
                crate::log("schowek: kanał zainicjowany");
                self.flush_announcement(stage, out)?;
            }
            ClipEvent::RemoteFormats(formats) => {
                self.remote = RemoteFormats::from_list(&formats);
                // Nowa zawartość zdalnego schowka unieważnia poprzednią listę plików, trwające
                // pobieranie i oczekiwaną odpowiedź (inaczej np. obraz zdekodowalibyśmy jako tekst).
                self.remote_files.clear();
                self.pending = None;
                if self.download.is_some() {
                    self.abort_download(
                        "Schowek na serwerze się zmienił, przerwano pobieranie plików.",
                    );
                }
                crate::log(format!(
                    "schowek: serwer ogłosił: {}",
                    kinds_label(&self.remote.kinds(), self.remote.file_list.is_some())
                ));
                crate::emit(&FromWorker::ClipRemote {
                    kinds: self.remote.kinds(),
                    files: self.remote.file_list.is_some(),
                });
            }
            ClipEvent::DataRequest(id) => match kind_of_format(id) {
                Some(kind) => {
                    crate::log(format!(
                        "schowek: serwer prosi o dane: {}",
                        kinds_label(&[kind], false)
                    ));
                    crate::emit(&FromWorker::ClipRequest { kind });
                }
                None => self.respond_format(stage, out, FormatDataResponse::new_error())?,
            },
            ClipEvent::DataResponse(data) => self.on_data_response(data),
            ClipEvent::RemoteFiles(files) => {
                self.pending = None;
                let list = describe_remote(&files);
                self.remote_files = files;
                crate::emit(&FromWorker::ClipFiles { files: list });
            }
            ClipEvent::FileRequest(req) => self.serve_file(&req, stage, out)?,
            ClipEvent::FileResponse {
                stream_id,
                data,
                error,
            } => {
                self.on_file_response(stream_id, &data, error, stage, out)?;
            }
        }
        Ok(())
    }

    /// Polecenie od aplikacji. Zwraca `true`, jeśli dotyczyło schowka.
    pub fn on_command(
        &mut self,
        cmd: &ToWorker,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<bool> {
        match cmd {
            ToWorker::ClipAnnounce { kinds } => {
                self.announced = Some(Announced::Formats(kinds.clone()));
                self.in_sync = false;
                self.flush_announcement(stage, out)?;
            }
            ToWorker::ClipAnnounceFiles { paths } => {
                self.announced = Some(Announced::Files(paths.clone()));
                self.in_sync = false;
                self.flush_announcement(stage, out)?;
            }
            ToWorker::ClipFetch { kind } => {
                let id = match kind {
                    ClipKind::Text => self
                        .remote
                        .text
                        .then_some(ClipboardFormatId::CF_UNICODETEXT),
                    ClipKind::Html => self.remote.html,
                    ClipKind::Image => self.remote.dib,
                };
                if let Some(id) = id {
                    self.pending = Some(Pending::Data(*kind));
                    if let Some(Ok(msgs)) = stage
                        .get_svc_processor_mut::<Cliprdr<Client>>()
                        .map(|c| c.initiate_paste(id))
                    {
                        send(stage, out, msgs)?;
                    }
                }
            }
            ToWorker::ClipFetchFiles => {
                if let Some(id) = self.remote.file_list {
                    self.pending = Some(Pending::Files);
                    if let Some(Ok(msgs)) = stage
                        .get_svc_processor_mut::<Cliprdr<Client>>()
                        .map(|c| c.initiate_paste(id))
                    {
                        send(stage, out, msgs)?;
                    }
                }
            }
            ToWorker::ClipDownload { dir } => {
                self.start_download(PathBuf::from(dir), stage, out)?
            }
            ToWorker::ClipData { kind, data } => {
                let resp = encode_clip_payload(*kind, data.clone())
                    .unwrap_or_else(FormatDataResponse::new_error);
                self.respond_format(stage, out, resp)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Wysyła serwerowi bieżące ogłoszenie, jeśli jeszcze go nie dostał i kanał jest na to gotowy.
    /// Wołane po każdym ogłoszeniu od aplikacji i po zakończeniu inicjalizacji kanału.
    fn flush_announcement(
        &mut self,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        if self.in_sync {
            return Ok(());
        }
        let Some(announced) = self.announced.clone() else {
            return Ok(());
        };
        if !can_send(self.phase, matches!(announced, Announced::Files(_))) {
            return Ok(());
        }
        self.in_sync = true;
        match announced {
            Announced::Formats(kinds) => {
                crate::log(format!(
                    "schowek: ogłoszono serwerowi: {}",
                    kinds_label(&kinds, false)
                ));
                self.send_formats(&kinds, stage, out)
            }
            Announced::Files(paths) => self.send_files(&paths, stage, out),
        }
    }

    fn send_formats(
        &mut self,
        kinds: &[ClipKind],
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        let formats: Vec<ClipboardFormat> = kinds
            .iter()
            .map(|k| match k {
                ClipKind::Text => ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
                ClipKind::Html => ClipboardFormat::new(ClipboardFormatId(HTML_FORMAT_ID))
                    .with_name(ClipboardFormatName::HTML),
                ClipKind::Image => ClipboardFormat::new(ClipboardFormatId::CF_DIB),
            })
            .collect();
        self.local_files.clear();
        if let Some(Ok(msgs)) = stage
            .get_svc_processor_mut::<Cliprdr<Client>>()
            .map(|c| c.initiate_copy(&formats))
        {
            send(stage, out, msgs)?;
        }
        Ok(())
    }

    fn send_files(
        &mut self,
        paths: &[String],
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        let (descs, entries, skipped) = build_local_files(paths);
        if skipped > 0 {
            notice(format!(
                "Pominięto {skipped} elementów (dowiązania, zbyt długie nazwy albo limit {MAX_ENTRIES})."
            ));
        }
        if descs.is_empty() {
            // Nic do pokazania serwerowi: ogłaszamy pusty schowek zamiast zostawiać poprzednią listę.
            return self.send_formats(&[], stage, out);
        }
        crate::log(format!(
            "schowek: ogłoszono serwerowi pliki ({})",
            descs.len()
        ));
        self.local_files = entries;
        if let Some(Ok(msgs)) = stage
            .get_svc_processor_mut::<Cliprdr<Client>>()
            .map(|c| c.initiate_file_copy(descs))
        {
            send(stage, out, msgs)?;
        } else {
            notice("Serwer nie obsługuje przesyłania plików przez schowek.");
        }
        Ok(())
    }

    /// Wywoływane w każdym obiegu pętli: pilnuje limitu czasu pobierania plików.
    pub fn tick(&mut self) {
        if self
            .download
            .as_ref()
            .is_some_and(|d| d.last.elapsed() > FILE_TIMEOUT)
        {
            self.abort_download("Przekroczono czas oczekiwania na pliki z serwera.");
        }
    }

    fn respond_format(
        &self,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
        resp: FormatDataResponse<'static>,
    ) -> anyhow::Result<()> {
        let msgs = stage
            .get_svc_processor::<Cliprdr<Client>>()
            .map(|c| c.submit_format_data(resp.into_owned()));
        if let Some(Ok(msgs)) = msgs {
            send(stage, out, msgs)?;
        }
        Ok(())
    }

    fn on_data_response(&mut self, data: Option<Vec<u8>>) {
        let Some(Pending::Data(kind)) = self.pending.take() else {
            return;
        };
        let Some(bytes) = data.filter(|d| d.len() <= DATA_LIMIT) else {
            crate::log(format!(
                "schowek: serwer nie przysłał danych ({}) albo przekroczyły limit",
                kinds_label(&[kind], false)
            ));
            return;
        };
        crate::log(format!(
            "schowek: pobrano z serwera: {}, {} B",
            kinds_label(&[kind], false),
            bytes.len()
        ));
        let payload = match kind {
            ClipKind::Text => utf16le_to_string(&bytes).into_bytes(),
            ClipKind::Html => match clipfmt::cf_html_to_html(&bytes) {
                Some(h) => h.into_bytes(),
                None => return,
            },
            ClipKind::Image => bytes,
        };
        crate::emit_clip(kind, &payload);
    }

    // ---- lokalne pliki serwowane serwerowi ----

    fn serve_file(
        &self,
        req: &FileContentsRequest,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        let resp = self
            .read_local(req)
            .unwrap_or_else(|| FileContentsResponse::new_error(req.stream_id));
        let msgs = stage
            .get_svc_processor::<Cliprdr<Client>>()
            .map(|c| c.submit_file_contents(resp));
        if let Some(Ok(msgs)) = msgs {
            send(stage, out, msgs)?;
        }
        Ok(())
    }

    /// Odczyt wyłącznie ogłoszonego elementu po indeksie; dowiązania i katalogi są odrzucane.
    fn read_local(&self, req: &FileContentsRequest) -> Option<FileContentsResponse<'static>> {
        let entry = self.local_files.get(usize::try_from(req.index).ok()?)?;
        if entry.is_dir {
            return None;
        }
        let meta = fs::symlink_metadata(&entry.path).ok()?;
        if !meta.is_file() || file_id(&meta) != entry.id {
            return None;
        }
        if req.flags.contains(FileContentsFlags::SIZE) {
            return Some(FileContentsResponse::new_size_response(
                req.stream_id,
                meta.len(),
            ));
        }
        if !req.flags.contains(FileContentsFlags::RANGE) {
            return None;
        }
        let want = usize::try_from(req.requested_size).ok()?.min(SERVE_CHUNK);
        let mut f = File::open(&entry.path).ok()?;
        let opened = f.metadata().ok()?;
        if !opened.is_file() || file_id(&opened) != entry.id {
            return None;
        }
        f.seek(SeekFrom::Start(req.position)).ok()?;
        let mut data = Vec::with_capacity(want.min(1 << 20));
        f.take(want as u64).read_to_end(&mut data).ok()?;
        Some(FileContentsResponse::new_data_response(req.stream_id, data))
    }

    // ---- pobieranie zdalnych plików ----

    fn start_download(
        &mut self,
        dir: PathBuf,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        // Nowsza kopia wygrywa: poprzednie pobieranie jest przerywane, a nie blokuje nowego.
        if self.download.take().is_some() {
            notice("Przerwano poprzednie pobieranie plików.");
        }
        let (plan, total, skipped) = plan_download(&dir, &self.remote_files);
        if plan.is_empty() {
            notice("Brak plików do pobrania.");
            return Ok(());
        }
        if plan.len() > MAX_ENTRIES || total > MAX_TOTAL_BYTES {
            notice(format!(
                "Zbyt dużo danych w schowku (limit {} MiB i {MAX_ENTRIES} elementów).",
                MAX_TOTAL_BYTES / (1024 * 1024)
            ));
            return Ok(());
        }
        if skipped > 0 {
            notice(format!(
                "Pominięto {skipped} elementów o niebezpiecznych nazwach."
            ));
        }
        // Błąd systemu plików (np. pełny dysk) kończy tylko pobieranie, a nie całą sesję RDP.
        if let Err(e) = fs::create_dir_all(&dir) {
            notice(format!("Nie można utworzyć katalogu pobierania: {e}"));
            return Ok(());
        }
        self.download = Some(Download {
            dir,
            plan,
            cur: 0,
            pos: 0,
            size: 0,
            out: None,
            stream: 0,
            awaiting_size: false,
            written: 0,
            last: Instant::now(),
        });
        self.advance(stage, out)
    }

    fn abort_download(&mut self, message: &str) {
        self.download = None;
        notice(message);
    }

    fn finish_download(&mut self) {
        let Some(d) = self.download.take() else {
            return;
        };
        let mut tops: Vec<String> = Vec::new();
        for p in &d.plan {
            if let Ok(rel) = p.dest.strip_prefix(&d.dir)
                && let Some(first) = rel.components().next()
            {
                let top = d.dir.join(first).to_string_lossy().into_owned();
                if !tops.contains(&top) {
                    tops.push(top);
                }
            }
        }
        crate::emit(&FromWorker::ClipFilesDone { paths: tops });
    }

    fn request(
        &mut self,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
        flags: FileContentsFlags,
        position: u64,
        size: u32,
    ) -> anyhow::Result<()> {
        self.next_stream = self.next_stream.wrapping_add(1);
        let stream = self.next_stream;
        let Some(d) = self.download.as_mut() else {
            return Ok(());
        };
        d.stream = stream;
        d.last = Instant::now();
        let req = FileContentsRequest {
            stream_id: stream,
            index: d.plan[d.cur].index,
            flags,
            position,
            requested_size: size,
            data_id: None,
        };
        match stage
            .get_svc_processor_mut::<Cliprdr<Client>>()
            .map(|c| c.request_file_contents(req))
        {
            Some(Ok(msgs)) => send(stage, out, msgs),
            _ => {
                self.abort_download("Serwer nie obsługuje pobierania plików przez schowek.");
                Ok(())
            }
        }
    }

    /// Przechodzi do następnego elementu planu i wysyła pierwsze żądanie; kończy, gdy plan się skończył.
    fn advance(&mut self, stage: &mut ActiveStage, out: &mut Out<'_>) -> anyhow::Result<()> {
        loop {
            let Some(d) = self.download.as_mut() else {
                return Ok(());
            };
            if d.cur >= d.plan.len() {
                self.finish_download();
                return Ok(());
            }
            let (is_dir, dest, size) = {
                let p = &d.plan[d.cur];
                (p.dir, p.dest.clone(), p.size)
            };
            if is_dir {
                if let Err(e) = fs::create_dir_all(&dest) {
                    self.abort_download(&format!("Nie można utworzyć katalogu: {e}"));
                    return Ok(());
                }
                d.cur += 1;
                continue;
            }
            let created = dest
                .parent()
                .map(fs::create_dir_all)
                .transpose()
                .and_then(|_| File::create(&dest));
            match created {
                Ok(f) => d.out = Some(f),
                Err(e) => {
                    self.abort_download(&format!("Nie można utworzyć pliku: {e}"));
                    return Ok(());
                }
            }
            d.pos = 0;
            match size {
                None => {
                    d.awaiting_size = true;
                    return self.request(stage, out, FileContentsFlags::SIZE, 0, 8);
                }
                Some(0) => {
                    d.out = None;
                    d.cur += 1;
                }
                Some(s) => {
                    d.size = s;
                    d.awaiting_size = false;
                    let n = u32::try_from(s.min(u64::from(FILE_CHUNK))).unwrap_or(FILE_CHUNK);
                    return self.request(stage, out, FileContentsFlags::RANGE, 0, n);
                }
            }
        }
    }

    fn on_file_response(
        &mut self,
        stream_id: u32,
        data: &[u8],
        error: bool,
        stage: &mut ActiveStage,
        out: &mut Out<'_>,
    ) -> anyhow::Result<()> {
        let Some(d) = self.download.as_mut() else {
            return Ok(());
        };
        if d.stream != stream_id {
            return Ok(());
        }
        if error {
            self.abort_download("Serwer odrzucił odczyt pliku.");
            return Ok(());
        }
        d.last = Instant::now();
        if d.awaiting_size {
            let Ok(raw) = <[u8; 8]>::try_from(data) else {
                self.abort_download("Serwer przysłał niepoprawny rozmiar pliku.");
                return Ok(());
            };
            let size = u64::from_le_bytes(raw);
            if size > MAX_TOTAL_BYTES.saturating_sub(d.written) {
                self.abort_download("Plik przekracza limit rozmiaru schowka.");
                return Ok(());
            }
            d.size = size;
            d.awaiting_size = false;
            if size == 0 {
                d.out = None;
                d.cur += 1;
                return self.advance(stage, out);
            }
            let n = u32::try_from(size.min(u64::from(FILE_CHUNK))).unwrap_or(FILE_CHUNK);
            return self.request(stage, out, FileContentsFlags::RANGE, 0, n);
        }
        let remaining = d.size.saturating_sub(d.pos);
        let take = usize::try_from(remaining.min(data.len() as u64)).unwrap_or(0);
        if take == 0 {
            self.abort_download("Serwer przysłał pustą porcję pliku.");
            return Ok(());
        }
        // Limit sprawdzamy przed zapisem, żeby na dysk nie trafiło nic ponad niego.
        if d.written.saturating_add(take as u64) > MAX_TOTAL_BYTES {
            self.abort_download("Przekroczono limit rozmiaru schowka.");
            return Ok(());
        }
        let write = d.out.as_mut().map(|f| f.write_all(&data[..take]));
        if !matches!(write, Some(Ok(()))) {
            self.abort_download("Nie można zapisać pobieranego pliku.");
            return Ok(());
        }
        d.pos += take as u64;
        d.written += take as u64;
        if d.pos >= d.size {
            d.out = None;
            d.cur += 1;
            self.advance(stage, out)
        } else {
            let (pos, n) = (
                d.pos,
                u32::try_from((d.size - d.pos).min(u64::from(FILE_CHUNK))).unwrap_or(FILE_CHUNK),
            );
            self.request(stage, out, FileContentsFlags::RANGE, pos, n)
        }
    }
}

fn describe_remote(files: &[FileDescriptor]) -> Vec<RemoteFile> {
    files
        .iter()
        .map(|f| {
            let rel = f.relative_path.as_deref().unwrap_or("").replace('\\', "/");
            let path = if rel.is_empty() {
                f.name.clone()
            } else {
                format!("{rel}/{}", f.name)
            };
            RemoteFile {
                path,
                size: f.file_size.unwrap_or(0),
                dir: f
                    .attributes
                    .is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY)),
            }
        })
        .collect()
}

/// Plan pobierania: bezpieczne ścieżki docelowe pod `dir`. Zwraca też łączny znany rozmiar i liczbę pominiętych.
fn plan_download(dir: &Path, files: &[FileDescriptor]) -> (Vec<Planned>, u64, usize) {
    let mut plan = Vec::new();
    let (mut total, mut skipped) = (0u64, 0usize);
    for (i, f) in files.iter().enumerate() {
        let Some(rel) = clipfmt::safe_relative_path(f.relative_path.as_deref(), &f.name) else {
            skipped += 1;
            continue;
        };
        let Ok(index) = i32::try_from(i) else {
            skipped += 1;
            continue;
        };
        let dir_entry = f
            .attributes
            .is_some_and(|a| a.contains(ClipboardFileAttributes::DIRECTORY));
        total = total.saturating_add(f.file_size.unwrap_or(0));
        plan.push(Planned {
            index,
            dest: dir.join(rel),
            size: f.file_size,
            dir: dir_entry,
        });
    }
    (plan, total, skipped)
}

/// Opisy lokalnych plików i katalogów (rekurencyjnie) wraz z wpisami do serwowania po indeksie.
/// Indeks opisu musi odpowiadać indeksowi wpisu, dlatego pomijamy wszystko, co biblioteka mogłaby odrzucić.
fn build_local_files(paths: &[String]) -> (Vec<FileDescriptor>, Vec<LocalEntry>, usize) {
    let (mut descs, mut entries, mut skipped) = (Vec::new(), Vec::new(), 0usize);
    for p in paths {
        walk(Path::new(p), "", 0, &mut descs, &mut entries, &mut skipped);
    }
    (descs, entries, skipped)
}

fn walk(
    path: &Path,
    rel: &str,
    depth: usize,
    descs: &mut Vec<FileDescriptor>,
    entries: &mut Vec<LocalEntry>,
    skipped: &mut usize,
) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        *skipped += 1;
        return;
    };
    let ft = meta.file_type();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Pole nazwy na łączu ma 260 jednostek UTF-16; znaki spoza BMP zajmują po dwie.
    let wire_len = if rel.is_empty() {
        name.encode_utf16().count()
    } else {
        rel.encode_utf16().count() + 1 + name.encode_utf16().count()
    };
    let first = if rel.is_empty() { name } else { rel };
    if ft.is_symlink()
        || !(ft.is_dir() || ft.is_file())
        || name.is_empty()
        || wire_len > MAX_WIRE_NAME
        || wire_looks_absolute(first)
        || entries.len() >= MAX_ENTRIES
    {
        *skipped += 1;
        return;
    }
    let mut desc = FileDescriptor::new(name);
    if !rel.is_empty() {
        desc = desc.with_relative_path(rel);
    }
    if ft.is_dir() {
        desc = desc.with_attributes(ClipboardFileAttributes::DIRECTORY);
    } else {
        desc = desc.with_file_size(meta.len());
    }
    descs.push(desc);
    entries.push(LocalEntry {
        path: path.to_owned(),
        is_dir: ft.is_dir(),
        id: file_id(&meta),
    });
    if ft.is_dir() && depth < MAX_DEPTH {
        let child_rel = if rel.is_empty() {
            name.to_owned()
        } else {
            format!("{rel}\\{name}")
        };
        let Ok(rd) = fs::read_dir(path) else { return };
        let mut children: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        children.sort();
        for c in children {
            walk(&c, &child_rel, depth + 1, descs, entries, skipped);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-clip-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn range(index: i32, position: u64, size: u32) -> FileContentsRequest {
        FileContentsRequest {
            stream_id: 7,
            index,
            flags: FileContentsFlags::RANGE,
            position,
            requested_size: size,
            data_id: None,
        }
    }

    #[test]
    fn announcements_wait_for_the_server_and_files_for_a_ready_channel() {
        // Przed zgłoszeniem gotowości serwera nic nie jest wysyłane (wcześniej przepadało).
        assert!(!can_send(Phase::Waiting, false));
        assert!(!can_send(Phase::Waiting, true));
        // W trakcie inicjalizacji można ogłosić formaty, ale nie listę plików.
        assert!(can_send(Phase::Initializing, false));
        assert!(!can_send(Phase::Initializing, true));
        assert!(can_send(Phase::Ready, false));
        assert!(can_send(Phase::Ready, true));
        assert_eq!(ClipState::new().phase, Phase::Waiting);
    }

    #[test]
    fn log_labels_name_kinds_without_content() {
        assert_eq!(kinds_label(&[], false), "nic");
        assert_eq!(
            kinds_label(&[ClipKind::Text, ClipKind::Image], true),
            "tekst, obraz, pliki"
        );
    }

    #[test]
    fn utf16_decoding_stops_at_nul() {
        let bytes: Vec<u8> = "zażółć\0śmieci"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16le_to_string(&bytes), "zażółć");
        assert_eq!(utf16le_to_string(&[0x41, 0x00, 0x42]), "A");
    }

    #[test]
    fn payload_encoding_rejects_empty_and_oversized() {
        assert!(encode_clip_payload(ClipKind::Text, Vec::new()).is_none());
        assert!(encode_clip_payload(ClipKind::Image, vec![0; DATA_LIMIT + 1]).is_none());
        assert!(encode_clip_payload(ClipKind::Html, b"<b>x</b>".to_vec()).is_some());
    }

    #[test]
    fn remote_format_detection() {
        let list = [
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
            ClipboardFormat::new(ClipboardFormatId(0xC100)).with_name(ClipboardFormatName::HTML),
            ClipboardFormat::new(ClipboardFormatId(0xC101))
                .with_name(ClipboardFormatName::FILE_LIST),
            ClipboardFormat::new(ClipboardFormatId::CF_DIBV5),
        ];
        let r = RemoteFormats::from_list(&list);
        assert_eq!(
            r.kinds(),
            vec![ClipKind::Text, ClipKind::Html, ClipKind::Image]
        );
        assert_eq!(r.file_list, Some(ClipboardFormatId(0xC101)));
        assert_eq!(r.dib, Some(ClipboardFormatId::CF_DIBV5));
    }

    #[test]
    fn local_files_are_walked_with_relative_paths_and_symlinks_skipped() {
        let root = tmp("walk");
        fs::create_dir_all(root.join("zestaw/pod")).unwrap();
        fs::write(root.join("zestaw/a.txt"), b"abc").unwrap();
        fs::write(root.join("zestaw/pod/b.txt"), b"de").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hostname", root.join("zestaw/link")).unwrap();
        let (descs, entries, skipped) =
            build_local_files(&[root.join("zestaw").to_string_lossy().into_owned()]);
        assert_eq!(
            descs.len(),
            entries.len(),
            "indeksy opisów i wpisów muszą się zgadzać"
        );
        let names: Vec<(String, Option<String>)> = descs
            .iter()
            .map(|d| (d.name.clone(), d.relative_path.clone()))
            .collect();
        assert!(names.contains(&("zestaw".into(), None)));
        assert!(names.contains(&("a.txt".into(), Some("zestaw".into()))));
        assert!(names.contains(&("b.txt".into(), Some("zestaw\\pod".into()))));
        #[cfg(unix)]
        assert_eq!(skipped, 1);
        #[cfg(unix)]
        assert!(!names.iter().any(|(n, _)| n == "link"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn names_the_library_would_drop_are_skipped_so_indexes_stay_aligned() {
        let root = tmp("wire");
        // Nazwa na łączu to "d1\\d2\\plik": 191 znaków, ale 380 jednostek UTF-16 (znaki spoza BMP
        // zajmują po dwie), czyli ponad limit pola. Pojedyncza nazwa w Linuksie ma najwyżej 255 bajtów.
        let part: String = std::iter::repeat_n('\u{1F600}', 63).collect();
        let deep = root.join(&part).join(&part);
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join(&part), b"x").unwrap();
        fs::create_dir_all(root.join("a:dane")).unwrap();
        fs::write(root.join("a:dane").join("w.txt"), b"w").unwrap();
        fs::write(root.join("ok.txt"), b"ok").unwrap();
        let (descs, entries, skipped) = build_local_files(&[
            root.join(&part).to_string_lossy().into_owned(),
            root.join("a:dane").to_string_lossy().into_owned(),
            root.join("ok.txt").to_string_lossy().into_owned(),
        ]);
        // Pominięte: plik z za długą nazwą na łączu i katalog "a:dane" (razem z zawartością).
        assert_eq!(skipped, 2);
        assert_eq!(descs.len(), entries.len());
        let names: Vec<_> = entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [part.clone(), part, "ok.txt".into()]);
        assert!(wire_looks_absolute("C:"));
        assert!(wire_looks_absolute("\\\\serwer"));
        assert!(!wire_looks_absolute("dane"));
    }

    #[cfg(unix)]
    #[test]
    fn file_swapped_after_announcement_is_not_served() {
        let root = tmp("swap");
        fs::write(root.join("jawny.txt"), b"jawne dane").unwrap();
        fs::write(root.join("tajny.txt"), b"tajne dane").unwrap();
        let (_, entries, _) =
            build_local_files(&[root.join("jawny.txt").to_string_lossy().into_owned()]);
        let st = ClipState {
            local_files: entries,
            ..Default::default()
        };
        assert!(st.read_local(&range(0, 0, 5)).is_some());
        fs::remove_file(root.join("jawny.txt")).unwrap();
        std::os::unix::fs::symlink(root.join("tajny.txt"), root.join("jawny.txt")).unwrap();
        assert!(st.read_local(&range(0, 0, 5)).is_none());
        // Podmiana przez `rename` innego istniejącego pliku też jest odrzucana.
        fs::remove_file(root.join("jawny.txt")).unwrap();
        fs::rename(root.join("tajny.txt"), root.join("jawny.txt")).unwrap();
        assert!(st.read_local(&range(0, 0, 5)).is_none());
    }

    #[test]
    fn serving_is_limited_to_announced_regular_files() {
        let root = tmp("serve");
        fs::write(root.join("a.bin"), (0u8..100).collect::<Vec<_>>()).unwrap();
        fs::create_dir_all(root.join("d")).unwrap();
        let (_, entries, _) = build_local_files(&[
            root.join("a.bin").to_string_lossy().into_owned(),
            root.join("d").to_string_lossy().into_owned(),
        ]);
        let st = ClipState {
            local_files: entries,
            ..Default::default()
        };

        let r = st.read_local(&range(0, 10, 5)).unwrap();
        assert_eq!(r.data(), &[10, 11, 12, 13, 14]);
        // Zakres wykraczający poza plik zwraca tyle, ile jest.
        assert_eq!(st.read_local(&range(0, 98, 50)).unwrap().data(), &[98, 99]);
        let size = FileContentsRequest {
            flags: FileContentsFlags::SIZE,
            ..range(0, 0, 8)
        };
        assert_eq!(st.read_local(&size).unwrap().data_as_size().unwrap(), 100);
        // Indeks spoza listy, ujemny, katalog.
        assert!(st.read_local(&range(2, 0, 1)).is_none());
        assert!(st.read_local(&range(-1, 0, 1)).is_none());
        assert!(st.read_local(&range(1, 0, 1)).is_none());
        // Plik zamieniony na dowiązanie po ogłoszeniu nie jest serwowany.
        #[cfg(unix)]
        {
            fs::remove_file(root.join("a.bin")).unwrap();
            std::os::unix::fs::symlink("/etc/hostname", root.join("a.bin")).unwrap();
            assert!(st.read_local(&range(0, 0, 4)).is_none());
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn download_plan_skips_traversal_and_keeps_indexes() {
        let files = vec![
            FileDescriptor::new("ok.txt").with_file_size(5),
            FileDescriptor::new("..").with_attributes(ClipboardFileAttributes::DIRECTORY),
            FileDescriptor::new("zly.txt").with_relative_path("..\\poza"),
            FileDescriptor::new("c.txt")
                .with_relative_path("dobry\\kat")
                .with_file_size(7),
            FileDescriptor::new("nul"),
        ];
        let dir = Path::new("/tmp/pobrane");
        let (plan, total, skipped) = plan_download(dir, &files);
        assert_eq!(skipped, 3);
        assert_eq!(total, 12);
        assert_eq!(plan.len(), 2);
        assert_eq!((plan[0].index, plan[1].index), (0, 3));
        assert_eq!(plan[1].dest, dir.join("dobry/kat/c.txt"));
        assert!(plan.iter().all(|p| p.dest.starts_with(dir)));
    }

    #[test]
    fn remote_listing_uses_forward_slashes() {
        let files = [
            FileDescriptor::new("k").with_attributes(ClipboardFileAttributes::DIRECTORY),
            FileDescriptor::new("a.txt")
                .with_relative_path("k\\s")
                .with_file_size(3),
        ];
        let d = describe_remote(&files);
        assert_eq!(
            d[0],
            RemoteFile {
                path: "k".into(),
                size: 0,
                dir: true
            }
        );
        assert_eq!(
            d[1],
            RemoteFile {
                path: "k/s/a.txt".into(),
                size: 3,
                dir: false
            }
        );
    }
}
