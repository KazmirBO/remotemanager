//! Przekierowanie czytników kart inteligentnych do sesji RDP ([MS-RDPESC] w kanale `rdpdr`).
//! Zdalny system widzi czytniki podłączone do tego komputera, więc programy na zdalnym pulpicie
//! mogą rozmawiać z kartą albo kluczem sprzętowym (certyfikaty PIV, KeePassXC z kluczem YubiKey).
//!
//! Biblioteka IronRDP dekoduje wywołania serwera i koduje odpowiedzi, ale samych operacji nie
//! wykonuje. Robi to ten moduł:
//!
//! - `Engine` przyjmuje wywołania w pętli sesji i niczego w niej nie blokuje: operacje na czytniku
//!   idą do wątków. Kontekst ma wątek operacji (lista czytników, łączenie) i osobny wątek czekania
//!   na zmianę stanu czytników, a każda połączona karta własny wątek (polecenia, stan, transakcje).
//!   Czekanie na kartę albo na dotyk klucza trwa dowolnie długo, a obraz i klawiatura sesji działają.
//! - Wyniki wracają kanałem jako `Reply`; pętla sesji zamienia je na komunikaty (`encode`).
//! - Dostęp do czytników jest za cechami `Service`, `Ctx` i `CardDev`: prawdziwa implementacja
//!   (usługa kart Windows) jest w `scard_pcsc`, a testy używają atrapy.
//! - `Names` opcjonalnie pokazuje serwerowi czytniki pod neutralnymi nazwami. KeePassXC pomija
//!   czytniki z "yubikey" w nazwie, więc klucza podłączonego po USB inaczej by nie zobaczył.
//!
//! Serwer jest niezaufany: liczba kontekstów, kart, stanów czytników i rozmiary buforów są
//! ograniczone, nieznany identyfikator daje kod błędu, a komunikat, którego biblioteka nie umie
//! zdekodować, jest pomijany i nie kończy sesji (`Channel`, `Sound`). Treść poleceń karty nigdy nie
//! trafia do dziennika. Serwer z włączonym przekierowaniem może jednak wysłać do karty dowolne
//! polecenie, dlatego funkcja jest domyślnie wyłączona.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ironrdp::core::{EncodeResult, WriteCursor};
use ironrdp::pdu::PduResult;
use ironrdp::pdu::gcc::ChannelName;
use ironrdp::pdu::utils::{CharacterSet, encoded_multistring_len, write_multistring_to_cursor};
use ironrdp::rdpdr::pdu::RdpdrPdu;
use ironrdp::rdpdr::pdu::efs::{
    DeviceControlRequest, DeviceControlResponse, NtStatus, ServerDeviceAnnounceResponse,
    ServerDriveIoRequest,
};
use ironrdp::rdpdr::pdu::esc::{
    CardProtocol, CardState, CardStateFlags, ConnectReturn, EstablishContextReturn,
    GetDeviceTypeIdReturn, GetReaderIconReturn, GetStatusChangeReturn, ListReadersReturn,
    LongReturn, ReadCacheReturn, ReaderStateCommonCall, ReturnCode, ScardCall, ScardContext,
    ScardHandle, ScardIoCtlCode, StatusReturn, TransmitReturn, ndr, rpce,
};
use ironrdp::rdpdr::{Rdpdr, RdpdrBackend};
use ironrdp::rdpsnd::client::{NoopRdpsndBackend, Rdpsnd};
use ironrdp::svc::{CompressionCondition, SvcClientProcessor, SvcMessage, SvcProcessor};

/// Kod zwrotny interfejsu kart (wartości `SCARD_*` z WinSCard); zero oznacza powodzenie.
pub(crate) type Code = u32;

pub(crate) const OK: Code = 0;
pub(crate) const E_INTERNAL: Code = 0x8010_0001;
pub(crate) const E_CANCELLED: Code = 0x8010_0002;
pub(crate) const E_INVALID_HANDLE: Code = 0x8010_0003;
pub(crate) const E_INVALID_PARAMETER: Code = 0x8010_0004;
pub(crate) const E_NO_MEMORY: Code = 0x8010_0006;
pub(crate) const E_UNKNOWN_READER: Code = 0x8010_0009;
pub(crate) const E_TIMEOUT: Code = 0x8010_000A;
pub(crate) const E_PROTO_MISMATCH: Code = 0x8010_000F;
pub(crate) const E_NOT_TRANSACTED: Code = 0x8010_0016;
pub(crate) const E_UNSUPPORTED_FEATURE: Code = 0x8010_0022;
pub(crate) const W_CACHE_ITEM_NOT_FOUND: Code = 0x8010_0070;
pub(crate) const W_CACHE_ITEM_STALE: Code = 0x8010_0071;
pub(crate) const W_CACHE_ITEM_TOO_BIG: Code = 0x8010_0072;

/// Sposób zakończenia transakcji i rozłączenia, który zostawia kartę w spokoju (`SCARD_LEAVE_CARD`).
pub(crate) const LEAVE_CARD: u32 = 0;
/// Czekanie na zmianę stanu bez limitu czasu (`INFINITE`).
pub(crate) const INFINITE: u32 = u32::MAX;

/// Typ czytnika zgłaszany serwerowi (`SCARD_READER_TYPE_USB`); usługa kart go nie udostępnia.
const READER_TYPE_USB: u32 = 0x20;

const MAX_CONTEXTS: usize = 64;
const MAX_CARDS: usize = 32;
const MAX_READER_STATES: usize = 16;
/// Największe polecenie karty i największa odpowiedź (rozszerzone APDU: 65535 bajtów danych i dodatki).
const MAX_SEND: usize = 66 * 1024;
const MAX_RECV: usize = 66 * 1024;
const MAX_CACHE_ITEMS: usize = 256;
const MAX_CACHE_ITEM: usize = 64 * 1024;
/// Tyle czytników dostaje neutralną nazwę i tyle nazw trafia do jednej odpowiedzi.
const MAX_READERS: usize = 32;
/// Tyle razy trafia do dziennika wywołanie, którego biblioteka nie obsługuje (serwer bywa natarczywy).
const MAX_UNSUPPORTED_LOGGED: u32 = 20;
/// Czekanie na zmianę stanu czytników idzie odcinkami tej długości, żeby wątek zauważył zwolnienie
/// kontekstu także wtedy, gdy anulowanie rozminęło się z początkiem czekania.
const WAIT_SLICE_MS: u32 = 1000;

const NEUTRAL_PREFIX: &str = "Smart Card Reader ";

/// Stan jednego czytnika w wywołaniu "czekaj na zmianę stanu": wejście (`current`) i wynik.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StateIo {
    pub reader: String,
    pub current: u32,
    pub event: u32,
    pub atr: Vec<u8>,
}

/// Stan połączonej karty.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CardInfo {
    pub readers: Vec<String>,
    /// Stan karty w numeracji protokołu (0 nieznany ... 6 tryb wybrany).
    pub state: u32,
    /// Aktywny protokół w numeracji WinSCard (T=0 to 1, T=1 to 2, surowy to 0x10000).
    pub protocol: u32,
    pub atr: Vec<u8>,
}

/// Usługa kart systemu.
pub(crate) trait Service: Send + 'static {
    type Ctx: Ctx;
    fn establish(&self) -> Result<Self::Ctx, Code>;
}

/// Kontekst usługi kart. Metody wołają jednocześnie różne wątki: `cancel` i `is_valid` pętla
/// sesji, a `connect` wątek operacji, gdy wątek czekania stoi w `status_change`.
pub(crate) trait Ctx: Send + Sync + 'static {
    type Card: CardDev;
    fn list_readers(&self) -> Result<Vec<String>, Code>;
    /// Czeka na zmianę stanu czytników najwyżej `timeout_ms` i wpisuje wynik do `states`.
    fn status_change(&self, timeout_ms: u32, states: &mut [StateIo]) -> Result<(), Code>;
    fn cancel(&self) -> Result<(), Code>;
    fn is_valid(&self) -> Result<(), Code>;
    /// Łączy z kartą w czytniku; zwraca kartę i aktywny protokół.
    fn connect(
        &self,
        reader: &str,
        share_mode: u32,
        protocols: u32,
    ) -> Result<(Self::Card, u32), Code>;
}

/// Operacje dostępne na karcie, także w trakcie transakcji.
pub(crate) trait CardOps {
    fn transmit(&self, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code>;
    fn status(&self) -> Result<CardInfo, Code>;
}

/// Połączona karta. Transakcja pożycza kartę, więc żyje na stosie wątku karty (`in_transaction`).
pub(crate) trait CardDev: CardOps + Send + 'static {
    type Tx<'a>: CardOps
    where
        Self: 'a;
    fn begin(&mut self) -> Result<Self::Tx<'_>, Code>;
    fn end(tx: Self::Tx<'_>, disposition: u32) -> Result<(), Code>;
    fn disconnect(self, disposition: u32) -> Result<(), Code>;
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Nazwy czytników pokazywane serwerowi. W trybie neutralnym czytnik dostaje nazwę
/// "Smart Card Reader N", stałą do końca sesji; inaczej nazwy przechodzą bez zmian.
pub(crate) struct Names {
    neutral: bool,
    /// Prawdziwe nazwy w kolejności nadawania numerów.
    real: Mutex<Vec<String>>,
    /// Ostatnia lista zapisana w dzienniku, żeby odpytywanie w kółko go nie zalewało.
    logged: Mutex<Option<String>>,
}

impl Names {
    pub(crate) fn new(neutral: bool) -> Self {
        Self {
            neutral,
            real: Mutex::new(Vec::new()),
            logged: Mutex::new(None),
        }
    }

    /// Nazwa czytnika dla serwera.
    fn remote(&self, real: &str) -> String {
        if !self.neutral {
            return real.to_owned();
        }
        let mut list = lock(&self.real);
        let index = match list.iter().position(|name| name == real) {
            Some(index) => index,
            // Ponad limit czytnik zostaje pod własną nazwą.
            None if list.len() >= MAX_READERS => return real.to_owned(),
            None => {
                list.push(real.to_owned());
                list.len() - 1
            }
        };
        format!("{NEUTRAL_PREFIX}{}", index + 1)
    }

    /// Nazwa czytnika w tym systemie. Nazwa, której nie nadaliśmy (np. pseudoczytnik powiadomień
    /// Windows o podłączeniu czytnika), przechodzi bez zmian.
    fn local(&self, remote: &str) -> String {
        if !self.neutral {
            return remote.to_owned();
        }
        remote
            .strip_prefix(NEUTRAL_PREFIX)
            .and_then(|number| number.parse::<usize>().ok())
            .and_then(|number| number.checked_sub(1))
            .and_then(|index| lock(&self.real).get(index).cloned())
            .unwrap_or_else(|| remote.to_owned())
    }

    /// Zapisuje w dzienniku wynik listowania czytników, jeśli różni się od poprzedniego.
    fn log_listing(&self, listing: String) {
        let mut logged = lock(&self.logged);
        if logged.as_deref() != Some(listing.as_str()) {
            crate::log(format!("karty: lista czytników dla serwera: {listing}"));
            *logged = Some(listing);
        }
    }
}

type Req = DeviceControlRequest<ScardIoCtlCode>;

/// Wynik wywołania do odesłania serwerowi.
pub(crate) struct Reply {
    req: Req,
    body: Body,
}

#[derive(Debug, PartialEq)]
enum Body {
    Long(Code),
    Context(Code, u32),
    Readers(Code, Vec<String>),
    States(Code, Vec<StateIo>),
    /// Kod, kontekst, uchwyt karty, aktywny protokół.
    Connected(Code, u32, u32, u32),
    Transmitted(Code, Vec<u8>),
    Status(Code, Option<CardInfo>),
    DeviceType(Code, u32),
    Cache(Code, Vec<u8>),
    Icon(Code),
}

/// Kod zwrotny w typie biblioteki; nieznana wartość daje błąd wewnętrzny.
fn return_code(code: Code) -> ReturnCode {
    const ALL: [ReturnCode; 67] = [
        ReturnCode::Success,
        ReturnCode::InternalError,
        ReturnCode::Cancelled,
        ReturnCode::InvalidHandle,
        ReturnCode::InvalidParameter,
        ReturnCode::InvalidTarget,
        ReturnCode::NoMemory,
        ReturnCode::WaitedTooLong,
        ReturnCode::InsufficientBuffer,
        ReturnCode::UnknownReader,
        ReturnCode::Timeout,
        ReturnCode::SharingViolation,
        ReturnCode::NoSmartcard,
        ReturnCode::UnknownCard,
        ReturnCode::CantDispose,
        ReturnCode::ProtoMismatch,
        ReturnCode::NotReady,
        ReturnCode::InvalidValue,
        ReturnCode::SystemCancelled,
        ReturnCode::CommError,
        ReturnCode::UnknownError,
        ReturnCode::InvalidAtr,
        ReturnCode::NotTransacted,
        ReturnCode::ReaderUnavailable,
        ReturnCode::Shutdown,
        ReturnCode::PciTooSmall,
        ReturnCode::IccInstallation,
        ReturnCode::IccCreateorder,
        ReturnCode::UnsupportedFeature,
        ReturnCode::DirNotFound,
        ReturnCode::FileNotFound,
        ReturnCode::NoDir,
        ReturnCode::ReaderUnsupported,
        ReturnCode::DuplicateReader,
        ReturnCode::CardUnsupported,
        ReturnCode::NoService,
        ReturnCode::ServiceStopped,
        ReturnCode::Unexpected,
        ReturnCode::NoFile,
        ReturnCode::NoAccess,
        ReturnCode::WriteTooMany,
        ReturnCode::BadSeek,
        ReturnCode::InvalidChv,
        ReturnCode::UnknownResMsg,
        ReturnCode::NoSuchCertificate,
        ReturnCode::CertificateUnavailable,
        ReturnCode::NoReadersAvailable,
        ReturnCode::CommDataLost,
        ReturnCode::NoKeyContainer,
        ReturnCode::ServerTooBusy,
        ReturnCode::PinCacheExpired,
        ReturnCode::NoPinCache,
        ReturnCode::ReadOnlyCard,
        ReturnCode::UnsupportedCard,
        ReturnCode::UnresponsiveCard,
        ReturnCode::UnpoweredCard,
        ReturnCode::ResetCard,
        ReturnCode::RemovedCard,
        ReturnCode::SecurityViolation,
        ReturnCode::WrongChv,
        ReturnCode::ChvBlocked,
        ReturnCode::Eof,
        ReturnCode::CancelledByUser,
        ReturnCode::CardNotAuthenticated,
        ReturnCode::CacheItemNotFound,
        ReturnCode::CacheItemStale,
        ReturnCode::CacheItemTooBig,
    ];
    ALL.into_iter()
        .find(|rc| u32::from(*rc) == code)
        .unwrap_or(ReturnCode::InternalError)
}

fn card_state(state: u32) -> CardState {
    match state {
        1 => CardState::Absent,
        2 => CardState::Present,
        3 => CardState::Swallowed,
        4 => CardState::Powered,
        5 => CardState::Negotiable,
        6 => CardState::SpecificMode,
        _ => CardState::Unknown,
    }
}

/// ATR w buforze stałej długości, jak w strukturach protokołu; zwraca też użytą długość.
fn atr_buffer<const N: usize>(atr: &[u8]) -> ([u8; N], u32) {
    let mut out = [0u8; N];
    let len = atr.len().min(N);
    out[..len].copy_from_slice(&atr[..len]);
    (out, u32::try_from(len).unwrap_or(0))
}

/// Odpowiedź na listowanie czytników w wersji ANSI (`ListReadersA`). Biblioteka koduje listę
/// zawsze w UTF-16, a programy wołające wersję ANSI (KeePassXC na Windows) czytają ją bajt po
/// bajcie, więc dostawałyby pierwszą literę pierwszej nazwy.
#[derive(Debug)]
struct ReadersAnsi {
    code: ReturnCode,
    readers: Vec<String>,
}

impl rpce::HeaderlessEncode for ReadersAnsi {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ironrdp::core::ensure_size!(ctx: "ListReadersA_Return", in: dst, size: self.size());
        dst.write_u32(self.code.into());
        let length: u32 = ironrdp::core::cast_length!(
            "ListReadersA_Return",
            "readers",
            encoded_multistring_len(&self.readers, CharacterSet::Ansi)
        )?;
        let mut index = 0;
        ndr::encode_ptr(Some(length), &mut index, dst)?;
        dst.write_u32(length);
        write_multistring_to_cursor(dst, &self.readers, CharacterSet::Ansi)
    }

    fn name(&self) -> &'static str {
        "ListReadersA_Return"
    }

    fn size(&self) -> usize {
        4 + ndr::ptr_size(true) + 4 + encoded_multistring_len(&self.readers, CharacterSet::Ansi)
    }
}

/// Zamienia wynik na komunikat kanału `rdpdr`.
pub(crate) fn encode(reply: Reply) -> SvcMessage {
    let Reply { req, body } = reply;
    let output: Box<dyn rpce::Encode> = match body {
        Body::Long(code) => Box::new(LongReturn::new(return_code(code))),
        Body::Context(code, id) => Box::new(EstablishContextReturn::new(
            return_code(code),
            ScardContext::new(id),
        )),
        Body::Readers(code, readers) => {
            if req.io_control_code == ScardIoCtlCode::ListReadersA {
                Box::new(rpce::Pdu(ReadersAnsi {
                    code: return_code(code),
                    readers,
                }))
            } else {
                Box::new(ListReadersReturn::new(return_code(code), readers))
            }
        }
        Body::States(code, states) => Box::new(GetStatusChangeReturn::new(
            return_code(code),
            states
                .iter()
                .map(|s| {
                    let (atr, atr_length) = atr_buffer::<36>(&s.atr);
                    ReaderStateCommonCall {
                        current_state: CardStateFlags::from_bits_retain(s.current),
                        event_state: CardStateFlags::from_bits_retain(s.event),
                        atr_length,
                        atr,
                    }
                })
                .collect(),
        )),
        Body::Connected(code, context, handle, protocol) => Box::new(ConnectReturn::new(
            return_code(code),
            ScardHandle::new(ScardContext::new(context), handle),
            CardProtocol::from_bits_retain(protocol),
        )),
        Body::Transmitted(code, data) => {
            Box::new(TransmitReturn::new(return_code(code), None, data))
        }
        Body::Status(code, info) => {
            let info = info.unwrap_or(CardInfo {
                readers: Vec::new(),
                state: 0,
                protocol: 0,
                atr: Vec::new(),
            });
            let (atr, atr_length) = atr_buffer::<32>(&info.atr);
            // Nazwy czytników wracają w tym kodowaniu, w którym serwer o nie zapytał.
            let encoding = if req.io_control_code == ScardIoCtlCode::StatusA {
                CharacterSet::Ansi
            } else {
                CharacterSet::Unicode
            };
            Box::new(StatusReturn::new(
                return_code(code),
                info.readers,
                card_state(info.state),
                CardProtocol::from_bits_retain(info.protocol),
                atr,
                atr_length,
                encoding,
            ))
        }
        Body::DeviceType(code, kind) => {
            Box::new(GetDeviceTypeIdReturn::new(return_code(code), kind))
        }
        Body::Cache(code, data) => Box::new(ReadCacheReturn::new(return_code(code), data)),
        Body::Icon(code) => Box::new(GetReaderIconReturn::new(return_code(code), Vec::new())),
    };
    SvcMessage::from(RdpdrPdu::DeviceControlResponse(DeviceControlResponse::new(
        req,
        NtStatus::SUCCESS,
        Some(output),
    )))
}

/// Wykonuje operację na czytniku tak, żeby panika w bibliotece (np. przy nieznanym kodzie błędu
/// systemu) dała kod błędu zamiast wątku, który przestał odpowiadać.
fn guard<T>(op: impl FnOnce() -> Result<T, Code>) -> Result<T, Code> {
    catch_unwind(AssertUnwindSafe(op)).unwrap_or(Err(E_INTERNAL))
}

fn code_of(result: Result<(), Code>) -> Code {
    result.err().unwrap_or(OK)
}

enum CtxJob {
    ListReaders(Req),
    StatusChange(Req, u32, Vec<StateIo>),
    Connect {
        req: Req,
        reader: String,
        share_mode: u32,
        protocols: u32,
        context: u32,
        handle: u32,
        jobs: Receiver<CardJob>,
        alive: Arc<AtomicBool>,
    },
}

impl CtxJob {
    /// Odpowiedź z kodem błędu w kształcie właściwym dla wywołania.
    fn fail(self, code: Code) -> Reply {
        match self {
            CtxJob::ListReaders(req) => Reply {
                req,
                body: Body::Readers(code, Vec::new()),
            },
            CtxJob::StatusChange(req, _, states) => Reply {
                req,
                body: Body::States(code, states),
            },
            CtxJob::Connect {
                req,
                context,
                alive,
                ..
            } => {
                alive.store(false, Ordering::Release);
                Reply {
                    req,
                    body: Body::Connected(code, context, 0, 0),
                }
            }
        }
    }
}

enum CardJob {
    Transmit(Req, Vec<u8>, usize),
    Status(Req),
    Begin(Req),
    End(Req, u32),
    Disconnect(Req, u32),
}

impl CardJob {
    fn fail(self, code: Code) -> Reply {
        match self {
            CardJob::Transmit(req, ..) => Reply {
                req,
                body: Body::Transmitted(code, Vec::new()),
            },
            CardJob::Status(req) => Reply {
                req,
                body: Body::Status(code, None),
            },
            CardJob::Begin(req) | CardJob::End(req, _) | CardJob::Disconnect(req, _) => Reply {
                req,
                body: Body::Long(code),
            },
        }
    }
}

/// To, co wątki kontekstu dzielą z pętlą sesji.
struct Shared<X> {
    ctx: X,
    names: Arc<Names>,
    /// Kontekst został zwolniony: czekanie na zmianę stanu ma się skończyć.
    released: AtomicBool,
}

/// Czeka na zmianę stanu czytników odcinkami po `WAIT_SLICE_MS`. Ponowienie z tym samym stanem
/// wejściowym znaczy dla usługi kart to samo co jedno dłuższe czekanie.
fn wait_for_change<X: Ctx>(shared: &Shared<X>, timeout_ms: u32, states: &mut [StateIo]) -> Code {
    let deadline = (timeout_ms != INFINITE)
        .then(|| Instant::now() + Duration::from_millis(u64::from(timeout_ms)));
    loop {
        if shared.released.load(Ordering::Acquire) {
            return E_CANCELLED;
        }
        let left = deadline.map(|deadline| {
            // W górę do pełnej milisekundy, żeby nie skończyć przed czasem.
            let left = deadline
                .saturating_duration_since(Instant::now())
                .as_micros()
                .div_ceil(1000);
            u32::try_from(left).unwrap_or(INFINITE)
        });
        let slice = left.map_or(WAIT_SLICE_MS, |left| left.min(WAIT_SLICE_MS));
        let code = code_of(guard(|| shared.ctx.status_change(slice, states)));
        if code != E_TIMEOUT || left.is_some_and(|left| left <= slice) {
            return code;
        }
    }
}

/// Wątek kontekstu. Kontekst ma takie dwa: jeden na operacje, drugi na czekanie na zmianę stanu,
/// żeby czekanie bez limitu czasu nie wstrzymywało łączenia z kartą.
fn context_loop<X: Ctx>(shared: &Shared<X>, jobs: Receiver<CtxJob>, out: &Sender<Reply>) {
    for job in jobs {
        let reply = match job {
            CtxJob::ListReaders(req) => match guard(|| shared.ctx.list_readers()) {
                Ok(readers) => {
                    let readers: Vec<String> = readers
                        .iter()
                        .take(MAX_READERS)
                        .map(|name| shared.names.remote(name))
                        .collect();
                    shared.names.log_listing(if readers.is_empty() {
                        "pusta".to_owned()
                    } else {
                        readers.join(", ")
                    });
                    Reply {
                        req,
                        body: Body::Readers(OK, readers),
                    }
                }
                Err(code) => {
                    shared.names.log_listing(format!("brak (kod {code:#010x})"));
                    Reply {
                        req,
                        body: Body::Readers(code, Vec::new()),
                    }
                }
            },
            CtxJob::StatusChange(req, timeout_ms, mut states) => {
                for state in &mut states {
                    state.reader = shared.names.local(&state.reader);
                }
                let code = wait_for_change(shared, timeout_ms, &mut states);
                Reply {
                    req,
                    body: Body::States(code, states),
                }
            }
            CtxJob::Connect {
                req,
                reader,
                share_mode,
                protocols,
                context,
                handle,
                jobs,
                alive,
            } => {
                let local = shared.names.local(&reader);
                match guard(|| shared.ctx.connect(&local, share_mode, protocols)) {
                    Ok((card, protocol)) => {
                        let (card_out, card_alive) = (out.clone(), Arc::clone(&alive));
                        let names = Arc::clone(&shared.names);
                        let spawned = std::thread::Builder::new()
                            .name("scard-card".into())
                            .spawn(move || card_loop(card, &jobs, &card_out, &names, &card_alive));
                        if spawned.is_ok() {
                            crate::log(format!("karty: połączono z kartą w czytniku {reader}"));
                            Reply {
                                req,
                                body: Body::Connected(OK, context, handle, protocol),
                            }
                        } else {
                            alive.store(false, Ordering::Release);
                            Reply {
                                req,
                                body: Body::Connected(E_INTERNAL, context, 0, 0),
                            }
                        }
                    }
                    Err(code) => {
                        alive.store(false, Ordering::Release);
                        crate::log(format!(
                            "karty: brak połączenia z kartą w czytniku {reader} (kod {code:#010x})"
                        ));
                        Reply {
                            req,
                            body: Body::Connected(code, context, 0, 0),
                        }
                    }
                }
            }
        };
        if out.send(reply).is_err() {
            return;
        }
    }
}

fn spawn_context<X: Ctx>(shared: &Arc<Shared<X>>, out: &Sender<Reply>) -> Option<Sender<CtxJob>> {
    let (jobs, jobs_rx) = channel();
    let (shared, out) = (Arc::clone(shared), out.clone());
    std::thread::Builder::new()
        .name("scard-context".into())
        .spawn(move || context_loop(&shared, jobs_rx, &out))
        .ok()
        .map(|_| jobs)
}

fn transmit_reply(card: &impl CardOps, req: Req, send: &[u8], max_recv: usize) -> Reply {
    match guard(|| card.transmit(send, max_recv)) {
        Ok(data) => Reply {
            req,
            body: Body::Transmitted(OK, data),
        },
        Err(code) => Reply {
            req,
            body: Body::Transmitted(code, Vec::new()),
        },
    }
}

fn status_reply(card: &impl CardOps, req: Req, names: &Names) -> Reply {
    match guard(|| card.status()) {
        Ok(mut info) => {
            info.readers.truncate(MAX_READERS);
            for reader in &mut info.readers {
                *reader = names.remote(reader);
            }
            Reply {
                req,
                body: Body::Status(OK, Some(info)),
            }
        }
        Err(code) => Reply {
            req,
            body: Body::Status(code, None),
        },
    }
}

/// Jak skończyła się transakcja.
enum TxEnd {
    Ended,
    /// Serwer rozłączył kartę w trakcie transakcji.
    Disconnect(Req, u32),
    /// Sesja albo kontekst już nie istnieje.
    Closed,
}

/// Obsługuje polecenia karty, dopóki trwa transakcja. Transakcja pożycza kartę, więc musi żyć tutaj,
/// na stosie wątku karty, a nie w tablicy uchwytów.
fn in_transaction<C: CardDev>(
    tx: C::Tx<'_>,
    jobs: &Receiver<CardJob>,
    out: &Sender<Reply>,
    names: &Names,
    commands: &mut u64,
) -> TxEnd {
    // Zagnieżdżone rozpoczęcia liczymy sami: prawdziwa transakcja kończy się z ostatnim zakończeniem.
    let mut nested = 0u32;
    loop {
        let Ok(job) = jobs.recv() else {
            let _ = guard(move || C::end(tx, LEAVE_CARD));
            return TxEnd::Closed;
        };
        let reply = match job {
            CardJob::Begin(req) => {
                nested = nested.saturating_add(1);
                Reply {
                    req,
                    body: Body::Long(OK),
                }
            }
            CardJob::End(req, disposition) => {
                if nested > 0 {
                    nested -= 1;
                    Reply {
                        req,
                        body: Body::Long(OK),
                    }
                } else {
                    let code = code_of(guard(move || C::end(tx, disposition)));
                    let _ = out.send(Reply {
                        req,
                        body: Body::Long(code),
                    });
                    return TxEnd::Ended;
                }
            }
            CardJob::Transmit(req, send, max_recv) => {
                *commands += 1;
                transmit_reply(&tx, req, &send, max_recv)
            }
            CardJob::Status(req) => status_reply(&tx, req, names),
            CardJob::Disconnect(req, disposition) => {
                let _ = guard(move || C::end(tx, LEAVE_CARD));
                return TxEnd::Disconnect(req, disposition);
            }
        };
        if out.send(reply).is_err() {
            let _ = guard(move || C::end(tx, LEAVE_CARD));
            return TxEnd::Closed;
        }
    }
}

/// Wątek karty: polecenia, stan, transakcje i rozłączenie, po kolei.
fn card_loop<C: CardDev>(
    mut card: C,
    jobs: &Receiver<CardJob>,
    out: &Sender<Reply>,
    names: &Names,
    alive: &AtomicBool,
) {
    // Liczba poleceń trafia do dziennika przy rozłączeniu: widać, czy program w ogóle rozmawiał z kartą.
    let mut commands = 0u64;
    let disconnect = loop {
        let Ok(job) = jobs.recv() else {
            break None;
        };
        let reply = match job {
            CardJob::Begin(req) => {
                let borrowed = &mut card;
                match guard(move || borrowed.begin()) {
                    Ok(tx) => {
                        if out
                            .send(Reply {
                                req,
                                body: Body::Long(OK),
                            })
                            .is_err()
                        {
                            let _ = guard(move || C::end(tx, LEAVE_CARD));
                            break None;
                        }
                        match in_transaction::<C>(tx, jobs, out, names, &mut commands) {
                            TxEnd::Ended => continue,
                            TxEnd::Disconnect(req, disposition) => break Some((req, disposition)),
                            TxEnd::Closed => break None,
                        }
                    }
                    Err(code) => Reply {
                        req,
                        body: Body::Long(code),
                    },
                }
            }
            CardJob::End(req, _) => Reply {
                req,
                body: Body::Long(E_NOT_TRANSACTED),
            },
            CardJob::Transmit(req, send, max_recv) => {
                commands += 1;
                transmit_reply(&card, req, &send, max_recv)
            }
            CardJob::Status(req) => status_reply(&card, req, names),
            CardJob::Disconnect(req, disposition) => break Some((req, disposition)),
        };
        if out.send(reply).is_err() {
            break None;
        }
    };
    alive.store(false, Ordering::Release);
    crate::log(format!("karty: rozłączono kartę, poleceń: {commands}"));
    match disconnect {
        Some((req, disposition)) => {
            let code = code_of(guard(move || card.disconnect(disposition)));
            let _ = out.send(Reply {
                req,
                body: Body::Long(code),
            });
        }
        // Serwer porzucił kartę bez rozłączenia (zwolnił kontekst albo sesja się kończy): zostawiamy
        // ją w spokoju. Samo porzucenie uchwytu w bibliotece PC/SC resetowałoby kartę.
        None => {
            let _ = guard(move || card.disconnect(LEAVE_CARD));
        }
    }
}

struct ContextEntry<X> {
    shared: Arc<Shared<X>>,
    jobs: Sender<CtxJob>,
    /// Wątek czekania na zmianę stanu powstaje przy pierwszym takim wywołaniu.
    waits: Option<Sender<CtxJob>>,
}

struct CardEntry {
    jobs: Sender<CardJob>,
    context: u32,
    alive: Arc<AtomicBool>,
}

/// Rozdziela wywołania serwera między wątki i pilnuje tablic identyfikatorów. Działa w pętli sesji,
/// więc niczego nie wykonuje na czytniku poza szybkim otwarciem i unieważnieniem kontekstu.
pub(crate) struct Engine<S: Service> {
    service: S,
    out: Sender<Reply>,
    names: Arc<Names>,
    contexts: HashMap<u32, ContextEntry<S::Ctx>>,
    cards: HashMap<u32, CardEntry>,
    next_id: u32,
    /// Pamięć podręczna danych kart, o którą prosi system zdalny: klucz to identyfikator karty
    /// i nazwa wpisu, wartość to licznik świeżości i dane.
    cache: HashMap<(Vec<u8>, String), (u32, Vec<u8>)>,
    unsupported_logged: u32,
    establish_failed_logged: bool,
}

impl<S: Service> Engine<S> {
    /// `neutral_names` pokazuje serwerowi czytniki pod neutralnymi nazwami (`Names`).
    pub(crate) fn new(service: S, out: Sender<Reply>, neutral_names: bool) -> Self {
        Self {
            service,
            out,
            names: Arc::new(Names::new(neutral_names)),
            contexts: HashMap::new(),
            cards: HashMap::new(),
            next_id: 0,
            cache: HashMap::new(),
            unsupported_logged: 0,
            establish_failed_logged: false,
        }
    }

    /// Nowy identyfikator kontekstu albo karty; nigdy zero i nigdy używany.
    fn allocate(&mut self) -> u32 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            let id = self.next_id;
            if id != 0 && !self.contexts.contains_key(&id) && !self.cards.contains_key(&id) {
                return id;
            }
        }
    }

    fn reply(&self, req: Req, body: Body) {
        // Brak odbiorcy oznacza koniec sesji.
        let _ = self.out.send(Reply { req, body });
    }

    fn send_to_context(&self, context: u32, job: CtxJob) {
        let reply = match self.contexts.get(&context) {
            Some(entry) => match entry.jobs.send(job) {
                Ok(()) => return,
                Err(failed) => failed.0.fail(E_INTERNAL),
            },
            None => job.fail(E_INVALID_HANDLE),
        };
        let _ = self.out.send(reply);
    }

    /// Czekanie na zmianę stanu idzie do osobnego wątku kontekstu.
    fn send_to_waiter(&mut self, context: u32, job: CtxJob) {
        let reply = match self.contexts.get_mut(&context) {
            Some(entry) => {
                if entry.waits.is_none() {
                    entry.waits = spawn_context(&entry.shared, &self.out);
                }
                match &entry.waits {
                    Some(waits) => match waits.send(job) {
                        Ok(()) => return,
                        Err(failed) => failed.0.fail(E_INTERNAL),
                    },
                    None => job.fail(E_INTERNAL),
                }
            }
            None => job.fail(E_INVALID_HANDLE),
        };
        let _ = self.out.send(reply);
    }

    fn send_to_card(&self, handle: u32, job: CardJob) {
        let reply = match self.cards.get(&handle) {
            Some(entry) => match entry.jobs.send(job) {
                Ok(()) => return,
                Err(failed) => failed.0.fail(E_INVALID_HANDLE),
            },
            None => job.fail(E_INVALID_HANDLE),
        };
        let _ = self.out.send(reply);
    }

    /// Obsługuje jedno wywołanie serwera; odpowiedź przychodzi kanałem `Reply`, od razu albo później.
    pub(crate) fn handle(&mut self, req: Req, call: ScardCall) {
        match call {
            ScardCall::AccessStartedEventCall(_) => self.reply(req, Body::Long(OK)),
            ScardCall::EstablishContextCall(_) => self.establish(req),
            ScardCall::ContextCall(call) => self.context_call(req, call.context.value),
            ScardCall::ListReadersCall(call) => {
                self.send_to_context(call.context.value, CtxJob::ListReaders(req));
            }
            ScardCall::GetStatusChangeCall(call) => {
                if call.states.len() > MAX_READER_STATES {
                    self.reply(req, Body::States(E_INVALID_PARAMETER, Vec::new()));
                    return;
                }
                let states = call
                    .states
                    .into_iter()
                    .map(|s| StateIo {
                        reader: s.reader,
                        current: s.common.current_state.bits(),
                        event: s.common.current_state.bits(),
                        atr: Vec::new(),
                    })
                    .collect();
                self.send_to_waiter(
                    call.context.value,
                    CtxJob::StatusChange(req, call.timeout, states),
                );
            }
            ScardCall::ConnectCall(call) => {
                self.connect(
                    req,
                    call.common.context.value,
                    call.reader,
                    call.common.share_mode,
                    call.common.preferred_protocols.bits(),
                );
            }
            ScardCall::HCardAndDispositionCall(call) => {
                let handle = call.handle.value;
                match req.io_control_code {
                    ScardIoCtlCode::BeginTransaction => {
                        self.send_to_card(handle, CardJob::Begin(req))
                    }
                    ScardIoCtlCode::EndTransaction => {
                        self.send_to_card(handle, CardJob::End(req, call.disposition));
                    }
                    ScardIoCtlCode::Disconnect => {
                        self.send_to_card(handle, CardJob::Disconnect(req, call.disposition));
                        // Wątek karty dokończy rozłączenie; uchwyt przestaje istnieć od razu.
                        self.cards.remove(&handle);
                    }
                    _ => self.reply(req, Body::Long(E_UNSUPPORTED_FEATURE)),
                }
            }
            ScardCall::TransmitCall(call) => {
                if call.send_buffer.len() > MAX_SEND {
                    self.reply(req, Body::Transmitted(E_INVALID_PARAMETER, Vec::new()));
                    return;
                }
                let wanted = usize::try_from(call.recv_length).unwrap_or(MAX_RECV);
                let max_recv = if wanted == 0 {
                    MAX_RECV
                } else {
                    wanted.min(MAX_RECV)
                };
                self.send_to_card(
                    call.handle.value,
                    CardJob::Transmit(req, call.send_buffer, max_recv),
                );
            }
            ScardCall::StatusCall(call) => {
                self.send_to_card(call.handle.value, CardJob::Status(req))
            }
            ScardCall::GetDeviceTypeIdCall(call) => {
                let body = if self.contexts.contains_key(&call.context.value) {
                    Body::DeviceType(OK, READER_TYPE_USB)
                } else {
                    Body::DeviceType(E_INVALID_HANDLE, 0)
                };
                self.reply(req, body);
            }
            ScardCall::ReadCacheCall(call) => {
                let key = (call.common.card_uuid, call.lookup_name);
                let body = match self.cache.get(&key) {
                    None => Body::Cache(W_CACHE_ITEM_NOT_FOUND, Vec::new()),
                    Some((freshness, _)) if *freshness != call.common.freshness_counter => {
                        Body::Cache(W_CACHE_ITEM_STALE, Vec::new())
                    }
                    Some((_, data)) => Body::Cache(OK, data.clone()),
                };
                self.reply(req, body);
            }
            ScardCall::WriteCacheCall(call) => {
                let key = (call.common.card_uuid, call.lookup_name);
                let code = if call.common.data.len() > MAX_CACHE_ITEM {
                    W_CACHE_ITEM_TOO_BIG
                } else if self.cache.len() >= MAX_CACHE_ITEMS && !self.cache.contains_key(&key) {
                    E_NO_MEMORY
                } else {
                    self.cache
                        .insert(key, (call.common.freshness_counter, call.common.data));
                    OK
                };
                self.reply(req, Body::Long(code));
            }
            ScardCall::GetReaderIconCall(_) => self.reply(req, Body::Icon(E_UNSUPPORTED_FEATURE)),
            ScardCall::Unsupported => {
                if self.unsupported_logged < MAX_UNSUPPORTED_LOGGED {
                    self.unsupported_logged += 1;
                    crate::log(format!(
                        "karty: nieobsługiwane wywołanie {:?}",
                        req.io_control_code
                    ));
                }
                self.reply(req, Body::Long(E_UNSUPPORTED_FEATURE));
            }
        }
    }

    fn establish(&mut self, req: Req) {
        if self.contexts.len() >= MAX_CONTEXTS {
            self.reply(req, Body::Context(E_NO_MEMORY, 0));
            return;
        }
        let ctx = match guard(|| self.service.establish()) {
            Ok(ctx) => ctx,
            Err(code) => {
                if !self.establish_failed_logged {
                    self.establish_failed_logged = true;
                    crate::log(format!(
                        "karty: usługa kart tego komputera odmówiła (kod {code:#010x})"
                    ));
                }
                self.reply(req, Body::Context(code, 0));
                return;
            }
        };
        let shared = Arc::new(Shared {
            ctx,
            names: Arc::clone(&self.names),
            released: AtomicBool::new(false),
        });
        let Some(jobs) = spawn_context(&shared, &self.out) else {
            self.reply(req, Body::Context(E_INTERNAL, 0));
            return;
        };
        let id = self.allocate();
        self.contexts.insert(
            id,
            ContextEntry {
                shared,
                jobs,
                waits: None,
            },
        );
        self.reply(req, Body::Context(OK, id));
    }

    /// Zwolnienie, sprawdzenie i anulowanie kontekstu: rozróżnia je kod wywołania.
    fn context_call(&mut self, req: Req, context: u32) {
        let code = match req.io_control_code {
            ScardIoCtlCode::ReleaseContext => match self.contexts.remove(&context) {
                Some(entry) => {
                    // Przerywa czekanie na zmianę stanu, żeby wątki kontekstu mogły się skończyć.
                    entry.shared.released.store(true, Ordering::Release);
                    let _ = guard(|| entry.shared.ctx.cancel());
                    self.cards.retain(|_, card| card.context != context);
                    OK
                }
                None => E_INVALID_HANDLE,
            },
            ScardIoCtlCode::IsValidContext => match self.contexts.get(&context) {
                Some(entry) => code_of(guard(|| entry.shared.ctx.is_valid())),
                None => E_INVALID_HANDLE,
            },
            ScardIoCtlCode::Cancel => match self.contexts.get(&context) {
                Some(entry) => code_of(guard(|| entry.shared.ctx.cancel())),
                None => E_INVALID_HANDLE,
            },
            _ => E_UNSUPPORTED_FEATURE,
        };
        self.reply(req, Body::Long(code));
    }

    fn connect(&mut self, req: Req, context: u32, reader: String, share_mode: u32, protocols: u32) {
        // Uchwyty kart, których wątek już się skończył, zwalniają miejsce.
        self.cards
            .retain(|_, card| card.alive.load(Ordering::Acquire));
        if !self.contexts.contains_key(&context) {
            self.reply(req, Body::Connected(E_INVALID_HANDLE, context, 0, 0));
            return;
        }
        if self.cards.len() >= MAX_CARDS {
            self.reply(req, Body::Connected(E_NO_MEMORY, context, 0, 0));
            return;
        }
        let handle = self.allocate();
        let (jobs, jobs_rx) = channel();
        let alive = Arc::new(AtomicBool::new(true));
        self.cards.insert(
            handle,
            CardEntry {
                jobs,
                context,
                alive: Arc::clone(&alive),
            },
        );
        self.send_to_context(
            context,
            CtxJob::Connect {
                req,
                reader,
                share_mode,
                protocols,
                context,
                handle,
                jobs: jobs_rx,
                alive,
            },
        );
    }
}

/// Zaplecze kanału `rdpdr`: przekazuje wywołania kart do `Engine`. Dysków nie przekierowujemy.
pub(crate) struct Backend {
    handler: Box<dyn FnMut(Req, ScardCall) + Send>,
}

impl Backend {
    pub(crate) fn new<S: Service>(mut engine: Engine<S>) -> Self {
        Self {
            handler: Box::new(move |req, call| engine.handle(req, call)),
        }
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scard::Backend")
    }
}

ironrdp::core::impl_as_any!(Backend);

impl RdpdrBackend for Backend {
    fn handle_server_device_announce_response(
        &mut self,
        pdu: ServerDeviceAnnounceResponse,
    ) -> PduResult<()> {
        crate::log(format!(
            "karty: serwer odpowiedział na zgłoszenie czytników ({:?})",
            pdu.result_code
        ));
        Ok(())
    }

    fn handle_scard_call(&mut self, req: Req, call: ScardCall) -> PduResult<()> {
        (self.handler)(req, call);
        Ok(())
    }

    fn handle_drive_io_request(
        &mut self,
        _req: ServerDriveIoRequest,
    ) -> PduResult<Vec<SvcMessage>> {
        Ok(Vec::new())
    }
}

/// Wynik kanału z biblioteki: komunikat serwera, którego biblioteka nie umie zdekodować, jest
/// pomijany z wpisem w dzienniku zamiast kończyć całą sesję.
fn tolerant(channel: &str, result: PduResult<Vec<SvcMessage>>) -> PduResult<Vec<SvcMessage>> {
    Ok(result.unwrap_or_else(|e| {
        crate::log(format!(
            "karty: kanał {channel} pominął komunikat serwera: {e}"
        ));
        Vec::new()
    }))
}

/// Kanał `rdpdr` biblioteki zgłaszający serwerowi jedno urządzenie: czytniki kart.
#[derive(Debug)]
pub(crate) struct Channel(Rdpdr);

impl Channel {
    pub(crate) fn new(backend: Backend, computer_name: String) -> Self {
        Self(Rdpdr::new(Box::new(backend), computer_name).with_smartcard(1))
    }
}

ironrdp::core::impl_as_any!(Channel);

impl SvcProcessor for Channel {
    fn channel_name(&self) -> ChannelName {
        self.0.channel_name()
    }

    fn compression_condition(&self) -> CompressionCondition {
        self.0.compression_condition()
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.0.start()
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        tolerant("rdpdr", self.0.process(payload))
    }
}

impl SvcClientProcessor for Channel {}

/// Kanał dźwięku, którego serwer Windows wymaga obok `rdpdr` ([MS-RDPEFS], dodatek A, uwaga 1).
/// Nie zgłasza żadnego formatu dźwięku, więc serwer niczego nie odtwarza po stronie klienta.
#[derive(Debug)]
pub(crate) struct Sound(Rdpsnd);

impl Sound {
    pub(crate) fn new() -> Self {
        Self(Rdpsnd::new(Box::new(NoopRdpsndBackend)))
    }
}

ironrdp::core::impl_as_any!(Sound);

impl SvcProcessor for Sound {
    fn channel_name(&self) -> ChannelName {
        self.0.channel_name()
    }

    fn compression_condition(&self) -> CompressionCondition {
        self.0.compression_condition()
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.0.start()
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        tolerant("rdpsnd", self.0.process(payload))
    }
}

impl SvcClientProcessor for Sound {}

#[cfg(test)]
mod tests {
    use std::sync::Condvar;
    use std::sync::mpsc::RecvTimeoutError;

    use ironrdp::rdpdr::pdu::efs::{DeviceIoRequest, MajorFunction, MinorFunction};
    use ironrdp::rdpdr::pdu::esc::{
        ConnectCall, ConnectCommon, ContextCall, EstablishContextCall, GetDeviceTypeIdCall,
        GetStatusChangeCall, HCardAndDispositionCall, ListReadersCall, ReadCacheCall,
        ReadCacheCommon, ReaderState, SCardIORequest, Scope, StatusCall, TransmitCall,
        WriteCacheCall, WriteCacheCommon,
    };

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const YUBI: &str = "Yubico YubiKey OTP+FIDO+CCID 0";
    const ATR: [u8; 4] = [0x3b, 0xfd, 0x13, 0x00];

    /// Atrapa usługi kart: zapisuje, co się z nią działo, i daje sterować czekaniem.
    #[derive(Default)]
    struct World {
        readers: Vec<String>,
        events: Mutex<Vec<String>>,
        cancelled: Mutex<bool>,
        wake: Condvar,
        establish_error: Option<Code>,
        panic_on_list: bool,
    }

    impl World {
        fn note(&self, event: impl Into<String>) {
            lock(&self.events).push(event.into());
        }

        fn events(&self) -> Vec<String> {
            lock(&self.events).clone()
        }
    }

    struct MockService(Arc<World>);
    struct MockCtx(Arc<World>);
    struct MockCard(Arc<World>);
    struct MockTx<'a>(&'a MockCard);

    impl Service for MockService {
        type Ctx = MockCtx;
        fn establish(&self) -> Result<MockCtx, Code> {
            match self.0.establish_error {
                Some(code) => Err(code),
                None => Ok(MockCtx(Arc::clone(&self.0))),
            }
        }
    }

    impl Ctx for MockCtx {
        type Card = MockCard;

        fn list_readers(&self) -> Result<Vec<String>, Code> {
            assert!(!self.0.panic_on_list, "atrapa: panika w bibliotece");
            Ok(self.0.readers.clone())
        }

        fn status_change(&self, timeout_ms: u32, states: &mut [StateIo]) -> Result<(), Code> {
            for state in states.iter() {
                self.0.note(format!("wait {} {timeout_ms}", state.reader));
            }
            // Stan "nieznany" (zero) dostaje odpowiedź od razu, jak w prawdziwej usłudze.
            if states.iter().any(|state| state.current == 0) {
                for state in states.iter_mut() {
                    state.event = 0x22;
                    state.atr = ATR.to_vec();
                }
                return Ok(());
            }
            let cancelled = lock(&self.0.cancelled);
            let (mut cancelled, _) = self
                .0
                .wake
                .wait_timeout_while(
                    cancelled,
                    Duration::from_millis(u64::from(timeout_ms)),
                    |c| !*c,
                )
                .unwrap_or_else(PoisonError::into_inner);
            if *cancelled {
                *cancelled = false;
                Err(E_CANCELLED)
            } else {
                Err(E_TIMEOUT)
            }
        }

        fn cancel(&self) -> Result<(), Code> {
            *lock(&self.0.cancelled) = true;
            self.0.wake.notify_all();
            Ok(())
        }

        fn is_valid(&self) -> Result<(), Code> {
            Ok(())
        }

        fn connect(
            &self,
            reader: &str,
            share_mode: u32,
            protocols: u32,
        ) -> Result<(MockCard, u32), Code> {
            self.0
                .note(format!("connect {reader} {share_mode} {protocols}"));
            if self.0.readers.iter().any(|name| name == reader) {
                Ok((MockCard(Arc::clone(&self.0)), 2))
            } else {
                Err(E_UNKNOWN_READER)
            }
        }
    }

    fn mock_transmit(world: &World, prefix: &str, send: &[u8], max_recv: usize) -> Vec<u8> {
        world.note(format!("{prefix}transmit {} {max_recv}", send.len()));
        let mut data: Vec<u8> = send.iter().rev().copied().collect();
        data.extend([0x90, 0x00]);
        data
    }

    fn mock_status(world: &World) -> CardInfo {
        CardInfo {
            readers: world.readers.clone(),
            state: 6,
            protocol: 2,
            atr: ATR.to_vec(),
        }
    }

    impl CardOps for MockCard {
        fn transmit(&self, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code> {
            Ok(mock_transmit(&self.0, "", send, max_recv))
        }
        fn status(&self) -> Result<CardInfo, Code> {
            Ok(mock_status(&self.0))
        }
    }

    impl CardOps for MockTx<'_> {
        fn transmit(&self, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code> {
            Ok(mock_transmit(&self.0.0, "tx ", send, max_recv))
        }
        fn status(&self) -> Result<CardInfo, Code> {
            Ok(mock_status(&self.0.0))
        }
    }

    impl CardDev for MockCard {
        type Tx<'a> = MockTx<'a>;
        fn begin(&mut self) -> Result<MockTx<'_>, Code> {
            self.0.note("begin");
            Ok(MockTx(self))
        }
        fn end(tx: MockTx<'_>, disposition: u32) -> Result<(), Code> {
            tx.0.0.note(format!("end {disposition}"));
            Ok(())
        }
        fn disconnect(self, disposition: u32) -> Result<(), Code> {
            self.0.note(format!("disconnect {disposition}"));
            Ok(())
        }
    }

    struct Rig {
        engine: Engine<MockService>,
        replies: Receiver<Reply>,
        world: Arc<World>,
        next: u32,
    }

    impl Rig {
        fn new(world: World, neutral: bool) -> Self {
            let world = Arc::new(world);
            let (tx, replies) = channel();
            Self {
                engine: Engine::new(MockService(Arc::clone(&world)), tx, neutral),
                replies,
                world,
                next: 0,
            }
        }

        fn with_key(neutral: bool) -> Self {
            Self::new(
                World {
                    readers: vec![YUBI.to_owned()],
                    ..World::default()
                },
                neutral,
            )
        }

        /// Wysyła wywołanie i zwraca numer, po którym przyjdzie odpowiedź.
        fn send(&mut self, code: ScardIoCtlCode, call: ScardCall) -> u32 {
            self.next += 1;
            let req = DeviceControlRequest {
                header: DeviceIoRequest {
                    device_id: 1,
                    file_id: 1,
                    completion_id: self.next,
                    major_function: MajorFunction::DeviceControl,
                    minor_function: MinorFunction::from(0),
                },
                output_buffer_length: 2048,
                input_buffer_length: 0,
                io_control_code: code,
            };
            self.engine.handle(req, call);
            self.next
        }

        fn recv(&self) -> (u32, Body) {
            let reply = self.replies.recv_timeout(WAIT).expect("brak odpowiedzi");
            (reply.req.header.completion_id, reply.body)
        }

        fn call(&mut self, code: ScardIoCtlCode, call: ScardCall) -> Body {
            let id = self.send(code, call);
            let (got, body) = self.recv();
            assert_eq!(got, id, "odpowiedź na inne wywołanie");
            body
        }

        fn establish(&mut self) -> u32 {
            let call = ScardCall::EstablishContextCall(EstablishContextCall { scope: Scope::User });
            match self.call(ScardIoCtlCode::EstablishContext, call) {
                Body::Context(OK, id) => id,
                other => panic!("kontekst: {other:?}"),
            }
        }

        fn connect(&mut self, context: u32, reader: &str) -> Body {
            self.call(
                ScardIoCtlCode::ConnectA,
                ScardCall::ConnectCall(ConnectCall {
                    reader: reader.to_owned(),
                    common: ConnectCommon {
                        context: ScardContext::new(context),
                        share_mode: 2,
                        preferred_protocols: CardProtocol::from_bits_retain(3),
                    },
                }),
            )
        }

        fn connected(&mut self, context: u32, reader: &str) -> u32 {
            match self.connect(context, reader) {
                Body::Connected(OK, got_context, handle, 2) => {
                    assert_eq!(got_context, context);
                    handle
                }
                other => panic!("połączenie: {other:?}"),
            }
        }

        fn list(&mut self, context: u32) -> Body {
            self.call(ScardIoCtlCode::ListReadersA, list_call(context))
        }

        fn release(&mut self, context: u32) -> Body {
            self.call(ScardIoCtlCode::ReleaseContext, context_call(context))
        }

        fn wait_for_event(&self, event: &str) {
            let deadline = Instant::now() + WAIT;
            while !self.world.events().iter().any(|e| e == event) {
                assert!(Instant::now() < deadline, "brak zdarzenia {event}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    fn list_call(context: u32) -> ScardCall {
        ScardCall::ListReadersCall(ListReadersCall {
            context: ScardContext::new(context),
            groups_ptr_length: 0,
            groups_length: 0,
            groups_ptr: 0,
            groups: Vec::new(),
            readers_is_null: true,
            readers_size: 0,
        })
    }

    fn context_call(context: u32) -> ScardCall {
        ScardCall::ContextCall(ContextCall {
            context: ScardContext::new(context),
        })
    }

    fn card_call(context: u32, handle: u32, disposition: u32) -> ScardCall {
        ScardCall::HCardAndDispositionCall(HCardAndDispositionCall {
            handle: ScardHandle::new(ScardContext::new(context), handle),
            disposition,
        })
    }

    fn transmit_call(context: u32, handle: u32, send: Vec<u8>, recv_length: u32) -> ScardCall {
        ScardCall::TransmitCall(TransmitCall {
            handle: ScardHandle::new(ScardContext::new(context), handle),
            send_pci: SCardIORequest {
                protocol: CardProtocol::from_bits_retain(2),
                extra_bytes_length: 0,
                extra_bytes: Vec::new(),
            },
            send_length: u32::try_from(send.len()).unwrap(),
            send_buffer: send,
            recv_pci: None,
            recv_buffer_is_null: false,
            recv_length,
        })
    }

    fn status_call(context: u32, handle: u32) -> ScardCall {
        ScardCall::StatusCall(StatusCall {
            handle: ScardHandle::new(ScardContext::new(context), handle),
            reader_names_is_null: false,
            reader_length: 128,
            atr_length: 32,
        })
    }

    fn wait_call(context: u32, timeout: u32, reader: &str, current: u32) -> ScardCall {
        ScardCall::GetStatusChangeCall(GetStatusChangeCall {
            context: ScardContext::new(context),
            timeout,
            states_ptr_length: 1,
            states_ptr: 0,
            states_length: 1,
            states: vec![ReaderState {
                reader: reader.to_owned(),
                common: ReaderStateCommonCall {
                    current_state: CardStateFlags::from_bits_retain(current),
                    event_state: CardStateFlags::from_bits_retain(0),
                    atr_length: 0,
                    atr: [0; 36],
                },
            }],
        })
    }

    #[test]
    fn readers_keep_real_names_by_default() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        assert_eq!(rig.list(context), Body::Readers(OK, vec![YUBI.to_owned()]));
        let handle = rig.connected(context, YUBI);
        match rig.call(ScardIoCtlCode::StatusA, status_call(context, handle)) {
            Body::Status(OK, Some(info)) => {
                assert_eq!(info.readers, vec![YUBI.to_owned()]);
                assert_eq!((info.state, info.protocol, info.atr), (6, 2, ATR.to_vec()));
            }
            other => panic!("stan: {other:?}"),
        }
        assert!(rig.world.events().contains(&format!("connect {YUBI} 2 3")));
    }

    #[test]
    fn neutral_names_hide_the_reader_name_in_both_directions() {
        let mut rig = Rig::with_key(true);
        let context = rig.establish();
        let neutral = "Smart Card Reader 1".to_owned();
        assert_eq!(rig.list(context), Body::Readers(OK, vec![neutral.clone()]));
        // Serwer łączy się po nazwie neutralnej, usługa kart dostaje prawdziwą.
        let handle = rig.connected(context, &neutral);
        assert!(rig.world.events().contains(&format!("connect {YUBI} 2 3")));
        match rig.call(ScardIoCtlCode::StatusA, status_call(context, handle)) {
            Body::Status(OK, Some(info)) => assert_eq!(info.readers, vec![neutral.clone()]),
            other => panic!("stan: {other:?}"),
        }
        // Czekanie na zmianę stanu też tłumaczy nazwę, a nazwa obca przechodzi bez zmian.
        let body = rig.call(
            ScardIoCtlCode::GetStatusChangeA,
            wait_call(context, 0, &neutral, 0),
        );
        match body {
            Body::States(OK, states) => {
                assert_eq!(
                    (states[0].event, states[0].atr.clone()),
                    (0x22, ATR.to_vec())
                );
            }
            other => panic!("stany: {other:?}"),
        }
        assert!(rig.world.events().contains(&format!("wait {YUBI} 0")));
        let pnp = r"\\?PnP?\Notification";
        rig.call(
            ScardIoCtlCode::GetStatusChangeA,
            wait_call(context, 0, pnp, 0),
        );
        assert!(rig.world.events().contains(&format!("wait {pnp} 0")));
        // Nazwa neutralna spoza listy nie wskazuje żadnego czytnika.
        assert_eq!(
            rig.connect(context, "Smart Card Reader 7"),
            Body::Connected(E_UNKNOWN_READER, context, 0, 0)
        );
    }

    #[test]
    fn names_are_stable_and_bounded() {
        let names = Names::new(true);
        assert_eq!(names.remote("b"), "Smart Card Reader 1");
        assert_eq!(names.remote("a"), "Smart Card Reader 2");
        assert_eq!(names.remote("b"), "Smart Card Reader 1");
        assert_eq!(names.local("Smart Card Reader 2"), "a");
        assert_eq!(names.local("Smart Card Reader 0"), "Smart Card Reader 0");
        assert_eq!(names.local("Smart Card Reader x"), "Smart Card Reader x");
        for i in 0..MAX_READERS {
            names.remote(&format!("r{i}"));
        }
        assert_eq!(names.remote("ponad limit"), "ponad limit");
        let plain = Names::new(false);
        assert_eq!(plain.remote(YUBI), YUBI);
        assert_eq!(plain.local("Smart Card Reader 1"), "Smart Card Reader 1");
    }

    #[test]
    fn card_commands_and_transactions_go_in_order() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let handle = rig.connected(context, YUBI);
        assert_eq!(
            rig.call(
                ScardIoCtlCode::Transmit,
                transmit_call(context, handle, vec![1, 2, 3], 0)
            ),
            Body::Transmitted(OK, vec![3, 2, 1, 0x90, 0x00])
        );
        // Zakończenie bez rozpoczęcia nie dociera do karty.
        assert_eq!(
            rig.call(
                ScardIoCtlCode::EndTransaction,
                card_call(context, handle, 0)
            ),
            Body::Long(E_NOT_TRANSACTED)
        );
        for code in [
            ScardIoCtlCode::BeginTransaction,
            ScardIoCtlCode::BeginTransaction,
        ] {
            assert_eq!(
                rig.call(code, card_call(context, handle, 0)),
                Body::Long(OK)
            );
        }
        assert_eq!(
            rig.call(
                ScardIoCtlCode::Transmit,
                transmit_call(context, handle, vec![9; 70], 22)
            ),
            Body::Transmitted(OK, {
                let mut data = vec![9; 70];
                data.extend([0x90, 0x00]);
                data
            })
        );
        assert!(matches!(
            rig.call(ScardIoCtlCode::StatusW, status_call(context, handle)),
            Body::Status(OK, Some(_))
        ));
        // Dwa zakończenia: pierwsze zamyka zagnieżdżone rozpoczęcie, drugie prawdziwą transakcję.
        for _ in 0..2 {
            assert_eq!(
                rig.call(
                    ScardIoCtlCode::EndTransaction,
                    card_call(context, handle, 1)
                ),
                Body::Long(OK)
            );
        }
        assert_eq!(
            rig.call(ScardIoCtlCode::Disconnect, card_call(context, handle, 0)),
            Body::Long(OK)
        );
        let events = rig.world.events();
        assert_eq!(
            events[1..],
            [
                format!("transmit 3 {MAX_RECV}"),
                "begin".to_owned(),
                "tx transmit 70 22".to_owned(),
                "end 1".to_owned(),
                "disconnect 0".to_owned(),
            ]
        );
        // Po rozłączeniu uchwyt nie istnieje.
        assert_eq!(
            rig.call(
                ScardIoCtlCode::Transmit,
                transmit_call(context, handle, vec![0], 0)
            ),
            Body::Transmitted(E_INVALID_HANDLE, Vec::new())
        );
    }

    #[test]
    fn disconnect_inside_transaction_ends_it_first() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let handle = rig.connected(context, YUBI);
        rig.call(
            ScardIoCtlCode::BeginTransaction,
            card_call(context, handle, 0),
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::Disconnect, card_call(context, handle, 1)),
            Body::Long(OK)
        );
        assert_eq!(rig.world.events()[1..], ["begin", "end 0", "disconnect 1"]);
    }

    #[test]
    fn waiting_does_not_block_connect_and_cancel_ends_it() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        // Stan wejściowy różny od zera: atrapa czeka do anulowania.
        let waiting = rig.send(
            ScardIoCtlCode::GetStatusChangeA,
            wait_call(context, INFINITE, YUBI, 0x10),
        );
        rig.wait_for_event(&format!("wait {YUBI} {WAIT_SLICE_MS}"));
        // W trakcie czekania ten sam kontekst łączy się z kartą i listuje czytniki.
        let handle = rig.connected(context, YUBI);
        assert_eq!(rig.list(context), Body::Readers(OK, vec![YUBI.to_owned()]));
        // Anulowanie budzi wątek czekania, zanim pętla sesji odeśle własną odpowiedź, więc obie
        // odpowiedzi przychodzą w dowolnej kolejności; serwer i tak rozróżnia je po numerze.
        let cancel = rig.send(ScardIoCtlCode::Cancel, context_call(context));
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (id, body) = rig.recv();
            seen.push(id);
            if id == waiting {
                assert!(matches!(body, Body::States(E_CANCELLED, states) if states.len() == 1));
            } else {
                assert_eq!(body, Body::Long(OK));
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, [waiting, cancel]);
        assert_eq!(
            rig.call(ScardIoCtlCode::Disconnect, card_call(context, handle, 0)),
            Body::Long(OK)
        );
    }

    #[test]
    fn finite_wait_times_out_after_the_requested_time() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let started = Instant::now();
        let body = rig.call(
            ScardIoCtlCode::GetStatusChangeW,
            wait_call(context, 60, YUBI, 0x10),
        );
        assert!(matches!(body, Body::States(E_TIMEOUT, _)));
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(started.elapsed() < Duration::from_millis(u64::from(WAIT_SLICE_MS)));
    }

    #[test]
    fn release_ends_waiting_and_leaves_abandoned_cards_alone() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let handle = rig.connected(context, YUBI);
        rig.call(
            ScardIoCtlCode::BeginTransaction,
            card_call(context, handle, 0),
        );
        let waiting = rig.send(
            ScardIoCtlCode::GetStatusChangeA,
            wait_call(context, INFINITE, YUBI, 0x10),
        );
        rig.wait_for_event(&format!("wait {YUBI} {WAIT_SLICE_MS}"));
        let released = rig.send(ScardIoCtlCode::ReleaseContext, context_call(context));
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (id, body) = rig.recv();
            seen.push(id);
            if id == waiting {
                assert!(matches!(body, Body::States(E_CANCELLED, _)));
            } else {
                assert_eq!(body, Body::Long(OK));
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, [waiting, released]);
        // Porzucona karta kończy transakcję i rozłącza się bez resetu.
        rig.wait_for_event("disconnect 0");
        let events = rig.world.events();
        assert!(events.contains(&"end 0".to_owned()), "{events:?}");
        // Kontekst i karta przestały istnieć.
        assert_eq!(rig.release(context), Body::Long(E_INVALID_HANDLE));
        assert_eq!(
            rig.list(context),
            Body::Readers(E_INVALID_HANDLE, Vec::new())
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::StatusA, status_call(context, handle)),
            Body::Status(E_INVALID_HANDLE, None)
        );
    }

    #[test]
    fn unknown_ids_and_oversized_requests_get_error_codes() {
        let mut rig = Rig::with_key(false);
        assert_eq!(rig.list(77), Body::Readers(E_INVALID_HANDLE, Vec::new()));
        assert_eq!(
            rig.connect(77, YUBI),
            Body::Connected(E_INVALID_HANDLE, 77, 0, 0)
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::GetStatusChangeA, wait_call(77, 0, YUBI, 0)),
            Body::States(
                E_INVALID_HANDLE,
                vec![StateIo {
                    reader: YUBI.to_owned(),
                    current: 0,
                    event: 0,
                    atr: Vec::new()
                }]
            )
        );
        for code in [ScardIoCtlCode::IsValidContext, ScardIoCtlCode::Cancel] {
            assert_eq!(
                rig.call(code, context_call(77)),
                Body::Long(E_INVALID_HANDLE)
            );
        }
        assert_eq!(
            rig.call(ScardIoCtlCode::BeginTransaction, card_call(1, 77, 0)),
            Body::Long(E_INVALID_HANDLE)
        );
        let context = rig.establish();
        assert_eq!(
            rig.call(ScardIoCtlCode::IsValidContext, context_call(context)),
            Body::Long(OK)
        );
        assert_eq!(
            rig.connect(context, "nie ma takiego"),
            Body::Connected(E_UNKNOWN_READER, context, 0, 0)
        );
        let handle = rig.connected(context, YUBI);
        assert_eq!(
            rig.call(
                ScardIoCtlCode::Transmit,
                transmit_call(context, handle, vec![0; MAX_SEND + 1], 0)
            ),
            Body::Transmitted(E_INVALID_PARAMETER, Vec::new())
        );
        let mut many = wait_call(context, 0, YUBI, 0);
        if let ScardCall::GetStatusChangeCall(call) = &mut many {
            let state = call.states[0].clone();
            call.states = vec![state; MAX_READER_STATES + 1];
        }
        assert_eq!(
            rig.call(ScardIoCtlCode::GetStatusChangeA, many),
            Body::States(E_INVALID_PARAMETER, Vec::new())
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::GetAttrib, ScardCall::Unsupported),
            Body::Long(E_UNSUPPORTED_FEATURE)
        );
        assert_eq!(
            rig.call(
                ScardIoCtlCode::GetDeviceTypeId,
                ScardCall::GetDeviceTypeIdCall(GetDeviceTypeIdCall {
                    context: ScardContext::new(context),
                    reader_ptr: 0,
                    reader_name: YUBI.to_owned(),
                })
            ),
            Body::DeviceType(OK, READER_TYPE_USB)
        );
    }

    #[test]
    fn limits_on_contexts_and_cards() {
        let mut rig = Rig::with_key(false);
        let contexts: Vec<u32> = (0..MAX_CONTEXTS).map(|_| rig.establish()).collect();
        let call = ScardCall::EstablishContextCall(EstablishContextCall { scope: Scope::User });
        assert_eq!(
            rig.call(ScardIoCtlCode::EstablishContext, call),
            Body::Context(E_NO_MEMORY, 0)
        );
        let context = contexts[0];
        let cards: Vec<u32> = (0..MAX_CARDS)
            .map(|_| rig.connected(context, YUBI))
            .collect();
        assert_eq!(
            rig.connect(context, YUBI),
            Body::Connected(E_NO_MEMORY, context, 0, 0)
        );
        // Rozłączona karta zwalnia miejsce.
        rig.call(ScardIoCtlCode::Disconnect, card_call(context, cards[0], 0));
        rig.connected(context, YUBI);
        // Identyfikatory się nie powtarzają.
        let mut ids: Vec<u32> = contexts.iter().chain(&cards).copied().collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), MAX_CONTEXTS + MAX_CARDS);
        assert!(!ids.contains(&0));
    }

    #[test]
    fn service_errors_and_panics_become_codes() {
        let mut refused = Rig::new(
            World {
                establish_error: Some(0x8010_001D),
                ..World::default()
            },
            false,
        );
        let call = ScardCall::EstablishContextCall(EstablishContextCall { scope: Scope::User });
        assert_eq!(
            refused.call(ScardIoCtlCode::EstablishContext, call),
            Body::Context(0x8010_001D, 0)
        );
        let mut panicking = Rig::new(
            World {
                panic_on_list: true,
                ..World::default()
            },
            false,
        );
        let context = panicking.establish();
        assert_eq!(
            panicking.list(context),
            Body::Readers(E_INTERNAL, Vec::new())
        );
        // Wątek kontekstu przeżył panikę i odpowiada dalej.
        assert_eq!(
            panicking.list(context),
            Body::Readers(E_INTERNAL, Vec::new())
        );
    }

    #[test]
    fn cache_keeps_items_per_card_with_freshness() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let read = |name: &str, freshness: u32| {
            ScardCall::ReadCacheCall(ReadCacheCall {
                lookup_name: name.to_owned(),
                common: ReadCacheCommon {
                    context: ScardContext::new(context),
                    card_uuid: vec![7; 16],
                    freshness_counter: freshness,
                    data_is_null: false,
                    data_len: 0,
                },
            })
        };
        let write = |name: &str, freshness: u32, data: Vec<u8>| {
            ScardCall::WriteCacheCall(WriteCacheCall {
                lookup_name: name.to_owned(),
                common: WriteCacheCommon {
                    context: ScardContext::new(context),
                    card_uuid: vec![7; 16],
                    freshness_counter: freshness,
                    data,
                },
            })
        };
        assert_eq!(
            rig.call(ScardIoCtlCode::ReadCacheW, read("a", 1)),
            Body::Cache(W_CACHE_ITEM_NOT_FOUND, Vec::new())
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::WriteCacheW, write("a", 1, vec![1, 2])),
            Body::Long(OK)
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::ReadCacheW, read("a", 1)),
            Body::Cache(OK, vec![1, 2])
        );
        assert_eq!(
            rig.call(ScardIoCtlCode::ReadCacheW, read("a", 2)),
            Body::Cache(W_CACHE_ITEM_STALE, Vec::new())
        );
        assert_eq!(
            rig.call(
                ScardIoCtlCode::WriteCacheW,
                write("b", 1, vec![0; MAX_CACHE_ITEM + 1])
            ),
            Body::Long(W_CACHE_ITEM_TOO_BIG)
        );
    }

    #[test]
    fn return_codes_round_trip_and_unknown_is_internal_error() {
        for code in [
            OK,
            E_INTERNAL,
            E_CANCELLED,
            E_INVALID_HANDLE,
            E_INVALID_PARAMETER,
            E_NO_MEMORY,
            E_UNKNOWN_READER,
            E_TIMEOUT,
            E_PROTO_MISMATCH,
            E_NOT_TRANSACTED,
            E_UNSUPPORTED_FEATURE,
            W_CACHE_ITEM_NOT_FOUND,
            W_CACHE_ITEM_STALE,
            W_CACHE_ITEM_TOO_BIG,
            0x8010_002E,
            0x8010_0069,
        ] {
            assert_eq!(u32::from(return_code(code)), code, "{code:#010x}");
        }
        assert_eq!(return_code(0x1234_5678), ReturnCode::InternalError);
    }

    #[test]
    fn ansi_reader_list_is_one_byte_per_character() {
        let pdu = rpce::Pdu(ReadersAnsi {
            code: ReturnCode::Success,
            readers: vec!["Ab".to_owned(), "C".to_owned()],
        });
        let bytes = ironrdp::core::encode_vec(&pdu).unwrap();
        // 16 bajtów nagłówków RPCE, potem kod, długość, wskaźnik, długość i nazwy z zerami.
        assert_eq!(bytes.len() % 8, 0);
        assert_eq!(
            bytes[16..34],
            [
                0, 0, 0, 0, // kod zwrotny
                6, 0, 0, 0, // cBytes
                0, 0, 2, 0, // wskaźnik
                6, 0, 0, 0, // liczba elementów
                b'A', b'b',
            ]
        );
        assert_eq!(bytes[34..38], [0, b'C', 0, 0]);
    }

    #[test]
    fn every_reply_shape_encodes() {
        let mut rig = Rig::with_key(false);
        let context = rig.establish();
        let handle = rig.connected(context, YUBI);
        let calls = vec![
            (ScardIoCtlCode::ListReadersA, list_call(context)),
            (ScardIoCtlCode::ListReadersW, list_call(context)),
            (
                ScardIoCtlCode::GetStatusChangeA,
                wait_call(context, 0, YUBI, 0),
            ),
            (
                ScardIoCtlCode::Transmit,
                transmit_call(context, handle, vec![1], 0),
            ),
            (ScardIoCtlCode::StatusA, status_call(context, handle)),
            (ScardIoCtlCode::StatusW, status_call(context, handle)),
            (ScardIoCtlCode::IsValidContext, context_call(context)),
            (ScardIoCtlCode::Disconnect, card_call(context, handle, 0)),
        ];
        for (code, call) in calls {
            let id = rig.send(code, call);
            let reply = rig.replies.recv_timeout(WAIT).expect("brak odpowiedzi");
            assert_eq!(reply.req.header.completion_id, id);
            // Kodowanie nie może się wyłożyć na żadnym kształcie odpowiedzi.
            let _message = encode(reply);
        }
        assert!(matches!(
            rig.replies.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
    }

    #[test]
    fn undecodable_server_messages_are_skipped() {
        let (tx, _replies) = channel();
        let engine = Engine::new(MockService(Arc::new(World::default())), tx, false);
        let mut channel = Channel::new(Backend::new(engine), "test".to_owned());
        assert_eq!(channel.channel_name().as_str(), Some("rdpdr"));
        assert!(channel.process(&[0xff; 3]).unwrap().is_empty());
        let mut sound = Sound::new();
        assert_eq!(sound.channel_name().as_str(), Some("rdpsnd"));
        assert!(sound.process(&[0xff; 1]).unwrap().is_empty());
    }
}
