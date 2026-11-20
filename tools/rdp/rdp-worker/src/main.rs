//! Proces pomocniczy RDP. Protokół stdio opisuje crate `rdp-proto`; stdout służy wyłącznie do
//! protokołu, diagnostyka idzie na stderr i nigdy nie zawiera hasła.

use std::io::{self, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use ironrdp::cliprdr::{Client, Cliprdr};
use ironrdp::connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp::connector::credssp::KerberosConfig;
use ironrdp::connector::{self, ConnectionResult, Credentials, Sequence as _};
use ironrdp::core::WriteBuf;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::fast_path;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, SessionError};
use ironrdp::svc::SvcProcessorMessages;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::pointer::{DecodedPointer, PointerError};
use rdp_proto::{
    CardRedirect, ClipKind, ConnectParams, FromWorker, Image, LinkProfile, Message, Pointer,
    ToWorker,
};
use sha2::{Digest as _, Sha256};
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use tokio_rustls::rustls;

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
mod clip;
mod memlimit;
// Poza Windows nie ma usługi kart, więc tam moduł pracuje tylko w testach.
#[cfg_attr(not(windows), allow(dead_code))]
mod scard;
#[cfg(windows)]
mod scard_pcsc;
mod webauthn;

type Framed = ironrdp_blocking::Framed<Tls>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Okres odpytywania pętli głównej: tyle najdłużej czeka odczyt z sieci, zanim pętla zajrzy do poleceń
/// aplikacji (mysz, klawisze, schowek). Przy 15 ms wejście z interfejsu czekało na tę pętlę nawet
/// 15 ms, co było widać jako opóźnienie kursora i pisania; 5 ms zostawia pętli pomijalny koszt
/// (ok. 200 pustych obrotów na sekundę). Obraz nadal idzie co `FLUSH_EVERY` przy ciągłym strumieniu,
/// a po ciszy dłuższej niż `POLL` od razu (patrz gałąź limitu czasu w pętli). Limity czasu schowka
/// i oczekiwanie na Display Control liczą się zegarem (`Instant`), nie obrotami pętli.
const POLL: Duration = Duration::from_millis(5);
const FLUSH_EVERY: Duration = Duration::from_millis(16);
/// Kod systemu Windows `WSA_IO_PENDING` ("pokrywająca się operacja we/wy jest w toku").
const WSA_IO_PENDING: i32 = 997;
/// Tyle kolejnych odczytów może skończyć się `WSA_IO_PENDING`, zanim uznamy gniazdo za zepsute
/// (z przerwą 1 ms po każdym to co najmniej 2 s bez żadnego udanego odczytu ani zwykłego limitu czasu).
const MAX_PENDING_READS: u32 = 2000;
/// Pierwsza sonda keepalive po tak długiej ciszy; potem co `KEEPALIVE_INTERVAL`. Bez tego pół-martwe
/// połączenie (np. po zmianie sieci albo uśpieniu serwera) wisiałoby bez końca.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Najdłuższy czas jednego zapisu do gniazda; przekroczenie kończy sesję jak każdy błąd zapisu.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Ile czekamy, aż serwer otworzy kanał Display Control i zgłosi swoje możliwości, zanim uznamy,
/// że zmiany rozdzielczości w trakcie sesji nie obsługuje.
const RESIZE_WAIT: Duration = Duration::from_secs(5);

// W testach komunikaty nie idą na stdout, tylko do listy odczytywanej przez test.
#[cfg(test)]
thread_local! {
    pub(crate) static EMITTED: std::cell::RefCell<Vec<FromWorker>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn emit(ev: &FromWorker) {
    EMITTED.with(|e| e.borrow_mut().push(ev.clone()));
}

#[cfg(not(test))]
pub(crate) fn emit(ev: &FromWorker) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_json(&mut out, ev);
}

/// Wpis do dziennika diagnostycznego aplikacji. Nigdy z treścią schowka, hasłem ani nazwami plików.
pub(crate) fn log(message: impl Into<String>) {
    emit(&FromWorker::Log {
        message: message.into(),
    });
}

#[cfg(test)]
pub(crate) fn emit_clip(_kind: ClipKind, _data: &[u8]) {}

#[cfg(not(test))]
pub(crate) fn emit_clip(kind: ClipKind, data: &[u8]) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_clip(&mut out, kind, data);
}

fn emit_image(img: &Image) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_image(&mut out, img);
}

fn emit_pointer(p: &Pointer) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_pointer(&mut out, p);
}

fn main() {
    // Pierwsza wiadomość: wersja protokołu, po której aplikacja rozpoznaje niezgodny (stary) proces.
    emit(&FromWorker::Hello {
        protocol: rdp_proto::PROTOCOL,
    });
    let (tx, rx) = mpsc::channel::<ToWorker>();
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            match rdp_proto::read_message(&mut stdin) {
                Ok(Some(Message::Json(bytes))) => match rdp_proto::parse_json::<ToWorker>(&bytes) {
                    Ok(cmd) => {
                        if tx.send(cmd).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("rdp-worker: nieczytelne polecenie: {e}"),
                },
                Ok(Some(Message::Clip { kind, data })) => {
                    if tx.send(ToWorker::ClipData { kind, data }).is_err() {
                        break;
                    }
                }
                Ok(Some(Message::Image(_) | Message::Pointer(_))) => {}
                // Koniec strumienia albo błąd: aplikacja zniknęła, kończymy sesję.
                Ok(None) | Err(_) => {
                    let _ = tx.send(ToWorker::Close);
                    break;
                }
            }
        }
    });

    let params = loop {
        match rx.recv() {
            Ok(ToWorker::Connect(p)) => break p,
            Ok(ToWorker::Close) | Err(_) => return,
            Ok(_) => {}
        }
    };
    match run(params, &rx) {
        Ok(reason) => emit(&FromWorker::Closed { reason }),
        Err(e) => emit(&FromWorker::Error {
            message: format!("{e:#}"),
        }),
    }
}

fn run(params: ConnectParams, rx: &Receiver<ToWorker>) -> anyhow::Result<String> {
    let config = build_config(&params);
    let kerberos = if params.kerberos {
        Some(KerberosConfig::new(params.kdc.clone(), hostname()).context("konfiguracja Kerberos")?)
    } else {
        None
    };
    let (clip_tx, clip_rx) = mpsc::channel::<clip::ClipEvent>();
    let mut clip = clip::ClipState::new();
    // Przekierowanie kluczy bezpieczeństwa: kanał powstaje tylko dla hostów z włączonym ustawieniem
    // i tylko tam, gdzie jest wykonawca operacji (Windows). Bez niego sesja działa jak dotąd.
    let (webauthn_tx, webauthn_rx) = mpsc::channel::<webauthn::Reply>();
    let webauthn_listener = if params.webauthn {
        let handlers = webauthn_handlers();
        if handlers.is_none() {
            emit(&FromWorker::Notice {
                message:
                    "Przekierowanie kluczy bezpieczeństwa działa tylko w aplikacji na Windows."
                        .into(),
            });
        }
        handlers.map(|handlers| webauthn::Listener::new(webauthn_tx, handlers))
    } else {
        None
    };
    if webauthn_listener.is_some() {
        log("WebAuthn: przekierowanie kluczy bezpieczeństwa włączone dla tej sesji");
    }
    // Przekierowanie czytników kart: kanały powstają tylko dla hostów z włączonym ustawieniem i tylko
    // tam, gdzie jest usługa kart (Windows). Bez nich sesja działa jak dotąd.
    let (scard_tx, scard_rx) = mpsc::channel::<scard::Reply>();
    let smartcard = match params.smartcard {
        CardRedirect::Off => None,
        mode => {
            let neutral = mode == CardRedirect::Neutral;
            let channels = smartcard_channels(neutral, scard_tx);
            if channels.is_some() {
                log(format!(
                    "karty: przekierowanie czytników włączone dla tej sesji (nazwy {})",
                    if neutral { "neutralne" } else { "prawdziwe" }
                ));
            } else {
                emit(&FromWorker::Notice {
                    message: "Przekierowanie czytników kart działa tylko w aplikacji na Windows."
                        .into(),
                });
            }
            channels
        }
    };
    let (result, mut framed) = connect(
        &config,
        &params,
        kerberos,
        rx,
        clip_tx,
        webauthn_listener,
        smartcard,
    )
    .context("połączenie")?;
    set_timeout(&framed, POLL);

    let factory =
        ConnectionActivationFactory::new(config, result.io_channel_id, result.user_channel_id);
    let (w, h) = validate_desktop_size(result.desktop_size.width, result.desktop_size.height)?;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, w, h);
    let mut stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    emit(&FromWorker::Connected {
        width: w,
        height: h,
    });

    let mut input = Database::new();
    let mut dirty = Dirty::new(w, h);
    // Ostatni stan wskaźnika czeka tu do wysyłki obrazu (`flush_all`), więc kształty nie wymagają
    // kontroli przepływu: serwer nie wymusi więcej niż jednej ramki wskaźnika na `FLUSH_EVERY`.
    let mut pointer = PointerState::new();
    // Czy biblioteka ma dekodować kształty wskaźnika. Po pierwszym błędzie dekodowania kształtu
    // wyłączamy je do końca sesji (także po reaktywacji), a lokalny kursor zostaje domyślny.
    let mut pointer_shapes = result.enable_server_pointer;
    let software_pointer = result.pointer_software_rendering;
    let mut share_id = result.share_id;
    let mut last_flush = Instant::now();
    // Kolejne odczyty zakończone `WSA_IO_PENDING` (patrz `is_pending_read`).
    let mut pending_reads = 0u32;
    // Prośba o zmianę rozdzielczości czekająca na gotowość kanału (rozmiar i chwila zgłoszenia).
    let mut pending_resize: Option<(u32, u32, Instant)> = None;
    let mut resize_refused = false;
    loop {
        memlimit::check_soft()?;
        loop {
            match rx.try_recv() {
                Ok(ToWorker::Close) | Err(TryRecvError::Disconnected) => {
                    if let Ok(outs) = stage.graceful_shutdown() {
                        for o in outs {
                            if let ActiveStageOutput::ResponseFrame(f) = o {
                                let _ = framed.write_all(&f);
                            }
                        }
                    }
                    return Ok("zamknięto przez użytkownika".into());
                }
                Ok(ToWorker::Resize { width, height }) => {
                    // Szerokość musi być parzysta i mieścić się w 200..=8192.
                    let (w, h) = (
                        u32::from(width.clamp(200, 8192) & !1),
                        u32::from(height.clamp(200, 8192)),
                    );
                    // Nowsza prośba zastępuje czekającą; wysyłka niżej, gdy kanał jest gotowy.
                    pending_resize = Some((w, h, Instant::now()));
                }
                Ok(cmd) => {
                    if clip.on_command(&cmd, &mut stage, &mut |b| framed.write_all(b))? {
                        continue;
                    }
                    let ops = operations_for(&cmd);
                    if !ops.is_empty() {
                        let events = input.apply(ops);
                        let outs = stage.process_fastpath_input(&mut image, &events)?;
                        handle(outs, &mut framed, &mut dirty, &mut pointer)?;
                    }
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        // Odpowiedzi WebAuthn gotowe po czasie: użytkownik odpowiedział w oknie systemu.
        while let Ok(reply) = webauthn_rx.try_recv() {
            match webauthn::encode_reply(reply) {
                Ok(messages) => match stage.encode_dvc_messages(messages) {
                    Ok(frame) => framed
                        .write_all(&frame)
                        .context("wysyłka odpowiedzi WebAuthn")?,
                    Err(e) => log(format!("WebAuthn: nie udało się zakodować odpowiedzi: {e}")),
                },
                Err(e) => log(format!("WebAuthn: nie udało się zakodować odpowiedzi: {e}")),
            }
        }

        // Odpowiedzi usługi kart gotowe po czasie (karta odpowiedziała albo ktoś dotknął klucza).
        // Każda idzie osobno: błąd kodowania jednej trafia do dziennika i nie zabiera pozostałych.
        while let Ok(reply) = scard_rx.try_recv() {
            let messages = SvcProcessorMessages::<scard::Channel>::new(vec![scard::encode(reply)]);
            match stage.process_svc_processor_messages(messages) {
                Ok(frame) => framed
                    .write_all(&frame)
                    .context("wysyłka odpowiedzi czytnika kart")?,
                Err(e) => log(format!("karty: nie udało się zakodować odpowiedzi: {e}")),
            }
        }

        if let Some((w, h, since)) = pending_resize {
            let sent = match resize_step(display_control_ready(&mut stage), since.elapsed()) {
                ResizeStep::Wait => None,
                ResizeStep::GiveUp => Some(false),
                ResizeStep::Send => match stage.encode_resize(w, h, None, None) {
                    Some(Ok(frame)) => {
                        framed.write_all(&frame).context("zapis zmiany rozmiaru")?;
                        Some(true)
                    }
                    _ => Some(false),
                },
            };
            if sent.is_some() {
                pending_resize = None;
            }
            // Brak obsługi zgłaszamy raz na sesję, żeby okno nie zalewało powiadomieniami przy każdej
            // zmianie rozmiaru.
            if sent == Some(false) && !resize_refused {
                resize_refused = true;
                emit(&FromWorker::Notice {
                    message: "Serwer nie obsługuje zmiany rozdzielczości w trakcie sesji. Pulpit zostaje w rozmiarze z chwili połączenia.".into(),
                });
            }
        }

        while let Ok(ev) = clip_rx.try_recv() {
            clip.on_event(ev, &mut stage, &mut |b| framed.write_all(b))?;
        }
        clip.tick();

        match framed.read_pdu() {
            Ok((action, payload)) => {
                pending_reads = 0;
                let outs = match stage.process(&mut image, action, &payload) {
                    Ok(outs) => outs,
                    // Wadliwy kształt wskaźnika (np. 8 bpp, maska niezgodna z wymiarami) nie może
                    // kończyć sesji: przechodzimy na tryb bez kształtów i ponawiamy ten sam PDU raz.
                    // Rozpoznanie po rodzaju źródła błędu, inne błędy sesji idą dalej.
                    Err(e) if pointer_shapes && is_pointer_decode_error(&e) => {
                        pointer_shapes = false;
                        stage.set_fastpath_processor(fast_path_processor(
                            factory.io_channel_id(),
                            factory.user_channel_id(),
                            share_id,
                            false,
                            software_pointer,
                        ));
                        stage.set_enable_server_pointer(false);
                        pointer.set(PointerShape::Default);
                        log(
                            "wskaźnik: nie udało się zdekodować kształtu, kształty wyłączone do końca sesji",
                        );
                        stage.process(&mut image, action, &payload)?
                    }
                    Err(e) => return Err(e.into()),
                };
                let mut reactivate_needed = false;
                for o in outs {
                    match o {
                        ActiveStageOutput::DeactivateAll => reactivate_needed = true,
                        other => {
                            if let Some(reason) =
                                handle_one(other, &mut framed, &mut dirty, &mut pointer)?
                            {
                                flush_all(&image, &mut dirty, &mut pointer);
                                return Ok(reason);
                            }
                        }
                    }
                }
                if reactivate_needed {
                    let (w, h, new_share_id) = reactivate(
                        &mut framed,
                        &factory,
                        &mut stage,
                        &mut image,
                        pointer_shapes,
                    )?;
                    share_id = new_share_id;
                    // Nowy procesor ma pustą pamięć kształtów, więc nie wiemy, jaki kursor
                    // pokazuje serwer: do czasu nowego kształtu lokalny kursor jest domyślny.
                    pointer.set(PointerShape::Default);
                    dirty = Dirty::new(w, h);
                    emit(&FromWorker::Resized {
                        width: w,
                        height: h,
                    });
                }
            }
            Err(e) if no_data_yet(&e, pending_reads) => {
                if is_pending_read(&e) {
                    // Krótka przerwa, żeby powtarzający się kod nie zamienił pętli w czekanie aktywne.
                    pending_reads += 1;
                    std::thread::sleep(Duration::from_millis(1));
                } else {
                    pending_reads = 0;
                }
                flush_all(&image, &mut dirty, &mut pointer);
                last_flush = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                flush_all(&image, &mut dirty, &mut pointer);
                return Ok("serwer zamknął połączenie".into());
            }
            Err(e) => return Err(anyhow::Error::new(e).context("odczyt z serwera")),
        }
        if last_flush.elapsed() >= FLUSH_EVERY {
            flush_all(&image, &mut dirty, &mut pointer);
            last_flush = Instant::now();
        }
    }
}

/// Czy serwer otworzył kanał Display Control i przysłał swoje możliwości. Prośba o zmianę rozmiaru
/// wysłana wcześniej jest wbrew MS-RDPEDISP (klient ma czekać na możliwości serwera) i serwer może
/// ją pominąć, a biblioteka sama tego nie sprawdza.
fn display_control_ready(stage: &mut ActiveStage) -> bool {
    stage
        .get_dvc::<DisplayControlClient>()
        .filter(|dvc| dvc.channel_id().is_some())
        .and_then(|dvc| dvc.channel_processor_downcast_ref::<DisplayControlClient>())
        .is_some_and(DisplayControlClient::ready)
}

#[derive(Debug, PartialEq, Eq)]
enum ResizeStep {
    Send,
    Wait,
    GiveUp,
}

/// Co zrobić z czekającą prośbą o zmianę rozdzielczości: wysłać, gdy kanał jest gotowy, poczekać
/// chwilę na serwer (kanał otwiera się krótko po połączeniu), a potem uznać, że serwer jej nie obsługuje.
fn resize_step(ready: bool, waited: Duration) -> ResizeStep {
    if ready {
        ResizeStep::Send
    } else if waited >= RESIZE_WAIT {
        ResizeStep::GiveUp
    } else {
        ResizeStep::Wait
    }
}

/// Największy bok pulpitu, jaki przyjmujemy od serwera (górna granica rozsądku, a nie limit
/// Display Control 200..8192, którym ograniczamy prośby klienta).
const MAX_DESKTOP_SIDE: u16 = 16384;
/// Największe pole pulpitu w pikselach (8192 x 8192, czyli 256 MiB obrazu RGBA). Przy reaktywacji
/// i wysyłce pasów obraz bywa chwilowo w pamięci dwa albo trzy razy, a całość musi zostać pod
/// progiem miękkim z `memlimit`.
const MAX_DESKTOP_PIXELS: u32 = 8192 * 8192;
const _: () = assert!(3 * (MAX_DESKTOP_PIXELS as usize) * 4 <= memlimit::SOFT_LIMIT);

/// Rozmiar pulpitu podany przez serwer trafia do bufora obrazu, więc zero i wartości absurdalne
/// odrzucamy przed alokacją.
fn validate_desktop_size(width: u16, height: u16) -> anyhow::Result<(u16, u16)> {
    let pixels = u32::from(width) * u32::from(height);
    if width == 0
        || height == 0
        || width > MAX_DESKTOP_SIDE
        || height > MAX_DESKTOP_SIDE
        || pixels > MAX_DESKTOP_PIXELS
    {
        bail!(
            "serwer podał nieprawidłowy rozmiar pulpitu: {width}x{height} (bok najwyżej {MAX_DESKTOP_SIDE}, pole najwyżej {MAX_DESKTOP_PIXELS} pikseli)"
        );
    }
    Ok((width, height))
}

/// Sekwencja deaktywacji i reaktywacji (MS-RDPBCGR 1.3.1.3): serwer zmienia parametry pulpitu.
fn reactivate(
    framed: &mut Framed,
    factory: &ConnectionActivationFactory,
    stage: &mut ActiveStage,
    image: &mut DecodedImage,
    pointer_shapes: bool,
) -> anyhow::Result<(u16, u16, u32)> {
    set_timeout(framed, CONNECT_TIMEOUT);
    let mut seq = factory.create();
    let mut buf = WriteBuf::new();
    let (desktop, share_id, server_pointer, software_pointer) = loop {
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
        } = seq.connection_activation_state()
        {
            break (
                desktop_size,
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
            );
        }
        buf.clear();
        let written = match seq.next_pdu_hint() {
            Some(hint) => {
                let pdu = framed.read_by_hint(hint).context("reaktywacja: odczyt")?;
                seq.step(&pdu, &mut buf)
                    .map_err(|e| anyhow!("reaktywacja: {e}"))?
            }
            None => seq
                .step_no_input(&mut buf)
                .map_err(|e| anyhow!("reaktywacja: {e}"))?,
        };
        if let Some(n) = written.size() {
            framed.write_all(&buf[..n]).context("reaktywacja: zapis")?;
        }
    };
    // `server_pointer` i `software_pointer` pochodzą z konfiguracji (`build_config`): wskaźnik idzie
    // do aplikacji, a nie do obrazu; nowy procesor zaczyna z pustą pamięcią kształtów (pętla główna
    // przywraca wtedy kursor domyślny). Gdy sesja przeszła na tryb bez kształtów (`pointer_shapes`
    // false), reaktywacja nie włącza ich z powrotem.
    let server_pointer = server_pointer && pointer_shapes;
    stage.set_fastpath_processor(fast_path_processor(
        factory.io_channel_id(),
        factory.user_channel_id(),
        share_id,
        server_pointer,
        software_pointer,
    ));
    stage.set_share_id(share_id);
    stage.set_enable_server_pointer(server_pointer);
    let (w, h) = validate_desktop_size(desktop.width, desktop.height)?;
    *image = DecodedImage::new(PixelFormat::RgbA32, w, h);
    set_timeout(framed, POLL);
    Ok((w, h, share_id))
}

/// Procesor fast-path bez kompresji (jej nie negocjujemy, patrz `performance_flags`), więc jego
/// przebudowa w trakcie sesji nie gubi stanu dekompresora; kodeki obrazu poza prostymi bitmapami
/// nie są ogłaszane serwerowi.
fn fast_path_processor(
    io_channel_id: u16,
    user_channel_id: u16,
    share_id: u32,
    enable_server_pointer: bool,
    pointer_software_rendering: bool,
) -> fast_path::Processor {
    fast_path::ProcessorBuilder {
        io_channel_id,
        user_channel_id,
        share_id,
        enable_server_pointer,
        pointer_software_rendering,
        bulk_decompressor: None,
    }
    .build()
}

fn handle(
    outs: Vec<ActiveStageOutput>,
    framed: &mut Framed,
    dirty: &mut Dirty,
    pointer: &mut PointerState,
) -> anyhow::Result<()> {
    for o in outs {
        handle_one(o, framed, dirty, pointer)?;
    }
    Ok(())
}

/// Zwraca powód zakończenia sesji, jeśli serwer ją zamknął.
fn handle_one(
    out: ActiveStageOutput,
    framed: &mut Framed,
    dirty: &mut Dirty,
    pointer: &mut PointerState,
) -> anyhow::Result<Option<String>> {
    match out {
        ActiveStageOutput::ResponseFrame(frame) => {
            framed.write_all(&frame).context("zapis odpowiedzi")?
        }
        ActiveStageOutput::GraphicsUpdate(r) => dirty.add(r.left, r.top, r.right, r.bottom),
        // Wskaźnik tylko zapamiętujemy; do aplikacji idzie ostatni stan przy wysyłce obrazu.
        ActiveStageOutput::PointerBitmap(p) => pointer.set(PointerShape::Bitmap(p)),
        ActiveStageOutput::PointerDefault => pointer.set(PointerShape::Default),
        ActiveStageOutput::PointerHidden => pointer.set(PointerShape::Hidden),
        // Pozycji wskaźnika z serwera nie stosujemy: lokalny kursor idzie za myszą użytkownika, a
        // serwer odsyła pozycję tylko jako echo naszych ruchów (przestawianie kursora na żądanie
        // serwera dawałoby skoki i opóźnienie).
        ActiveStageOutput::PointerPosition { .. } => {}
        ActiveStageOutput::Terminate(reason) => {
            return Ok(Some(format!("serwer zakończył sesję: {reason:?}")));
        }
        _ => {}
    }
    Ok(None)
}

/// Zamienia bitmapę wskaźnika z biblioteki na ramkę protokołu. Biblioteka nie sprawdza wymiarów
/// (patrz `MAX_POINTER_SIDE`), więc kontrola jest tutaj; punkt zaczepienia ucinamy do bitmapy.
fn pointer_frame(p: &DecodedPointer) -> Option<Pointer> {
    let frame = Pointer {
        width: p.width,
        height: p.height,
        hot_x: p.hotspot_x.min(p.width.saturating_sub(1)),
        hot_y: p.hotspot_y.min(p.height.saturating_sub(1)),
        rgba: p.bitmap_data.clone(),
    };
    frame.is_valid().then_some(frame)
}

/// Stan wskaźnika zgłoszony przez serwer. Kształty porównujemy po tożsamości `Arc` (kształt z
/// pamięci podręcznej biblioteki to ten sam `Arc`), więc porównanie jest tanie.
#[derive(Clone)]
enum PointerShape {
    Default,
    Hidden,
    Bitmap(Arc<DecodedPointer>),
}

impl PartialEq for PointerShape {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) | (Self::Hidden, Self::Hidden) => true,
            (Self::Bitmap(a), Self::Bitmap(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// Co wysłać do aplikacji.
enum PointerOut {
    Default,
    Hidden,
    Frame(Pointer),
}

/// Pamięta tylko ostatni stan wskaźnika i ostatnio wysłany. Wrogi serwer może kilkubajtowymi PDU
/// (kształt z pamięci podręcznej) wymuszać duże ramki, a wskaźnik nie podlega kontroli przepływu,
/// więc wysyłka idzie najwyżej raz na wysyłkę obrazu. Daje to też pomijanie `PointerHidden`, które
/// biblioteka zgłasza tuż przed kształtem z pamięci podręcznej (krok pośredni): liczy się stan
/// końcowy, a kursor nie mruga.
struct PointerState {
    wanted: Option<PointerShape>,
    sent: Option<PointerShape>,
}

impl PointerState {
    fn new() -> Self {
        Self {
            wanted: None,
            sent: None,
        }
    }

    fn set(&mut self, shape: PointerShape) {
        // Kształt o boku zero to ukryty kursor (patrz `pointer_out`); sprowadzony do `Hidden`
        // nie jest wysyłany ponownie, gdy kursor już jest ukryty.
        self.wanted = Some(match shape {
            PointerShape::Bitmap(p) if p.width == 0 || p.height == 0 => PointerShape::Hidden,
            other => other,
        });
    }

    /// Stan do wysłania teraz, jeśli różni się od ostatnio wysłanego.
    fn take_due(&mut self) -> Option<PointerOut> {
        let wanted = self.wanted.take()?;
        if self.sent.as_ref() == Some(&wanted) {
            return None;
        }
        let out = match &wanted {
            PointerShape::Default => PointerOut::Default,
            PointerShape::Hidden => PointerOut::Hidden,
            PointerShape::Bitmap(p) => pointer_out(p),
        };
        self.sent = Some(wanted);
        Some(out)
    }
}

/// Kształt o boku zero to w IronRDP kursor niewidoczny; kształt, którego nie umiemy bezpiecznie
/// przekazać (ponad limit, długość niezgodna z wymiarami), zastępujemy kursorem domyślnym zamiast
/// psuć sesję.
fn pointer_out(p: &DecodedPointer) -> PointerOut {
    if p.width == 0 || p.height == 0 {
        return PointerOut::Hidden;
    }
    pointer_frame(p).map_or(PointerOut::Default, PointerOut::Frame)
}

/// Wysyła do aplikacji ostatni stan wskaźnika, jeśli się zmienił.
fn flush_pointer(pointer: &mut PointerState) {
    match pointer.take_due() {
        Some(PointerOut::Default) => emit(&FromWorker::PointerDefault),
        Some(PointerOut::Hidden) => emit(&FromWorker::PointerHidden),
        Some(PointerOut::Frame(frame)) => emit_pointer(&frame),
        None => {}
    }
}

fn flush_all(image: &DecodedImage, dirty: &mut Dirty, pointer: &mut PointerState) {
    flush(image, dirty);
    flush_pointer(pointer);
}

/// Czy błąd przetwarzania PDU pochodzi z dekodowania kształtu wskaźnika. Biblioteka opakowuje
/// wtedy `PointerError` jako źródło błędu sesji (`SessionError::custom` w `process_pointer_update`),
/// więc rozpoznajemy go po typie źródła, a nie po treści komunikatu.
fn is_pointer_decode_error(e: &SessionError) -> bool {
    std::error::Error::source(e).is_some_and(|s| s.is::<PointerError>())
}

fn operations_for(cmd: &ToWorker) -> Vec<Operation> {
    let button = |b: u8| match b {
        0 => Some(MouseButton::Left),
        1 => Some(MouseButton::Middle),
        2 => Some(MouseButton::Right),
        3 => Some(MouseButton::X1),
        4 => Some(MouseButton::X2),
        _ => None,
    };
    match *cmd {
        ToWorker::MouseMove { x, y } => vec![Operation::MouseMove(MousePosition { x, y })],
        ToWorker::MouseButton { button: b, down } => button(b)
            .map(|b| {
                vec![if down {
                    Operation::MouseButtonPressed(b)
                } else {
                    Operation::MouseButtonReleased(b)
                }]
            })
            .unwrap_or_default(),
        ToWorker::Wheel { vertical, delta } => {
            vec![Operation::WheelRotations(WheelRotations {
                is_vertical: vertical,
                rotation_units: delta,
            })]
        }
        ToWorker::Key {
            scancode,
            extended,
            down,
        } => {
            let sc = Scancode::from_u8(extended, scancode);
            vec![if down {
                Operation::KeyPressed(sc)
            } else {
                Operation::KeyReleased(sc)
            }]
        }
        ToWorker::CtrlAltDel => {
            let (ctrl, alt, del) = (
                Scancode::from_u8(false, 0x1d),
                Scancode::from_u8(false, 0x38),
                Scancode::from_u8(true, 0x53),
            );
            vec![
                Operation::KeyPressed(ctrl),
                Operation::KeyPressed(alt),
                Operation::KeyPressed(del),
                Operation::KeyReleased(del),
                Operation::KeyReleased(alt),
                Operation::KeyReleased(ctrl),
            ]
        }
        _ => Vec::new(),
    }
}

/// Prostokąt `(lewy, górny, prawy, dolny)`, współrzędne włącznie.
type Rect = (u16, u16, u16, u16);

/// Najwięcej osobnych prostokątów zmian do następnego wysłania obrazu.
const MAX_DIRTY_RECTS: usize = 16;
/// Połączenie dwóch prostokątów opłaca się, gdy dokłada najwyżej tyle pikseli zbędnych...
const MERGE_FREE_WASTE: u64 = 64;
/// ...albo gdy zbędne piksele to najwyżej 1/8 pikseli faktycznie zmienionych w obu.
const MERGE_WASTE_DIVISOR: u64 = 8;

fn rect_area((l, t, r, b): Rect) -> u64 {
    u64::from(r - l + 1) * u64::from(b - t + 1)
}

fn rect_union(a: Rect, b: Rect) -> Rect {
    (a.0.min(b.0), a.1.min(b.1), a.2.max(b.2), a.3.max(b.3))
}

fn rect_overlap_area(a: Rect, b: Rect) -> u64 {
    let (l, t, r, bt) = (a.0.max(b.0), a.1.max(b.1), a.2.min(b.2), a.3.min(b.3));
    if l > r || t > bt {
        0
    } else {
        rect_area((l, t, r, bt))
    }
}

/// Piksele, które połączenie dokłada ponad faktycznie zmienione, i liczba faktycznie zmienionych.
fn merge_cost(a: Rect, b: Rect) -> (u64, u64) {
    let covered = rect_area(a) + rect_area(b) - rect_overlap_area(a, b);
    (rect_area(rect_union(a, b)) - covered, covered)
}

/// Ograniczona lista prostokątów zmienionych od ostatniego wysłania obrazu (współrzędne włącznie,
/// przycięte do obrazu). Dwie małe zmiany w przeciwległych rogach zostają dwoma prostokątami, a nie
/// jednym na cały ekran; prostokąty, których połączenie prawie nic nie marnuje (stykające się,
/// zachodzące, zawarte), są łączone. Po przekroczeniu `MAX_DIRTY_RECTS` łączone są te pary, które
/// marnują najmniej, aż lista się zmieści (w ostateczności zostaje jeden prostokąt obejmujący).
struct Dirty {
    width: u16,
    height: u16,
    rects: Vec<Rect>,
}

impl Dirty {
    fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            rects: Vec::new(),
        }
    }

    fn add(&mut self, l: u16, t: u16, r: u16, b: u16) {
        if self.width == 0 || self.height == 0 {
            return;
        }
        let (r, b) = (r.min(self.width - 1), b.min(self.height - 1));
        if l > r || t > b {
            return;
        }
        self.rects.push((l, t, r, b));
        // Łączymy do ustabilizowania: połączony prostokąt bywa większy i może teraz pasować do innych.
        'again: loop {
            for i in 0..self.rects.len() {
                for j in i + 1..self.rects.len() {
                    let (waste, covered) = merge_cost(self.rects[i], self.rects[j]);
                    if waste <= MERGE_FREE_WASTE || waste * MERGE_WASTE_DIVISOR <= covered {
                        self.merge(i, j);
                        continue 'again;
                    }
                }
            }
            break;
        }
        while self.rects.len() > MAX_DIRTY_RECTS {
            let mut best = (u64::MAX, 0, 1);
            for i in 0..self.rects.len() {
                for j in i + 1..self.rects.len() {
                    let (waste, _) = merge_cost(self.rects[i], self.rects[j]);
                    if waste < best.0 {
                        best = (waste, i, j);
                    }
                }
            }
            self.merge(best.1, best.2);
        }
    }

    /// Scala prostokąt `j` z `i` (musi być `i < j`).
    fn merge(&mut self, i: usize, j: usize) {
        let removed = self.rects.remove(j);
        self.rects[i] = rect_union(self.rects[i], removed);
    }

    /// Oddaje zebrane prostokąty i zaczyna od zera.
    fn take(&mut self) -> Vec<Rect> {
        std::mem::take(&mut self.rects)
    }
}

/// Największy fragment obrazu w jednej ramce. Musi być poniżej `MAX_FRAME`: większe ramki były
/// odrzucane po cichu i duże pulpity (od ok. 4K) przestawały się odświeżać. Mniejsze pasy dochodzą
/// też szybciej do interfejsu.
const STRIP_BYTES: usize = 16 * 1024 * 1024;
const _: () = assert!(STRIP_BYTES < rdp_proto::MAX_FRAME);

fn flush(image: &DecodedImage, dirty: &mut Dirty) {
    for rect in dirty.take() {
        for img in strips(
            image.data(),
            image.width(),
            image.height(),
            rect,
            STRIP_BYTES,
        ) {
            emit_image(&img);
        }
    }
}

/// Wycina prostokąt `(l, t, r, b)` (włącznie) z obrazu RGBA, dzieląc go na poziome pasy
/// po najwyżej `max_bytes` bajtów (zawsze co najmniej jeden wiersz).
fn strips(data: &[u8], iw: u16, ih: u16, (l, t, r, b): Rect, max_bytes: usize) -> Vec<Image> {
    if iw == 0 || ih == 0 {
        return Vec::new();
    }
    let (r, b) = (r.min(iw - 1), b.min(ih - 1));
    if l > r || t > b {
        return Vec::new();
    }
    let w = r - l + 1;
    let row_bytes = usize::from(w) * 4;
    let rows_per_strip = u16::try_from((max_bytes / row_bytes).max(1)).unwrap_or(u16::MAX);
    let stride = usize::from(iw) * 4;
    let mut out = Vec::new();
    let mut top = t;
    loop {
        let bottom = top.saturating_add(rows_per_strip - 1).min(b);
        let mut rgba = Vec::with_capacity(row_bytes * usize::from(bottom - top + 1));
        for row in top..=bottom {
            let start = usize::from(row) * stride + usize::from(l) * 4;
            rgba.extend_from_slice(&data[start..start + row_bytes]);
        }
        out.push(Image {
            x: l,
            y: top,
            width: w,
            height: bottom - top + 1,
            rgba,
        });
        if bottom == b {
            break;
        }
        top = bottom + 1;
    }
    out
}

/// Windows: gniazda biblioteki standardowej mają atrybut "overlapped", a odczyt z limitem czasu
/// (`SO_RCVTIMEO`, nasze odpytywanie co `POLL`) bywa na nich przerywany w chwili, gdy system
/// anuluje operację po upływie limitu. Zamiast przekroczenia czasu wraca wtedy `WSA_IO_PENDING`.
/// To nie jest błąd połączenia: kolejny odczyt działa, a sesja kończona tym kodem urywała się
/// "czasami", bez związku z serwerem.
fn is_pending_read(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(WSA_IO_PENDING)
}

/// Czy błąd odczytu oznacza tylko, że na razie nie ma danych: limit czasu odpytywania albo
/// `WSA_IO_PENDING`, o ile nie powtarza się bez końca (`pending_reads` to liczba kolejnych wystąpień).
fn no_data_yet(e: &io::Error, pending_reads: u32) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) || (is_pending_read(e) && pending_reads < MAX_PENDING_READS)
}

fn set_timeout(framed: &Framed, d: Duration) {
    let _ = framed.get_inner().0.sock.set_read_timeout(Some(d));
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "multiremotemanager".to_owned())
}

/// Flagi wydajności wysyłane serwerowi w zależności od profilu łącza. `Fast` to dotychczasowe
/// ustawienia biblioteki. `Slow` wyłącza tapetę, przeciąganie okien z zawartością, animacje menu,
/// motywy i cień kursora; nie włącza wygładzania czcionek ani kompozycji pulpitu i nie dotyka bitów
/// zarezerwowanych. Serwer może te flagi zignorować albo nadpisać własnymi.
///
/// Kompresji danych (`compression_type`) i 16 bitów koloru świadomie NIE włączamy w żadnym profilu:
/// IronRDP 0.17 dekompresuje tylko fast-path (ścieżka slow-path ma w źródle TODO i dostałaby
/// skompresowane bajty jako grafikę), a ogłaszana głębia kolorów jest w bibliotece wpisana na stałe.
fn performance_flags(profile: LinkProfile) -> PerformanceFlags {
    match profile {
        LinkProfile::Fast => PerformanceFlags::default(),
        LinkProfile::Slow => {
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_THEMING
                | PerformanceFlags::DISABLE_CURSOR_SHADOW
        }
    }
}

/// Ustawia gniazdo długo żyjącej sesji: bez opóźniania małych pakietów (ruch myszy, klawisze),
/// z keepalive (pierwsza sonda po `KEEPALIVE_IDLE`, kolejne co `KEEPALIVE_INTERVAL`) i limitem czasu
/// zapisu. Próbuje wszystkich ustawień i zwraca pierwszy błąd; wywołujący może go zignorować
/// (sesja działa też bez nich).
fn tune_socket(tcp: &TcpStream) -> io::Result<()> {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    let results = [
        tcp.set_nodelay(true),
        tcp.set_write_timeout(Some(WRITE_TIMEOUT)),
        socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive),
    ];
    results.into_iter().collect()
}

fn build_config(p: &ConnectParams) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: p.username.clone(),
            password: p.password.clone(),
        },
        domain: p.domain.clone().filter(|d| !d.is_empty()),
        enable_tls: false,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: p.width,
            height: p.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "multiremotemanager".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(not(windows))]
        platform: MajorPlatformType::UNIX,
        // Kształt wskaźnika idzie do aplikacji (lokalny kursor), a nie do obrazu pulpitu.
        enable_server_pointer: true,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        compression_type: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: performance_flags(p.profile),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// Wykonawcy operacji WebAuthn dla kolejnych otwarć kanału: systemowe API Windows (okno
/// "Zabezpieczenia Windows"). Stan operacji w toku jest wspólny, bo serwer otwiera kanał od nowa
/// przy każdej operacji, a anulowanie może przyjść już innym otwarciem. Okno nadrzędne 0 oznacza
/// okno na pierwszym planie, czyli okno aplikacji z tą sesją.
#[cfg(windows)]
fn webauthn_handlers() -> Option<webauthn::HandlerFactory> {
    use ironrdp_rdpewa::RdpewaClientHandler;
    use ironrdp_rdpewa_native::{WindowsRdpewaBackend, WindowsRdpewaSessionState};

    let state = Arc::new(WindowsRdpewaSessionState::default());
    Some(Box::new(move || {
        Box::new(WindowsRdpewaBackend::new_with_session_state(
            0,
            Arc::clone(&state),
        )) as Box<dyn RdpewaClientHandler>
    }))
}

/// Poza Windows nie ma wykonawcy operacji, więc kanał nie jest rejestrowany.
#[cfg(not(windows))]
fn webauthn_handlers() -> Option<webauthn::HandlerFactory> {
    None
}

/// Kanały przekierowania czytników kart: `rdpdr` z usługą kart Windows i wymagany obok niego
/// kanał dźwięku. `neutral` pokazuje serwerowi czytniki pod neutralnymi nazwami.
#[cfg(windows)]
fn smartcard_channels(
    neutral: bool,
    replies: mpsc::Sender<scard::Reply>,
) -> Option<(scard::Channel, scard::Sound)> {
    let engine = scard::Engine::new(scard_pcsc::System, replies, neutral);
    Some((
        scard::Channel::new(scard::Backend::new(engine), hostname()),
        scard::Sound::new(),
    ))
}

/// Poza Windows nie ma usługi kart, więc kanały nie są rejestrowane.
#[cfg(not(windows))]
fn smartcard_channels(
    _neutral: bool,
    _replies: mpsc::Sender<scard::Reply>,
) -> Option<(scard::Channel, scard::Sound)> {
    None
}

fn connect(
    config: &connector::Config,
    p: &ConnectParams,
    kerberos: Option<KerberosConfig>,
    rx: &Receiver<ToWorker>,
    clip_tx: mpsc::Sender<clip::ClipEvent>,
    webauthn: Option<webauthn::Listener>,
    smartcard: Option<(scard::Channel, scard::Sound)>,
) -> anyhow::Result<(ConnectionResult, Framed)> {
    let addrs: Vec<_> = (p.host.as_str(), p.port)
        .to_socket_addrs()
        .with_context(|| format!("nie można rozwiązać adresu {}", p.host))?
        .collect();
    // Kolejne adresy z DNS: np. przy niedziałającej trasie IPv6 próbujemy jeszcze IPv4.
    let mut last_err = None;
    let mut tcp = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_secs(10)) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let tcp = match (tcp, last_err) {
        (Some(t), _) => t,
        (None, Some(e)) => return Err(anyhow::Error::new(e).context("połączenie TCP")),
        (None, None) => anyhow::bail!("brak adresu hosta"),
    };
    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    if let Err(e) = tune_socket(&tcp) {
        log(format!("gniazdo: nie udało się ustawić opcji: {e}"));
    }
    let client_addr = tcp.local_addr()?;
    let mut framed = ironrdp_blocking::Framed::new(tcp);
    // Kanał dynamiczny Display Control pozwala zmieniać rozmiar pulpitu bez ponownego łączenia.
    let mut dynamic =
        DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    if let Some(listener) = webauthn {
        dynamic = dynamic.with_listener(listener);
    }
    let mut connector = connector::ClientConnector::new(config.clone(), client_addr)
        .with_static_channel(dynamic)
        .with_static_channel(Cliprdr::<Client>::new(Box::new(clip::ClipBackend {
            tx: clip_tx,
            tmp: std::env::temp_dir().to_string_lossy().into_owned(),
        })));
    if let Some((cards, sound)) = smartcard {
        connector = connector
            .with_static_channel(sound)
            .with_static_channel(cards);
    }
    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("negocjacja")?;

    let (tls, server_public_key) =
        tls_upgrade(framed.into_inner_no_leftover(), &p.host, rx).context("TLS")?;
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_blocking::Framed::new(tls);
    let mut network = ReqwestNetworkClient;
    let result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut network,
        p.host.clone().into(),
        server_public_key,
        kerberos,
    )
    .map_err(|e| anyhow!("uwierzytelnianie (NLA) nie powiodło się: {e}"))?;
    Ok((result, framed))
}

/// Nawiązuje TLS i prosi aplikację o decyzję o certyfikacie, zanim wyśle jakiekolwiek poświadczenia.
/// Konfiguracja TLS klienta RDP.
fn tls_client_config() -> rustls::ClientConfig {
    // Ten sam dostawca kryptografii, którego używa `ClientConfig::builder()`.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let verifier = PinnedCert {
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("domyślne wersje TLS są obsługiwane przez dostawcę")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    // CredSSP nie wspiera wznawiania sesji TLS.
    config.resumption = rustls::client::Resumption::disabled();
    config
}

/// Błąd uzgadniania TLS. Odrzucony podpis dostaje opis po polsku, bo to przypadek, w którym
/// użytkownik powinien wiedzieć, że połączenie mogło być przechwycone.
fn handshake_error(e: io::Error) -> anyhow::Error {
    let bad_signature = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|r| {
            matches!(
                r,
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
            )
        });
    if bad_signature {
        anyhow!(
            "serwer nie dowiódł, że ma klucz prywatny z przedstawionego certyfikatu. Połączenie przerwano: to może być próba podsłuchu albo błędna konfiguracja serwera"
        )
    } else {
        anyhow::Error::new(e)
    }
}

fn tls_upgrade(
    stream: TcpStream,
    host: &str,
    rx: &Receiver<ToWorker>,
) -> anyhow::Result<(Tls, Vec<u8>)> {
    let client =
        rustls::ClientConnection::new(Arc::new(tls_client_config()), host.to_owned().try_into()?)?;
    let mut tls = rustls::StreamOwned::new(client, stream);
    tls.flush().map_err(handshake_error)?;
    let cert = tls
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .context("brak certyfikatu serwera")?;

    let fingerprint = Sha256::digest(cert.as_ref())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let (key, subject) = parse_cert(cert)?;
    emit(&FromWorker::Cert {
        fingerprint,
        subject,
    });
    loop {
        match rx.recv() {
            Ok(ToWorker::Trust { accept: true }) => break,
            Ok(ToWorker::Trust { accept: false }) => bail!("certyfikat serwera został odrzucony"),
            Ok(ToWorker::Close) | Err(_) => bail!("przerwano przed potwierdzeniem certyfikatu"),
            Ok(_) => {}
        }
    }
    Ok((tls, key))
}

fn parse_cert(cert: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert)?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("klucz publiczny nie jest wyrównany do bajtów")?
        .to_owned();
    Ok((key, cert.tbs_certificate.subject.to_string()))
}

/// Weryfikator certyfikatu serwera RDP. Samego certyfikatu nie ocenia: serwery RDP mają zwykle
/// certyfikaty samopodpisane, a o zaufaniu decyduje odcisk potwierdzony przez użytkownika
/// i zapamiętany przez aplikację (patrz `tls_upgrade`). Podpis uzgadniania TLS sprawdza jednak
/// zawsze. Bez tego odcisk nie dowodziłby, że rozmówca ma klucz prywatny z certyfikatu: pośrednik
/// w sieci mógłby przedstawić cudzy, publicznie znany certyfikat, a zapamiętany odcisk
/// przepuściłby go bez pytania.
#[derive(Debug)]
struct PinnedCert {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_timeouts_and_pending_reads_mean_no_data_yet() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert!(no_data_yet(&io::Error::from(kind), 0));
        }
        assert!(!no_data_yet(
            &io::Error::from(io::ErrorKind::ConnectionReset),
            0
        ));
        // Kod 997 znaczy "brak danych" tylko na Windows i tylko, dopóki nie powtarza się bez końca.
        let pending = io::Error::from_raw_os_error(WSA_IO_PENDING);
        assert_eq!(is_pending_read(&pending), cfg!(windows));
        assert_eq!(no_data_yet(&pending, 0), cfg!(windows));
        assert_eq!(no_data_yet(&pending, MAX_PENDING_READS - 1), cfg!(windows));
        assert!(!no_data_yet(&pending, MAX_PENDING_READS));
    }

    #[test]
    fn desktop_size_is_validated() {
        assert_eq!(validate_desktop_size(1, 1).unwrap(), (1, 1));
        assert_eq!(validate_desktop_size(1920, 1080).unwrap(), (1920, 1080));
        assert_eq!(validate_desktop_size(8192, 8192).unwrap(), (8192, 8192));
        assert_eq!(validate_desktop_size(16384, 4096).unwrap(), (16384, 4096));
        for (w, h) in [
            (16384, 16384),
            (8193, 8192),
            (0, 0),
            (0, 600),
            (800, 0),
            (16385, 600),
            (800, 16385),
            (65535, 65535),
        ] {
            let e = validate_desktop_size(w, h).unwrap_err().to_string();
            assert!(e.contains("nieprawidłowy rozmiar pulpitu"), "{e}");
        }
    }

    #[test]
    fn resize_waits_for_display_control_then_gives_up() {
        assert_eq!(resize_step(true, Duration::ZERO), ResizeStep::Send);
        assert_eq!(resize_step(true, RESIZE_WAIT * 2), ResizeStep::Send);
        assert_eq!(resize_step(false, Duration::ZERO), ResizeStep::Wait);
        assert_eq!(
            resize_step(false, RESIZE_WAIT - Duration::from_millis(1)),
            ResizeStep::Wait
        );
        assert_eq!(resize_step(false, RESIZE_WAIT), ResizeStep::GiveUp);
    }

    #[test]
    fn dirty_rectangles_are_merged() {
        let mut d = Dirty::new(200, 200);
        assert!(d.rects.is_empty());
        d.add(10, 20, 30, 40);
        d.add(5, 25, 28, 90);
        // Zachodzące prostokąty o małym marnotrawstwie: jeden wspólny.
        assert_eq!(d.take(), vec![(5, 20, 30, 90)]);
        assert!(d.take().is_empty());
    }

    #[test]
    fn dirty_keeps_distant_changes_apart_and_merges_neighbours() {
        let mut d = Dirty::new(1000, 800);
        d.add(0, 0, 9, 9);
        d.add(990, 790, 999, 799);
        assert_eq!(d.rects, vec![(0, 0, 9, 9), (990, 790, 999, 799)]);
        // Stykający się z pierwszym (bez marnotrawstwa) łączy się z nim.
        d.add(10, 0, 19, 9);
        assert_eq!(d.rects, vec![(0, 0, 19, 9), (990, 790, 999, 799)]);
        // Zawarty w już zebranym nic nie zmienia.
        d.add(2, 2, 3, 3);
        assert_eq!(d.rects.len(), 2);
        // Pusty prostokąt biblioteki (0,0,0,0) leży w pierwszym.
        d.add(0, 0, 0, 0);
        assert_eq!(d.rects.len(), 2);
    }

    #[test]
    fn dirty_library_empty_rectangle_does_not_inflate_the_area() {
        let mut d = Dirty::new(200, 200);
        d.add(0, 0, 0, 0);
        d.add(100, 100, 199, 199);
        let total: u64 = d.rects.iter().map(|&r| rect_area(r)).sum();
        assert_eq!(d.rects.len(), 2);
        assert_eq!(total, 1 + 100 * 100);
    }

    #[test]
    fn dirty_clips_to_image_and_ignores_empty_ranges() {
        let mut d = Dirty::new(100, 50);
        d.add(90, 40, 5000, 5000);
        assert_eq!(d.rects, vec![(90, 40, 99, 49)]);
        d.add(100, 0, 200, 10);
        d.add(0, 50, 10, 60);
        d.add(20, 0, 10, 10);
        assert_eq!(d.rects.len(), 1);
        let mut empty = Dirty::new(0, 0);
        empty.add(0, 0, 1, 1);
        assert!(empty.rects.is_empty());
    }

    /// Niezmiennik: każdy piksel każdego dodanego (przyciętego) prostokąta jest pokryty przez listę,
    /// lista mieści się w limicie, a jej prostokąty leżą w obrazie.
    #[test]
    fn dirty_list_covers_every_added_pixel_within_the_limit() {
        let (w, h) = (96u16, 64u16);
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        for round in 0..200 {
            let mut d = Dirty::new(w, h);
            let mut added: Vec<Rect> = Vec::new();
            for _ in 0..(1 + next(60)) {
                // Część prostokątów wystaje poza obraz albo jest pojedynczym pikselem.
                let l = next(u64::from(w) + 20) as u16;
                let t = next(u64::from(h) + 20) as u16;
                let span = if next(3) == 0 { 0 } else { next(30) as u16 };
                let (r, b) = (l + span, t + (next(20) as u16));
                d.add(l, t, r, b);
                let (cr, cb) = (r.min(w - 1), b.min(h - 1));
                if l <= cr && t <= cb {
                    added.push((l, t, cr, cb));
                }
                assert!(d.rects.len() <= MAX_DIRTY_RECTS, "runda {round}");
            }
            for &(l, t, r, b) in &d.rects {
                assert!(l <= r && t <= b && r < w && b < h, "{:?}", d.rects);
            }
            for &(l, t, r, b) in &added {
                for y in t..=b {
                    for x in l..=r {
                        assert!(
                            d.rects
                                .iter()
                                .any(|&(a, c, e, f)| a <= x && x <= e && c <= y && y <= f),
                            "piksel {x},{y} niepokryty, runda {round}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dirty_over_the_limit_degrades_to_fewer_rectangles() {
        let mut d = Dirty::new(2000, 2000);
        // 40 odległych kropek: lista ma zostać w limicie, a pierwsza kropka pokryta.
        for i in 0..40u16 {
            d.add(i * 50, i * 50, i * 50, i * 50);
            assert!(d.rects.len() <= MAX_DIRTY_RECTS);
        }
        assert!(d.rects.iter().any(|&(l, t, _, _)| l == 0 && t == 0));
        assert!(d.rects.len() > 1);
    }

    fn decoded(w: u16, h: u16, len: usize, hot: (u16, u16)) -> DecodedPointer {
        DecodedPointer {
            width: w,
            height: h,
            hotspot_x: hot.0,
            hotspot_y: hot.1,
            bitmap_data: vec![7; len],
        }
    }

    #[test]
    fn pointer_frame_accepts_valid_and_rejects_bad_shapes() {
        let ok = pointer_frame(&decoded(32, 32, 32 * 32 * 4, (3, 4))).unwrap();
        assert_eq!((ok.width, ok.height, ok.hot_x, ok.hot_y), (32, 32, 3, 4));
        assert_eq!(ok.rgba.len(), 32 * 32 * 4);
        // Punkt zaczepienia poza bitmapą jest ucinany.
        let clamped = pointer_frame(&decoded(8, 8, 8 * 8 * 4, (500, 9))).unwrap();
        assert_eq!((clamped.hot_x, clamped.hot_y), (7, 7));
        assert!(pointer_frame(&decoded(384, 384, 384 * 384 * 4, (0, 0))).is_some());
        for bad in [
            decoded(0, 0, 0, (0, 0)),
            decoded(0, 8, 0, (0, 0)),
            decoded(385, 1, 385 * 4, (0, 0)),
            decoded(1, 385, 385 * 4, (0, 0)),
            decoded(8, 8, 8 * 8 * 4 - 1, (0, 0)),
            decoded(8, 8, 8 * 8 * 4 + 4, (0, 0)),
        ] {
            assert!(pointer_frame(&bad).is_none());
        }
    }

    fn shape(w: u16, h: u16) -> PointerShape {
        PointerShape::Bitmap(Arc::new(decoded(
            w,
            h,
            usize::from(w) * usize::from(h) * 4,
            (0, 0),
        )))
    }

    fn kind(o: &Option<PointerOut>) -> &'static str {
        match o {
            None => "nic",
            Some(PointerOut::Default) => "domyslny",
            Some(PointerOut::Hidden) => "ukryty",
            Some(PointerOut::Frame(_)) => "ksztalt",
        }
    }

    #[test]
    fn pointer_series_between_flushes_sends_only_the_last_state() {
        let mut st = PointerState::new();
        assert_eq!(kind(&st.take_due()), "nic");
        st.set(PointerShape::Hidden);
        st.set(shape(2, 2));
        st.set(PointerShape::Default);
        st.set(PointerShape::Hidden);
        assert_eq!(kind(&st.take_due()), "ukryty");
        assert_eq!(kind(&st.take_due()), "nic");
        // Ukrycie tuż przed kształtem z pamięci podręcznej daje sam kształt.
        st.set(PointerShape::Hidden);
        st.set(shape(2, 2));
        assert_eq!(kind(&st.take_due()), "ksztalt");
    }

    #[test]
    fn repeated_same_shape_is_not_sent_again() {
        let mut st = PointerState::new();
        let a = shape(4, 4);
        st.set(a.clone());
        assert_eq!(kind(&st.take_due()), "ksztalt");
        st.set(a.clone());
        assert_eq!(kind(&st.take_due()), "nic");
        // Ukrycie tuż przed tym samym kształtem (kształt z pamięci podręcznej) też nic nie wysyła.
        st.set(PointerShape::Hidden);
        st.set(a.clone());
        assert_eq!(kind(&st.take_due()), "nic");
        // Inny kształt o tej samej treści to osobny `Arc` i jest wysyłany.
        st.set(shape(4, 4));
        assert_eq!(kind(&st.take_due()), "ksztalt");
    }

    #[test]
    fn shape_hidden_same_shape_is_sent_across_flushes() {
        let mut st = PointerState::new();
        let a = shape(4, 4);
        st.set(a.clone());
        assert_eq!(kind(&st.take_due()), "ksztalt");
        st.set(PointerShape::Hidden);
        assert_eq!(kind(&st.take_due()), "ukryty");
        st.set(a);
        assert_eq!(kind(&st.take_due()), "ksztalt");
    }

    #[test]
    fn reactivation_default_overrides_hidden_or_shape() {
        let mut st = PointerState::new();
        st.set(PointerShape::Hidden);
        assert_eq!(kind(&st.take_due()), "ukryty");
        st.set(PointerShape::Default);
        assert_eq!(kind(&st.take_due()), "domyslny");
        st.set(shape(4, 4));
        assert_eq!(kind(&st.take_due()), "ksztalt");
        st.set(PointerShape::Default);
        assert_eq!(kind(&st.take_due()), "domyslny");
    }

    #[test]
    fn zero_sized_shape_hides_and_bad_shape_falls_back_to_default() {
        let mut st = PointerState::new();
        st.set(PointerShape::Bitmap(Arc::new(decoded(0, 0, 0, (0, 0)))));
        assert_eq!(kind(&st.take_due()), "ukryty");
        st.set(PointerShape::Bitmap(Arc::new(decoded(0, 8, 0, (0, 0)))));
        assert_eq!(kind(&st.take_due()), "nic");
        st.set(PointerShape::Bitmap(Arc::new(decoded(8, 8, 3, (0, 0)))));
        assert_eq!(kind(&st.take_due()), "domyslny");
    }

    #[test]
    fn only_pointer_decode_errors_are_recognised() {
        use ironrdp::session::SessionErrorExt as _;
        let pointer = SessionError::custom(
            "failed to decode pointer attribute",
            PointerError::NotSupportedBpp { bpp: 8 },
        );
        assert!(is_pointer_decode_error(&pointer));
        assert!(!is_pointer_decode_error(&SessionError::general("inny")));
        assert!(!is_pointer_decode_error(&SessionError::reason(
            "inny", "powód"
        )));
        let io = SessionError::custom("inny", io::Error::other("x"));
        assert!(!is_pointer_decode_error(&io));
    }

    #[test]
    fn config_uses_local_cursor_and_link_profile() {
        let c = build_config(&ConnectParams {
            host: "h".into(),
            port: 3389,
            username: "u".into(),
            domain: None,
            password: String::new(),
            kerberos: false,
            kdc: None,
            width: 800,
            height: 600,
            profile: LinkProfile::Slow,
            webauthn: false,
            smartcard: rdp_proto::CardRedirect::Off,
        });
        assert!(c.enable_server_pointer);
        assert!(!c.pointer_software_rendering);
        assert!(c.compression_type.is_none());
        assert_eq!(c.performance_flags, performance_flags(LinkProfile::Slow));
    }

    #[test]
    fn link_profiles_map_to_performance_flags() {
        assert_eq!(
            performance_flags(LinkProfile::Fast),
            PerformanceFlags::default()
        );
        let slow = performance_flags(LinkProfile::Slow);
        assert_eq!(
            slow,
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_THEMING
                | PerformanceFlags::DISABLE_CURSOR_SHADOW
        );
        for off in [
            PerformanceFlags::ENABLE_FONT_SMOOTHING,
            PerformanceFlags::ENABLE_DESKTOP_COMPOSITION,
            PerformanceFlags::RESERVED1,
            PerformanceFlags::RESERVED2,
        ] {
            assert!(!slow.intersects(off));
        }
    }

    #[test]
    fn tune_socket_sets_nodelay_keepalive_and_write_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tune_socket(&tcp).unwrap();
        assert!(tcp.nodelay().unwrap());
        assert_eq!(tcp.write_timeout().unwrap(), Some(WRITE_TIMEOUT));
        let sock = socket2::SockRef::from(&tcp);
        assert!(sock.keepalive().unwrap());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(sock.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
            assert_eq!(sock.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
        }
    }

    #[test]
    fn mouse_buttons_map_and_unknown_are_ignored() {
        assert_eq!(
            operations_for(&ToWorker::MouseButton {
                button: 0,
                down: true
            })
            .len(),
            1
        );
        assert_eq!(
            operations_for(&ToWorker::MouseButton {
                button: 9,
                down: true
            })
            .len(),
            0
        );
        assert_eq!(operations_for(&ToWorker::MouseMove { x: 1, y: 2 }).len(), 1);
    }

    #[test]
    fn ctrl_alt_del_presses_and_releases_in_order() {
        let ops = operations_for(&ToWorker::CtrlAltDel);
        assert_eq!(ops.len(), 6);
        assert!(matches!(ops[0], Operation::KeyPressed(_)));
        assert!(matches!(ops[5], Operation::KeyReleased(_)));
    }

    #[test]
    fn control_commands_produce_no_input() {
        assert!(operations_for(&ToWorker::Close).is_empty());
        assert!(operations_for(&ToWorker::ClipFetchFiles).is_empty());
    }

    #[test]
    fn large_dirty_area_is_split_into_strips_under_the_limit() {
        let (iw, ih) = (10u16, 7u16);
        let data: Vec<u8> = (0..usize::from(iw) * usize::from(ih) * 4)
            .map(|i| (i % 251) as u8)
            .collect();
        // Prostokąt 4x7 od kolumny 2; limit pozwala na 2 wiersze (32 B) w pasie.
        let parts = strips(&data, iw, ih, (2, 0, 5, 6), 40);
        assert_eq!(parts.len(), 4);
        assert!(
            parts
                .iter()
                .all(|p| p.rgba.len() <= 40 && p.x == 2 && p.width == 4)
        );
        assert_eq!(
            parts.iter().map(|p| (p.y, p.height)).collect::<Vec<_>>(),
            [(0, 2), (2, 2), (4, 2), (6, 1)]
        );
        // Złożone pasy dają ten sam obraz co jeden duży prostokąt.
        let whole = strips(&data, iw, ih, (2, 0, 5, 6), usize::MAX);
        assert_eq!(whole.len(), 1);
        let joined: Vec<u8> = parts.iter().flat_map(|p| p.rgba.clone()).collect();
        assert_eq!(joined, whole[0].rgba);
    }

    /// Para certyfikat i klucz RSA wygenerowana w locie przez `openssl` (DER).
    fn openssl_pair(
        dir: &std::path::Path,
        name: &str,
    ) -> Option<(
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        let run = |args: &[&str]| {
            std::process::Command::new("openssl")
                .args(args)
                .current_dir(dir)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        let (key, cert) = (format!("{name}.key.pem"), format!("{name}.crt.pem"));
        let (key_der, cert_der) = (format!("{name}.key.der"), format!("{name}.crt.der"));
        let made = run(&[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=test",
            "-keyout", &key, "-out", &cert,
        ]) && run(&["x509", "-in", &cert, "-outform", "DER", "-out", &cert_der])
            && run(&[
                "pkcs8", "-topk8", "-nocrypt", "-in", &key, "-outform", "DER", "-out", &key_der,
            ]);
        if !made {
            return None;
        }
        let cert = std::fs::read(dir.join(cert_der)).ok()?;
        let key = std::fs::read(dir.join(key_der)).ok()?;
        Some((
            rustls::pki_types::CertificateDer::from(cert),
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key,
            )),
        ))
    }

    #[derive(Debug)]
    struct FixedCert(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for FixedCert {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// Uzgadnianie TLS klienta RDP z lokalnym serwerem, który przedstawia `cert`, a podpisuje
    /// kluczem `key`. Zwraca wynik po stronie klienta.
    fn handshake_with(
        version: &'static rustls::SupportedProtocolVersion,
        cert: rustls::pki_types::CertificateDer<'static>,
        key: &rustls::pki_types::PrivateKeyDer<'static>,
    ) -> io::Result<()> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(key).unwrap();
        let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert], signing));
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(certified))),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = rustls::ServerConnection::new(server_config).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut stream).is_err() {
                    break;
                }
            }
        });
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let client = rustls::ClientConnection::new(
            Arc::new(tls_client_config()),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        let mut tls = rustls::StreamOwned::new(client, stream);
        let result = tls.flush();
        drop(tls);
        server.join().unwrap();
        result
    }

    /// Odcisk certyfikatu ma sens tylko wtedy, gdy serwer dowiedzie, że ma klucz prywatny z tego
    /// certyfikatu. Pośrednik w sieci zna cudzy certyfikat (jest publiczny), ale podpisuje własnym
    /// kluczem: takie uzgadnianie musi się nie udać, inaczej zapamiętany odcisk przepuszcza go po cichu.
    #[test]
    fn tls_handshake_requires_key_matching_the_certificate() {
        let dir = std::env::temp_dir().join(format!("mrm-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pairs = (
            openssl_pair(&dir, "serwer"),
            openssl_pair(&dir, "posrednik"),
        );
        let _ = std::fs::remove_dir_all(&dir);
        let (Some((server_cert, server_key)), Some((_, intruder_key))) = pairs else {
            eprintln!("pominięto: brak polecenia openssl");
            return;
        };
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            handshake_with(version, server_cert.clone(), &server_key)
                .unwrap_or_else(|e| panic!("{version:?}: właściwy serwer odrzucony: {e}"));
            let forged = handshake_with(version, server_cert.clone(), &intruder_key);
            let Err(e) = forged else {
                panic!("{version:?}: przyjęto serwer bez klucza prywatnego z certyfikatu");
            };
            let shown = handshake_error(e).to_string();
            assert!(shown.contains("klucz prywatny"), "{version:?}: {shown}");
        }
    }
}
