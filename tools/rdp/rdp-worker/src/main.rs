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
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_graphics::image_processing::PixelFormat;
use rdp_proto::{ClipKind, ConnectParams, FromWorker, Image, Message, ToWorker};
use sha2::{Digest as _, Sha256};
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use tokio_rustls::rustls;

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
mod clip;

type Framed = ironrdp_blocking::Framed<Tls>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(15);
const FLUSH_EVERY: Duration = Duration::from_millis(16);

pub(crate) fn emit(ev: &FromWorker) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_json(&mut out, ev);
}

pub(crate) fn emit_clip(kind: ClipKind, data: &[u8]) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_clip(&mut out, kind, data);
}

fn emit_image(img: &Image) {
    let mut out = io::stdout().lock();
    let _ = rdp_proto::write_image(&mut out, img);
}

fn main() {
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
                Ok(Some(Message::Image(_))) => {}
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
    let (result, mut framed) =
        connect(&config, &params, kerberos, rx, clip_tx).context("połączenie")?;
    set_timeout(&framed, POLL);

    let factory =
        ConnectionActivationFactory::new(config, result.io_channel_id, result.user_channel_id);
    let (w, h) = (result.desktop_size.width, result.desktop_size.height);
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
    let mut dirty = Dirty::default();
    let mut last_flush = Instant::now();
    loop {
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
                    if let Some(Ok(frame)) = stage.encode_resize(w, h, None, None) {
                        framed.write_all(&frame).context("zapis zmiany rozmiaru")?;
                    }
                }
                Ok(cmd) => {
                    if clip.on_command(&cmd, &mut stage, &mut |b| framed.write_all(b))? {
                        continue;
                    }
                    let ops = operations_for(&cmd);
                    if !ops.is_empty() {
                        let events = input.apply(ops);
                        let outs = stage.process_fastpath_input(&mut image, &events)?;
                        handle(outs, &mut framed, &mut dirty)?;
                    }
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        while let Ok(ev) = clip_rx.try_recv() {
            clip.on_event(ev, &mut stage, &mut |b| framed.write_all(b))?;
        }
        clip.tick();

        match framed.read_pdu() {
            Ok((action, payload)) => {
                let outs = stage.process(&mut image, action, &payload)?;
                let mut reactivate_needed = false;
                for o in outs {
                    match o {
                        ActiveStageOutput::DeactivateAll => reactivate_needed = true,
                        other => {
                            if let Some(reason) = handle_one(other, &mut framed, &mut dirty)? {
                                flush(&image, &mut dirty);
                                return Ok(reason);
                            }
                        }
                    }
                }
                if reactivate_needed {
                    let (w, h) = reactivate(&mut framed, &factory, &mut stage, &mut image)?;
                    dirty = Dirty::default();
                    emit(&FromWorker::Resized {
                        width: w,
                        height: h,
                    });
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                flush(&image, &mut dirty);
                last_flush = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                flush(&image, &mut dirty);
                return Ok("serwer zamknął połączenie".into());
            }
            Err(e) => return Err(anyhow::Error::new(e).context("odczyt z serwera")),
        }
        if last_flush.elapsed() >= FLUSH_EVERY {
            flush(&image, &mut dirty);
            last_flush = Instant::now();
        }
    }
}

/// Sekwencja deaktywacji i reaktywacji (MS-RDPBCGR 1.3.1.3): serwer zmienia parametry pulpitu.
fn reactivate(
    framed: &mut Framed,
    factory: &ConnectionActivationFactory,
    stage: &mut ActiveStage,
    image: &mut DecodedImage,
) -> anyhow::Result<(u16, u16)> {
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
    stage.set_fastpath_processor(
        fast_path::ProcessorBuilder {
            io_channel_id: factory.io_channel_id(),
            user_channel_id: factory.user_channel_id(),
            share_id,
            enable_server_pointer: server_pointer,
            pointer_software_rendering: software_pointer,
            bulk_decompressor: None,
        }
        .build(),
    );
    stage.set_share_id(share_id);
    stage.set_enable_server_pointer(server_pointer);
    *image = DecodedImage::new(PixelFormat::RgbA32, desktop.width, desktop.height);
    set_timeout(framed, POLL);
    Ok((desktop.width, desktop.height))
}

fn handle(
    outs: Vec<ActiveStageOutput>,
    framed: &mut Framed,
    dirty: &mut Dirty,
) -> anyhow::Result<()> {
    for o in outs {
        handle_one(o, framed, dirty)?;
    }
    Ok(())
}

/// Zwraca powód zakończenia sesji, jeśli serwer ją zamknął.
fn handle_one(
    out: ActiveStageOutput,
    framed: &mut Framed,
    dirty: &mut Dirty,
) -> anyhow::Result<Option<String>> {
    match out {
        ActiveStageOutput::ResponseFrame(frame) => {
            framed.write_all(&frame).context("zapis odpowiedzi")?
        }
        ActiveStageOutput::GraphicsUpdate(r) => dirty.add(r.left, r.top, r.right, r.bottom),
        ActiveStageOutput::Terminate(reason) => {
            return Ok(Some(format!("serwer zakończył sesję: {reason:?}")));
        }
        _ => {}
    }
    Ok(None)
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

/// Suma prostokątów zmienionych od ostatniego wysłania obrazu (współrzędne włącznie).
#[derive(Default)]
struct Dirty(Option<(u16, u16, u16, u16)>);

impl Dirty {
    fn add(&mut self, l: u16, t: u16, r: u16, b: u16) {
        self.0 = Some(match self.0 {
            None => (l, t, r, b),
            Some((a, c, d, e)) => (a.min(l), c.min(t), d.max(r), e.max(b)),
        });
    }
}

fn flush(image: &DecodedImage, dirty: &mut Dirty) {
    let Some((l, t, r, b)) = dirty.0.take() else {
        return;
    };
    let (iw, ih) = (image.width(), image.height());
    if iw == 0 || ih == 0 {
        return;
    }
    let (r, b) = (r.min(iw - 1), b.min(ih - 1));
    if l > r || t > b {
        return;
    }
    let (w, h) = (r - l + 1, b - t + 1);
    let stride = usize::from(iw) * 4;
    let data = image.data();
    let mut rgba = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
    for row in t..=b {
        let start = usize::from(row) * stride + usize::from(l) * 4;
        rgba.extend_from_slice(&data[start..start + usize::from(w) * 4]);
    }
    emit_image(&Image {
        x: l,
        y: t,
        width: w,
        height: h,
        rgba,
    });
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
        enable_server_pointer: false,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        compression_type: None,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

fn connect(
    config: &connector::Config,
    p: &ConnectParams,
    kerberos: Option<KerberosConfig>,
    rx: &Receiver<ToWorker>,
    clip_tx: mpsc::Sender<clip::ClipEvent>,
) -> anyhow::Result<(ConnectionResult, Framed)> {
    let addr = (p.host.as_str(), p.port)
        .to_socket_addrs()
        .with_context(|| format!("nie można rozwiązać adresu {}", p.host))?
        .next()
        .context("brak adresu hosta")?;
    let tcp =
        TcpStream::connect_timeout(&addr, Duration::from_secs(10)).context("połączenie TCP")?;
    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    let client_addr = tcp.local_addr()?;
    let mut framed = ironrdp_blocking::Framed::new(tcp);
    // Kanał dynamiczny Display Control pozwala zmieniać rozmiar pulpitu bez ponownego łączenia.
    let mut connector = connector::ClientConnector::new(config.clone(), client_addr)
        .with_static_channel(
            DrdynvcClient::new()
                .with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new()))),
        )
        .with_static_channel(Cliprdr::<Client>::new(Box::new(clip::ClipBackend {
            tx: clip_tx,
            tmp: std::env::temp_dir().to_string_lossy().into_owned(),
        })));
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
fn tls_upgrade(
    stream: TcpStream,
    host: &str,
    rx: &Receiver<ToWorker>,
) -> anyhow::Result<(Tls, Vec<u8>)> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    // CredSSP nie wspiera wznawiania sesji TLS.
    config.resumption = rustls::client::Resumption::disabled();
    let client = rustls::ClientConnection::new(Arc::new(config), host.to_owned().try_into()?)?;
    let mut tls = rustls::StreamOwned::new(client, stream);
    tls.flush()?;
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

/// Weryfikację zastępuje decyzja użytkownika o odcisku (patrz `tls_upgrade`).
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
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
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_rectangles_are_merged() {
        let mut d = Dirty::default();
        assert!(d.0.is_none());
        d.add(10, 20, 30, 40);
        d.add(5, 25, 28, 90);
        assert_eq!(d.0, Some((5, 20, 30, 90)));
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
}
