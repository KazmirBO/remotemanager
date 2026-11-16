//! Prototyp: czy IronRDP przechodzi NLA (CredSSP) na prawdziwym serwerze.
//!
//! Użycie: `RDP_PASSWORD=... rdp-probe --host dc01 -u user -d DOMENA -o /tmp/dc01.png`
//! Bez zmiennej `RDP_PASSWORD` hasło jest pobierane z ukrytego pytania. Hasło nie jest nigdzie wypisywane.
//! Walidacja certyfikatu TLS jest tu wyłączona, bo to tylko sonda; aplikacja musi pytać o zaufanie do certyfikatu.

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use clap::Parser;
use ironrdp::connector::credssp::KerberosConfig;
use ironrdp::connector::{self, ConnectionResult, Credentials};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStageBuilder, ActiveStageOutput};
use ironrdp_graphics::image_processing::PixelFormat;
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use tokio_rustls::rustls;

#[derive(Parser)]
#[command(about = "Sonda NLA dla IronRDP")]
struct Cli {
    #[arg(long)]
    host: String,
    #[arg(long, default_value_t = 3389)]
    port: u16,
    #[arg(short, long)]
    user: String,
    #[arg(short, long)]
    domain: Option<String>,
    /// Plik wyjściowy PNG z pierwszą ramką.
    #[arg(short, long, default_value = "probe.png")]
    output: PathBuf,
    /// Żądana szerokość pulpitu.
    #[arg(long, default_value_t = 1280)]
    width: u16,
    /// Żądana wysokość pulpitu.
    #[arg(long, default_value_t = 800)]
    height: u16,
    /// Włącza Kerberos (wymaga pełnej nazwy hosta, np. dc01.firma.local).
    #[arg(long)]
    kerberos: bool,
    /// Adres KDC (tcp://host:88) albo proxy KKDCP (https://...); domyślnie wykrywany przez sspi.
    #[arg(long)]
    kdc: Option<String>,
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let password = match std::env::var("RDP_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => rpassword::prompt_password(format!("Hasło dla {}: ", cli.user))?,
    };

    let started = Instant::now();
    let config = connector::Config {
        credentials: Credentials::UsernamePassword {
            username: cli.user.clone(),
            password,
        },
        domain: cli.domain.clone(),
        enable_tls: false,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: cli.width,
            height: cli.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "multiremotemanager-probe".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
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
    };

    let kerberos = if cli.kerberos {
        let client_name = hostname();
        Some(KerberosConfig::new(cli.kdc.clone(), client_name).context("konfiguracja Kerberos")?)
    } else {
        None
    };

    let (result, mut framed) =
        connect(config, &cli.host, cli.port, kerberos).context("połączenie i NLA")?;
    println!(
        "NLA OK ({}) po {} ms; pulpit {}x{}",
        if cli.kerberos {
            "Kerberos"
        } else {
            "NTLM/negocjacja"
        },
        started.elapsed().as_millis(),
        result.desktop_size.width,
        result.desktop_size.height
    );

    let mut image = DecodedImage::new(
        PixelFormat::RgbA32,
        result.desktop_size.width,
        result.desktop_size.height,
    );
    let frames = read_first_frame(result, &mut framed, &mut image).context("odbiór ramki")?;
    println!("Odebrano aktualizacji grafiki: {frames}");
    save_png(&cli.output, &image)?;
    println!(
        "Zapisano {} ({}x{})",
        cli.output.display(),
        image.width(),
        image.height()
    );
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "multiremotemanager".to_owned())
}

fn connect(
    config: connector::Config,
    host: &str,
    port: u16,
    kerberos: Option<KerberosConfig>,
) -> anyhow::Result<(ConnectionResult, ironrdp_blocking::Framed<Tls>)> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .context("nie znaleziono adresu hosta")?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).context("TCP")?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let client_addr = tcp.local_addr()?;
    let mut framed = ironrdp_blocking::Framed::new(tcp);
    let mut connector = connector::ClientConnector::new(config, client_addr);
    let should_upgrade =
        ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("faza początkowa")?;

    let (tls, server_public_key) =
        tls_upgrade(framed.into_inner_no_leftover(), host).context("TLS")?;
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_blocking::Framed::new(tls);
    let mut network = ReqwestNetworkClient;
    let result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut network,
        host.to_owned().into(),
        server_public_key,
        kerberos,
    )
    .context("CredSSP / finalizacja")?;
    Ok((result, framed))
}

fn tls_upgrade(stream: TcpStream, host: &str) -> anyhow::Result<(Tls, Vec<u8>)> {
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
    let key = public_key_of(cert)?;
    Ok((tls, key))
}

fn public_key_of(cert: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(cert)?;
    Ok(cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("klucz publiczny nie jest wyrównany do bajtów")?
        .to_owned())
}

/// Czyta PDU aż do pierwszej aktualizacji grafiki, potem jeszcze krótko, żeby zebrać pełną ramkę.
fn read_first_frame(
    result: ConnectionResult,
    framed: &mut ironrdp_blocking::Framed<Tls>,
    image: &mut DecodedImage,
) -> anyhow::Result<usize> {
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
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut updates = 0usize;
    let mut quiet_after_first = 0;
    while Instant::now() < deadline {
        let (action, payload) = match framed.read_pdu() {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if updates > 0 {
                    break;
                }
                quiet_after_first += 1;
                if quiet_after_first > 2 {
                    bail!("serwer nie wysłał grafiki w 15 s");
                }
                continue;
            }
            Err(e) => return Err(anyhow::Error::new(e).context("odczyt ramki")),
        };
        for out in stage.process(image, action, &payload)? {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => framed.write_all(&frame)?,
                ActiveStageOutput::GraphicsUpdate(_) => updates += 1,
                ActiveStageOutput::Terminate(reason) => bail!("serwer zakończył sesję: {reason:?}"),
                _ => {}
            }
        }
    }
    if updates == 0 {
        bail!("brak aktualizacji grafiki");
    }
    Ok(updates)
}

fn save_png(path: &std::path::Path, image: &DecodedImage) -> anyhow::Result<()> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, u32::from(image.width()), u32::from(image.height()));
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(image.data())?;
    Ok(())
}

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
