//! Test integracyjny na lokalnym serwerze `freerdp-shadow-cli` z NLA (NTLM).
//! Wymaga zbudowanego procesu (`cargo build --manifest-path tools/rdp/Cargo.toml`), `freerdp-shadow-cli`,
//! `openssl` z providerem legacy (MD4) i wyświetlacza X11. Bez nich test kończy się bez błędu.
//! Serwer udostępnia tylko prostokąt 200x200 px, a obrazy zostają w pamięci testu.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rdp::{ConnectParams, Event, FromWorker, RdpClient, ToWorker};
use tokio::sync::mpsc::{Receiver, channel};

struct Server {
    child: Child,
    port: u16,
    dir: PathBuf,
    password: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let log = std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default();
            let tail: Vec<&str> = log.lines().rev().take(12).collect();
            eprintln!(
                "--- log serwera (koniec) ---\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|d| Path::new(d).join(bin))
        .find(|p| p.is_file())
}

fn worker() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/rdp/target/debug/rdp-worker");
    p.is_file().then_some(p)
}

fn start_server() -> Option<Server> {
    let shadow = which("freerdp-shadow-cli")?;
    which("openssl")?;
    std::env::var_os("DISPLAY")?;
    // Testy działają równolegle w jednym procesie, więc katalog musi być unikalny dla każdego serwera.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("mrm-rdp-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let shadow_dir = dir.join("cfg/freerdp/shadow");
    std::fs::create_dir_all(&shadow_dir).ok()?;

    let ok = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
        ])
        .arg(shadow_dir.join("shadow.key"))
        .arg("-out")
        .arg(shadow_dir.join("shadow.crt"))
        .stderr(Stdio::null())
        .status()
        .ok()?
        .success();
    if !ok {
        return None;
    }
    // Hasło jednorazowe z /dev/urandom; skrót NT liczy openssl (MD4 z providera legacy).
    let mut raw = [0u8; 9];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").ok()?, &mut raw).ok()?;
    let password: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut md4 = Command::new("openssl")
        .args([
            "dgst",
            "-md4",
            "-provider",
            "legacy",
            "-provider",
            "default",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    std::io::Write::write_all(md4.stdin.as_mut()?, &utf16).ok()?;
    drop(md4.stdin.take());
    let out = md4.wait_with_output().ok()?;
    let hash = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .last()?
        .to_owned();
    if hash.len() != 32 {
        return None;
    }
    let sam = dir.join("SAM");
    std::fs::write(
        &sam,
        format!("tester:WORKGROUP:{}:{hash}:::\n", "0".repeat(32)),
    )
    .ok()?;

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .ok()?
        .local_addr()
        .ok()?
        .port();
    let child = Command::new(shadow)
        .env("XDG_CONFIG_HOME", dir.join("cfg"))
        .arg(format!("/port:{port}"))
        .arg("/bind-address:127.0.0.1")
        .arg(format!("/sam-file:{}", sam.display()))
        .arg("/rect:0,0,200,200")
        .arg("/log-level:INFO")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("server.log")).ok()?)
        .spawn()
        .ok()?;
    let server = Server {
        child,
        port,
        dir,
        password,
    };
    for _ in 0..60 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn params(s: &Server, password: &str) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port: s.port,
        username: "tester".into(),
        domain: Some("WORKGROUP".into()),
        password: password.into(),
        kerberos: false,
        kdc: None,
        width: 200,
        height: 200,
    }
}

async fn next(rx: &mut Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("limit czasu")
        .expect("kanał zamknięty")
}

#[tokio::test]
async fn nla_login_delivers_frames_and_accepts_input() {
    let (Some(worker), Some(server)) = (worker(), start_server()) else {
        return eprintln!(
            "pominięto: brak procesu rdp-worker, freerdp-shadow-cli, openssl albo DISPLAY"
        );
    };
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    let client = RdpClient::spawn(&worker, params(&server, &server.password), tx).unwrap();

    let Event::Worker(FromWorker::Cert { fingerprint, .. }) = next(&mut rx).await else {
        panic!("oczekiwano Cert")
    };
    assert_eq!(
        fingerprint.split(':').count(),
        32,
        "SHA-256 w hex z dwukropkami: {fingerprint}"
    );
    client.send(&ToWorker::Trust { accept: true }).unwrap();

    let mut connected = false;
    let mut pixels = 0usize;
    while !(connected && pixels > 0) {
        match next(&mut rx).await {
            Event::Worker(FromWorker::Connected { width, height }) => {
                assert!(width > 0 && height > 0);
                connected = true;
            }
            Event::Worker(FromWorker::Error { message }) => panic!("błąd procesu: {message}"),
            Event::Image(img) => pixels += img.rgba.len(),
            Event::Worker(_) | Event::Clip { .. } => {}
        }
    }
    client.send(&ToWorker::MouseMove { x: 10, y: 10 }).unwrap();
    client
        .send(&ToWorker::Key {
            scancode: 0x2a,
            extended: false,
            down: true,
        })
        .unwrap();
    client
        .send(&ToWorker::Key {
            scancode: 0x2a,
            extended: false,
            down: false,
        })
        .unwrap();
    // Prośba o zmianę rozmiaru nie może zepsuć sesji, nawet gdy serwer nie obsługuje Display Control.
    client
        .send(&ToWorker::Resize {
            width: 320,
            height: 240,
        })
        .unwrap();
    client.send(&ToWorker::Close).unwrap();
    loop {
        match next(&mut rx).await {
            Event::Worker(FromWorker::Closed { .. }) => break,
            Event::Worker(FromWorker::Error { message }) => {
                panic!("błąd przy zamykaniu: {message}")
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn wrong_password_is_reported_as_error() {
    let (Some(worker), Some(server)) = (worker(), start_server()) else {
        return eprintln!(
            "pominięto: brak procesu rdp-worker, freerdp-shadow-cli, openssl albo DISPLAY"
        );
    };
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    let client = RdpClient::spawn(&worker, params(&server, "zle-haslo"), tx).unwrap();
    assert!(matches!(
        next(&mut rx).await,
        Event::Worker(FromWorker::Cert { .. })
    ));
    client.send(&ToWorker::Trust { accept: true }).unwrap();
    loop {
        match next(&mut rx).await {
            Event::Worker(FromWorker::Error { message }) => {
                assert!(
                    message.contains("NLA") || message.contains("uwierzytel"),
                    "{message}"
                );
                assert!(
                    !message.contains("zle-haslo"),
                    "komunikat nie może zawierać hasła"
                );
                break;
            }
            Event::Worker(FromWorker::Connected { .. }) => panic!("zalogowano złym hasłem"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn rejected_certificate_stops_before_credentials() {
    let (Some(worker), Some(server)) = (worker(), start_server()) else {
        return eprintln!(
            "pominięto: brak procesu rdp-worker, freerdp-shadow-cli, openssl albo DISPLAY"
        );
    };
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    let client = RdpClient::spawn(&worker, params(&server, &server.password), tx).unwrap();
    assert!(matches!(
        next(&mut rx).await,
        Event::Worker(FromWorker::Cert { .. })
    ));
    client.send(&ToWorker::Trust { accept: false }).unwrap();
    let Event::Worker(FromWorker::Error { message }) = next(&mut rx).await else {
        panic!("oczekiwano Error")
    };
    assert!(message.contains("odrzucony"), "{message}");
}

#[tokio::test]
async fn resize_request_is_answered_and_never_silent() {
    let (Some(worker), Some(server)) = (worker(), start_server()) else {
        return eprintln!(
            "pominięto: brak procesu rdp-worker, freerdp-shadow-cli, openssl albo DISPLAY"
        );
    };
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    let client = RdpClient::spawn(&worker, params(&server, &server.password), tx).unwrap();
    assert!(matches!(
        next(&mut rx).await,
        Event::Worker(FromWorker::Cert { .. })
    ));
    client.send(&ToWorker::Trust { accept: true }).unwrap();
    loop {
        match next(&mut rx).await {
            Event::Worker(FromWorker::Connected { .. }) => break,
            Event::Worker(FromWorker::Error { message }) => panic!("błąd procesu: {message}"),
            _ => {}
        }
    }
    client
        .send(&ToWorker::Resize {
            width: 320,
            height: 240,
        })
        .unwrap();
    // Serwer albo zmienia rozdzielczość (`Resized`), albo proces zgłasza, że serwer tego nie
    // obsługuje (`Notice`). Cisza zostawiałaby użytkownika bez wyjaśnienia.
    let answer = loop {
        match next(&mut rx).await {
            Event::Worker(FromWorker::Resized { width, height }) => {
                break format!("serwer zmienił rozdzielczość na {width}x{height}");
            }
            Event::Worker(FromWorker::Notice { message }) => {
                assert!(message.contains("rozdzielczości"), "{message}");
                break message;
            }
            // Wpisy diagnostyczne procesu (np. etapy inicjalizacji schowka) są tylko wypisywane.
            Event::Worker(FromWorker::Log { message }) => eprintln!("dziennik: {message}"),
            Event::Worker(FromWorker::Error { message }) => panic!("błąd procesu: {message}"),
            _ => {}
        }
    };
    eprintln!("odpowiedź na prośbę o zmianę rozdzielczości: {answer}");
    client.close();
}
