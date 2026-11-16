//! Powitanie procesu RDP: proces bez zgodnej wersji protokołu (np. stara kopia binarki obok
//! aplikacji) ma dać czytelny błąd, a nie sesję, która po cichu pomija nowsze polecenia.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use rdp::{ConnectParams, Event, FromWorker, RdpClient};
use tokio::sync::mpsc::channel;

/// Atrapa procesu: skrypt, który wypisuje przygotowaną ramkę i czeka.
fn fake_worker(name: &str, first: &FromWorker) -> PathBuf {
    let mut frame = Vec::new();
    rdp_proto::write_json(&mut frame, first).unwrap();
    fake_worker_bytes(name, &frame)
}

/// Atrapa procesu wypisująca dokładnie podane bajty (także uszkodzone ramki).
fn fake_worker_bytes(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mrm-hello-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ramka"), bytes).unwrap();
    let script = dir.join("rdp-worker");
    std::fs::write(
        &script,
        "#!/bin/sh\ncat \"$(dirname \"$0\")/ramka\"\nsleep 5\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn params() -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port: 3389,
        username: "u".into(),
        domain: None,
        password: "p".into(),
        kerberos: false,
        kdc: None,
        width: 800,
        height: 600,
    }
}

async fn first_event(worker: PathBuf) -> Event {
    let (tx, mut rx) = channel(rdp::EVENT_QUEUE);
    // Świeżo zapisany skrypt bywa chwilowo "zajęty" (ETXTBSY), gdy inny test równolegle forkuje
    // proces z jeszcze otwartym deskryptorem zapisu; wtedy ponawiamy.
    let mut attempts = 0;
    let client = loop {
        match RdpClient::spawn(&worker, params(), tx.clone()) {
            Ok(c) => break c,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 50 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("nie udało się uruchomić atrapy: {e}"),
        }
    };
    drop(tx);
    let ev = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("brak zdarzenia")
        .expect("kanał zamknięty");
    client.close();
    ev
}

#[tokio::test]
async fn worker_without_greeting_is_rejected_with_a_clear_error() {
    // Tak zaczynał stary proces: od certyfikatu, bez powitania.
    let worker = fake_worker(
        "stary",
        &FromWorker::Cert {
            fingerprint: "aa".into(),
            subject: String::new(),
        },
    );
    let Event::Worker(FromWorker::Error { message }) = first_event(worker.clone()).await else {
        panic!("oczekiwano błędu wersji")
    };
    assert!(message.contains("innej wersji"), "{message}");
    assert!(message.contains(&worker.display().to_string()), "{message}");
}

#[tokio::test]
async fn worker_with_other_protocol_version_is_rejected() {
    let worker = fake_worker(
        "inna-wersja",
        &FromWorker::Hello {
            protocol: rdp_proto::PROTOCOL + 1,
        },
    );
    let Event::Worker(FromWorker::Error { message }) = first_event(worker).await else {
        panic!("oczekiwano błędu wersji")
    };
    assert!(message.contains("innej wersji"), "{message}");
}

/// Poprawne powitanie jako bajty ramki.
fn hello_frame() -> Vec<u8> {
    let mut frame = Vec::new();
    rdp_proto::write_json(
        &mut frame,
        &FromWorker::Hello {
            protocol: rdp_proto::PROTOCOL,
        },
    )
    .unwrap();
    frame
}

/// Surowa ramka: `u32 długość | rodzaj | treść` (długość obejmuje bajt rodzaju).
fn raw_frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(body.len() + 1)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    f.push(kind);
    f.extend_from_slice(body);
    f
}

/// Po uszkodzonej ramce sesja kończy się czytelnym błędem (a nie zawieszeniem ani paniką wątku
/// czytającego). Atrapa żyje dalej (`sleep`), więc klient musi sam zabić proces po krótkiej zwłoce.
async fn assert_corrupt_frame_ends_session(name: &str, corrupt: &[u8]) {
    let mut bytes = hello_frame();
    bytes.extend_from_slice(corrupt);
    let Event::Worker(FromWorker::Error { message }) =
        first_event(fake_worker_bytes(name, &bytes)).await
    else {
        panic!("oczekiwano błędu po uszkodzonej ramce")
    };
    assert!(
        message.contains("zakończył się nieoczekiwanie"),
        "{message}"
    );
}

#[tokio::test]
async fn unknown_frame_kind_after_greeting_ends_the_session_with_an_error() {
    assert_corrupt_frame_ends_session("rodzaj", &raw_frame(99, b"cokolwiek")).await;
}

#[tokio::test]
async fn invalid_frame_length_after_greeting_ends_the_session_with_an_error() {
    // Długość zero jest niepoprawna.
    assert_corrupt_frame_ends_session("dlugosc0", &0u32.to_le_bytes()).await;
}

#[tokio::test]
async fn truncated_image_frame_after_greeting_ends_the_session_with_an_error() {
    // Rodzaj obrazu (2) z nagłówkiem krótszym niż 8 bajtów.
    assert_corrupt_frame_ends_session("obraz", &raw_frame(2, &[1, 2, 3])).await;
}

#[tokio::test]
async fn unknown_control_message_is_skipped_and_the_session_goes_on() {
    // Nieznany wariant JSON po powitaniu jest pomijany (nowszy proces mógłby go wysyłać), a
    // kolejna poprawna wiadomość dociera bez zakłóceń.
    let mut bytes = hello_frame();
    bytes.extend(raw_frame(1, br#"{"t":"wariant_z_przyszlosci","x":1}"#));
    bytes.extend(raw_frame(1, b"to nie jest json"));
    rdp_proto::write_json(
        &mut bytes,
        &FromWorker::Notice {
            message: "dalej".into(),
        },
    )
    .unwrap();
    let Event::Worker(FromWorker::Notice { message }) =
        first_event(fake_worker_bytes("nieznany", &bytes)).await
    else {
        panic!("oczekiwano wiadomości po pominiętych")
    };
    assert_eq!(message, "dalej");
}
