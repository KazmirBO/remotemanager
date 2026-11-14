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
    let dir = std::env::temp_dir().join(format!("mrm-hello-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut frame = Vec::new();
    rdp_proto::write_json(&mut frame, first).unwrap();
    std::fs::write(dir.join("ramka"), frame).unwrap();
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
    let client = RdpClient::spawn(&worker, params(), tx).unwrap();
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
