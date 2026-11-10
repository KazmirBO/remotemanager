//! Klient procesu `rdp-worker`: uruchamia go, tłumaczy polecenia i zdarzenia.
//!
//! IronRDP działa w osobnym procesie, bo jego zależności nie mieszczą się w jednym `Cargo.lock`
//! z `russh` (patrz PROJECT.md). Hasło trafia do procesu przez stdin, nie przez argumenty.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

pub use rdp_proto::{ClipKind, ConnectParams, FromWorker, Image, RemoteFile, ToWorker, clipfmt};

/// Nazwa pliku wykonywalnego procesu obok aplikacji.
pub const WORKER_NAME: &str = if cfg!(windows) {
    "multiremotemanager-rdp-worker.exe"
} else {
    "multiremotemanager-rdp-worker"
};

#[derive(Debug)]
pub enum Event {
    Worker(FromWorker),
    Image(Image),
    /// Dane zdalnego schowka (odpowiedź na `ClipFetch`).
    Clip {
        kind: rdp_proto::ClipKind,
        data: Vec<u8>,
    },
}

/// Szuka procesu: zmienna `MRM_RDP_WORKER`, potem katalog pliku wykonywalnego aplikacji.
pub fn find_worker() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("MRM_RDP_WORKER").map(PathBuf::from)
        && p.is_file()
    {
        return Some(p);
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let sibling = dir.join(WORKER_NAME);
    if sibling.is_file() {
        return Some(sibling);
    }
    // Tryb deweloperski: aplikacja w `target/<profil>/`, proces w osobnym workspace `tools/rdp`.
    if cfg!(debug_assertions) {
        let profile = dir.file_name()?;
        let dev = dir
            .parent()?
            .parent()?
            .join("tools/rdp/target")
            .join(profile)
            .join("rdp-worker");
        if dev.is_file() {
            return Some(dev);
        }
    }
    None
}

struct Inner {
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Child>,
}

/// Uchwyt do działającego procesu RDP. Zamknięcie ostatniego klona kończy proces.
#[derive(Clone)]
pub struct RdpClient {
    inner: Arc<Inner>,
}

impl RdpClient {
    /// Uruchamia proces i wysyła `Connect`. Zdarzenia trafiają do `events` aż do końca procesu.
    pub fn spawn(
        worker: &Path,
        params: ConnectParams,
        events: UnboundedSender<Event>,
    ) -> io::Result<Self> {
        let mut child = Command::new(worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("brak stdout procesu"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("brak stdin procesu"))?;
        let inner = Arc::new(Inner {
            stdin: Mutex::new(Some(stdin)),
            child: Mutex::new(child),
        });
        let client = Self {
            inner: inner.clone(),
        };
        client.send(&ToWorker::Connect(params))?;

        std::thread::spawn(move || {
            let mut finished = false;
            loop {
                match rdp_proto::read_message(&mut stdout) {
                    Ok(Some(rdp_proto::Message::Json(bytes))) => match rdp_proto::parse_json::<
                        FromWorker,
                    >(&bytes)
                    {
                        Ok(ev) => {
                            finished |=
                                matches!(ev, FromWorker::Closed { .. } | FromWorker::Error { .. });
                            if events.send(Event::Worker(ev)).is_err() {
                                break;
                            }
                        }
                        Err(_) => continue,
                    },
                    Ok(Some(rdp_proto::Message::Clip { kind, data })) => {
                        if events.send(Event::Clip { kind, data }).is_err() {
                            break;
                        }
                    }
                    Ok(Some(rdp_proto::Message::Image(img))) => {
                        if events.send(Event::Image(img)).is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            if !finished {
                let code = inner
                    .child
                    .lock()
                    .ok()
                    .and_then(|mut c| c.wait().ok())
                    .and_then(|s| s.code());
                let message = match code {
                    Some(c) => format!("proces RDP zakończył się nieoczekiwanie (kod {c})"),
                    None => "proces RDP zakończył się nieoczekiwanie".to_owned(),
                };
                let _ = events.send(Event::Worker(FromWorker::Error { message }));
            }
        });
        Ok(client)
    }

    pub fn send(&self, cmd: &ToWorker) -> io::Result<()> {
        let mut guard = self
            .inner
            .stdin
            .lock()
            .map_err(|_| io::Error::other("zatruta blokada"))?;
        match guard.as_mut() {
            Some(stdin) => match cmd {
                ToWorker::ClipData { kind, data } => rdp_proto::write_clip(stdin, *kind, data),
                other => rdp_proto::write_json(stdin, other),
            },
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sesja jest zamknięta",
            )),
        }
    }

    /// Prosi proces o zamknięcie, a gdyby nie zdążył, kończy go po krótkiej zwłoce.
    pub fn close(&self) {
        let _ = self.send(&ToWorker::Close);
        if let Ok(mut s) = self.inner.stdin.lock() {
            *s = None;
        }
        let inner = self.inner.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if let Ok(mut c) = inner.child.lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
        });
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
