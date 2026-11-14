//! Sesje SSH: uwierzytelnianie (agent albo hasło), bastiony (ProxyJump przez `direct-tcpip`),
//! weryfikacja klucza hosta przez wstrzyknięty callback, powłoka z PTY.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nie można połączyć z {0}")]
    Connect(String),
    #[error("agent SSH jest niedostępny: {0}")]
    AgentUnavailable(String),
    #[error("agent SSH nie ma żadnych kluczy")]
    NoIdentities,
    #[error("uwierzytelnianie nie powiodło się")]
    AuthFailed,
    #[error("klucz hosta {0} został odrzucony")]
    HostKeyRejected(String),
    #[error("błąd protokołu SSH: {0}")]
    Protocol(String),
    #[error("{0} nie odpowiada (przekroczono czas oczekiwania)")]
    Timeout(String),
}

impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Self {
        Error::Protocol(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub enum Auth {
    /// Agent z `SSH_AUTH_SOCK` (Unix) albo domyślny agent systemu (Windows).
    Agent,
    /// Agent pod wskazaną ścieżką gniazda (Unix) albo potoku nazwanego (Windows).
    AgentSocket(std::path::PathBuf),
    Password(Arc<Zeroizing<String>>),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Agent => f.write_str("Auth::Agent"),
            Auth::AgentSocket(p) => write!(f, "Auth::AgentSocket({})", p.display()),
            Auth::Password(_) => f.write_str("Auth::Password(***)"),
        }
    }
}

/// Jeden przystanek łańcucha (bastion albo cel).
#[derive(Debug, Clone)]
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: Auth,
}

/// Informacje o kluczu hosta pokazywane przy decyzji o zaufaniu.
#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// Odcisk w formacie `SHA256:...`.
    pub fingerprint: String,
}

/// Decyzja o zaufaniu kluczowi: `true` = kontynuuj.
pub type HostKeyVerifier =
    Arc<dyn Fn(HostKeyInfo) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

struct Client {
    host: String,
    port: u16,
    verifier: HostKeyVerifier,
    rejected: Option<oneshot::Sender<()>>,
    /// Ustawiane na czas pytania użytkownika o zaufanie: ten czas nie liczy się do limitu łączenia.
    asking: Arc<AtomicBool>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let pk = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.key_data(),
            PublicKeyOrCertificate::Certificate(c) => c.public_key(),
        };
        let info = HostKeyInfo {
            host: self.host.clone(),
            port: self.port,
            algorithm: pk.algorithm().to_string(),
            fingerprint: pk.fingerprint(HashAlg::Sha256).to_string(),
        };
        self.asking.store(true, Ordering::Relaxed);
        let ok = (self.verifier)(info).await;
        self.asking.store(false, Ordering::Relaxed);
        if !ok && let Some(tx) = self.rejected.take() {
            let _ = tx.send(());
        }
        Ok(ok)
    }
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    })
}

type DynAgent = AgentClient<Box<dyn russh::keys::agent::client::AgentStream + Send + Unpin>>;

async fn agent(socket: Option<&std::path::Path>) -> Result<DynAgent> {
    #[cfg(unix)]
    let a = match socket {
        Some(path) => AgentClient::connect_uds(path).await.map(|a| a.dynamic()),
        None => AgentClient::connect_env().await.map(|a| a.dynamic()),
    };
    #[cfg(windows)]
    let a = match socket {
        Some(path) => AgentClient::connect_named_pipe(path)
            .await
            .map(|a| a.dynamic()),
        None => match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            Ok(a) => Ok(a.dynamic()),
            Err(_) => AgentClient::connect_pageant().await.map(|a| a.dynamic()),
        },
    };
    a.map_err(|e| Error::AgentUnavailable(e.to_string()))
}

async fn authenticate<H: client::Handler>(handle: &mut Handle<H>, hop: &Hop) -> Result<()> {
    let ok = match &hop.auth {
        Auth::Password(p) => handle
            .authenticate_password(hop.username.clone(), p.as_str())
            .await?
            .success(),
        Auth::Agent | Auth::AgentSocket(_) => {
            let socket = match &hop.auth {
                Auth::AgentSocket(p) => Some(p.as_path()),
                _ => None,
            };
            let mut agent = agent(socket).await?;
            let ids = agent
                .request_identities()
                .await
                .map_err(|e| Error::AgentUnavailable(e.to_string()))?;
            let keys: Vec<_> = ids
                .into_iter()
                .filter_map(|i| match i {
                    AgentIdentity::PublicKey { key, .. } => Some(key),
                    AgentIdentity::Certificate { .. } => None,
                })
                .collect();
            if keys.is_empty() {
                return Err(Error::NoIdentities);
            }
            let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
            let mut success = false;
            for key in keys {
                let hash = if key.algorithm().is_rsa() {
                    rsa_hash
                } else {
                    None
                };
                let res = handle
                    .authenticate_publickey_with(hop.username.clone(), key, hash, &mut agent)
                    .await
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                if res.success() {
                    success = true;
                    break;
                }
            }
            success
        }
    };
    if ok { Ok(()) } else { Err(Error::AuthFailed) }
}

/// Zdarzenia z powłoki.
#[derive(Debug)]
pub enum ShellEvent {
    Data(Vec<u8>),
    Exit(u32),
    Closed,
}

/// Połączona sesja. Trzyma uchwyty wszystkich przystanków, żeby tunel żył razem z nią.
pub struct Session {
    handles: Vec<Handle<Client>>,
}

/// Uchwyt do wysyłania danych i zmiany rozmiaru okna.
#[derive(Clone)]
pub struct ShellHandle {
    writer: Arc<russh::ChannelWriteHalf<client::Msg>>,
}

impl ShellHandle {
    pub async fn write(&self, data: Vec<u8>) -> Result<()> {
        self.writer.data_bytes(data).await.map_err(Into::into)
    }

    pub async fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.writer
            .window_change(cols, rows, 0, 0)
            .await
            .map_err(Into::into)
    }

    pub async fn close(&self) -> Result<()> {
        self.writer.close().await.map_err(Into::into)
    }
}

/// Domyślny limit czasu na połączenie i uwierzytelnienie jednego przystanku.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Czeka na `f`, ale najwyżej `limit` czasu, w którym `paused` było fałszywe (czas pytania
/// użytkownika o zaufanie nie jest liczony). `None` oznacza przekroczenie limitu.
async fn within<F: Future>(f: F, limit: Duration, paused: &AtomicBool) -> Option<F::Output> {
    const TICK: Duration = Duration::from_millis(250);
    tokio::pin!(f);
    let mut waited = Duration::ZERO;
    loop {
        tokio::select! {
            out = &mut f => return Some(out),
            _ = tokio::time::sleep(TICK) => {
                if !paused.load(Ordering::Relaxed) {
                    waited += TICK;
                    if waited >= limit {
                        return None;
                    }
                }
            }
        }
    }
}

impl Session {
    /// Łączy przez kolejne przystanki; ostatni element `hops` to cel.
    pub async fn connect(hops: &[Hop], verifier: HostKeyVerifier) -> Result<Self> {
        Self::connect_with_timeout(hops, verifier, CONNECT_TIMEOUT).await
    }

    /// Jak `connect`, z własnym limitem czasu na przystanek. Serwer, który przyjmuje połączenie TCP
    /// i milczy, kończy się błędem `Timeout` zamiast wiecznego "Łączenie...".
    pub async fn connect_with_timeout(
        hops: &[Hop],
        verifier: HostKeyVerifier,
        limit: Duration,
    ) -> Result<Self> {
        let mut handles: Vec<Handle<Client>> = Vec::new();
        for (i, hop) in hops.iter().enumerate() {
            let (rej_tx, rej_rx) = oneshot::channel();
            let asking = Arc::new(AtomicBool::new(false));
            let handler = Client {
                host: hop.host.clone(),
                port: hop.port,
                verifier: verifier.clone(),
                rejected: Some(rej_tx),
                asking: asking.clone(),
            };
            let target = format!("{}:{}", hop.host, hop.port);
            let connecting = async {
                match handles.last() {
                    None => Ok::<_, Error>(
                        client::connect(config(), (hop.host.as_str(), hop.port), handler).await,
                    ),
                    Some(prev) => {
                        let ch = prev
                            .channel_open_direct_tcpip(
                                hop.host.clone(),
                                hop.port as u32,
                                "127.0.0.1",
                                0,
                            )
                            .await
                            .map_err(|_| Error::Connect(target.clone()))?;
                        Ok(client::connect_stream(config(), ch.into_stream(), handler).await)
                    }
                }
            };
            let connected = within(connecting, limit, &asking)
                .await
                .ok_or_else(|| Error::Timeout(target.clone()))??;
            let mut handle = match connected {
                Ok(h) => h,
                Err(e) => {
                    return Err(if rej_rx.await.is_ok() {
                        Error::HostKeyRejected(target)
                    } else if matches!(e, russh::Error::IO(_)) {
                        Error::Connect(target)
                    } else {
                        e.into()
                    });
                }
            };
            within(authenticate(&mut handle, hop), limit, &asking)
                .await
                .unwrap_or_else(|| Err(Error::Timeout(target.clone())))
                .map_err(|e| {
                    // Dla czytelności błędu przy bastionie.
                    if i + 1 < hops.len() {
                        Error::Protocol(format!("bastion {}: {e}", hop.host))
                    } else {
                        e
                    }
                })?;
            handles.push(handle);
        }
        if handles.is_empty() {
            return Err(Error::Protocol("pusta lista przystanków".into()));
        }
        Ok(Self { handles })
    }

    /// Otwiera powłokę z PTY. Zdarzenia płyną kanałem; kanał zamyka się po zakończeniu sesji.
    pub async fn open_shell(
        &self,
        cols: u32,
        rows: u32,
    ) -> Result<(ShellHandle, mpsc::Receiver<ShellEvent>)> {
        let target = self.handles.last().expect("co najmniej jeden przystanek");
        let channel = target.channel_open_session().await?;
        channel
            .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await?;
        channel.request_shell(true).await?;
        let (mut reader, writer) = channel.split();
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(msg) = reader.wait().await {
                let ev = match msg {
                    ChannelMsg::Data { data } => ShellEvent::Data(data.to_vec()),
                    ChannelMsg::ExtendedData { data, .. } => ShellEvent::Data(data.to_vec()),
                    ChannelMsg::ExitStatus { exit_status } => ShellEvent::Exit(exit_status),
                    ChannelMsg::Close => break,
                    _ => continue,
                };
                if tx.send(ev).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(ShellEvent::Closed).await;
        });
        Ok((
            ShellHandle {
                writer: Arc::new(writer),
            },
            rx,
        ))
    }

    pub async fn disconnect(&self) {
        for h in self.handles.iter().rev() {
            let _ = h.disconnect(Disconnect::ByApplication, "", "pl").await;
        }
    }
}
