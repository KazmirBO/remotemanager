//! Sesje SSH: uwierzytelnianie (klucz prywatny, agent, hasło), bastiony (ProxyJump przez `direct-tcpip`),
//! weryfikacja klucza hosta przez wstrzyknięty callback, powłoka z PTY.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{AgentAuthError, ChannelMsg, Disconnect, SendError, Signer};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

mod keys;
pub use keys::{KeyError, KeyInfo, MAX_KEY_TEXT, SecretKey, import_key, parse_key, read_key_file};

/// Limit prób uwierzytelniania na jeden przystanek (sshd domyślnie rozłącza po 6).
pub const MAX_AUTH_ATTEMPTS: usize = 5;

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
    #[error("agent SSH nie odpowiedział (przekroczono czas oczekiwania na potwierdzenie)")]
    AgentTimeout,
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
    /// Klucz prywatny (odszyfrowany przed `Session::connect`, więc hasło klucza nie liczy się do
    /// limitu czasu).
    Key {
        key: SecretKey,
        origin: KeyOrigin,
    },
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Agent => f.write_str("Auth::Agent"),
            Auth::AgentSocket(p) => write!(f, "Auth::AgentSocket({})", p.display()),
            Auth::Password(_) => f.write_str("Auth::Password(***)"),
            Auth::Key { origin, .. } => write!(f, "Auth::Key({origin:?}, ***)"),
        }
    }
}

impl Auth {
    fn is_agent(&self) -> bool {
        matches!(self, Auth::Agent | Auth::AgentSocket(_))
    }
}

/// Skąd pochodzi klucz `Auth::Key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Z pliku hostów.
    Stored,
    /// Ze ścieżki dokładnie tak, jak podał ją użytkownik (do dziennika).
    File(String),
}

/// Jeden przystanek łańcucha (bastion albo cel).
#[derive(Debug, Clone)]
pub struct Hop {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Metody w kolejności prób.
    pub methods: Vec<Auth>,
    /// Dopuszcza starsze algorytmy dla serwerów, które nie znają nowych (patrz `legacy_preferred`).
    pub legacy: bool,
}

/// Metoda, która zadziałała na danym przystanku.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthUsed {
    StoredKey(KeyInfo),
    KeyFile { path: String, info: KeyInfo },
    Agent(KeyInfo),
    Password,
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

/// Typ terminala zgłaszany serwerowi (zmienna `TERM`), gdy host nie ustawia własnego.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// Czy nazwa typu terminala jest poprawna: od 1 do 64 znaków ASCII z liter, cyfr oraz `-`, `_`,
/// `.` i `+` (tak wyglądają nazwy w bazie terminfo, np. `vt100`, `aixterm`, `xterm-256color`).
pub fn valid_term(term: &str) -> bool {
    (1..=64).contains(&term.len())
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

/// Algorytmy dla starych serwerów (np. AIX ze starym OpenSSH): zestaw domyślny, a po nim wymiana
/// kluczy oparta na SHA-1, szyfry CBC i `hmac-sha1`. Starsze są na końcu listy, więc serwer, który
/// zna nowe, nadal je wybierze. Te algorytmy są słabsze, dlatego wymagają włączenia dla hosta.
fn legacy_preferred() -> russh::Preferred {
    let default = russh::Preferred::DEFAULT;
    let mut kex = default.kex.to_vec();
    kex.extend([
        russh::kex::DH_G14_SHA1,
        russh::kex::DH_GEX_SHA1,
        russh::kex::DH_G1_SHA1,
    ]);
    let mut cipher = default.cipher.to_vec();
    cipher.extend([
        russh::cipher::AES_256_CBC,
        russh::cipher::AES_192_CBC,
        russh::cipher::AES_128_CBC,
    ]);
    let mut mac = default.mac.to_vec();
    mac.extend([russh::mac::HMAC_SHA1_ETM, russh::mac::HMAC_SHA1]);
    russh::Preferred {
        kex: kex.into(),
        cipher: cipher.into(),
        mac: mac.into(),
        ..default
    }
}

fn config(legacy: bool) -> Arc<client::Config> {
    Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        preferred: if legacy {
            legacy_preferred()
        } else {
            russh::Preferred::DEFAULT
        },
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

/// Najdłuższe czekanie na odpowiedź agenta, która może wymagać działania użytkownika: odblokowania
/// agenta, potwierdzenia użycia klucza (`ssh-add -c`, 1Password, KeePassXC) albo dotknięcia klucza
/// sprzętowego.
pub const AGENT_USER_TIMEOUT: Duration = Duration::from_secs(120);

/// Czeka na odpowiedź agenta, która może wymagać działania użytkownika. Na ten czas ustawia `asking`,
/// więc nie liczy się on do limitu łączenia (tak samo jak pytanie o zaufanie do klucza hosta);
/// osobny limit `AGENT_USER_TIMEOUT` chroni przed agentem, który nie odpowiada wcale.
async fn agent_reply<F: Future>(asking: &AtomicBool, f: F) -> Option<F::Output> {
    asking.store(true, Ordering::Relaxed);
    let out = tokio::time::timeout(AGENT_USER_TIMEOUT, f).await.ok();
    asking.store(false, Ordering::Relaxed);
    out
}

#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error(transparent)]
    Agent(#[from] AgentAuthError),
    #[error(transparent)]
    Send(#[from] SendError),
    #[error("agent SSH nie odpowiedział")]
    Timeout,
}

/// Podpisywanie przez agenta z wstrzymaniem limitu łączenia na czas podpisu (patrz `agent_reply`).
struct UserSigner<'a> {
    agent: &'a mut DynAgent,
    asking: &'a AtomicBool,
}

impl Signer for UserSigner<'_> {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, SignError> {
        let signing = self.agent.auth_sign(key, hash_alg, to_sign);
        match agent_reply(self.asking, signing).await {
            Some(signed) => Ok(signed?),
            None => Err(SignError::Timeout),
        }
    }
}

/// Algorytm skrótu dla kluczy RSA, ustalany najwyżej raz na przystanek (czeka do 1 s na
/// `server-sig-algs`).
async fn rsa_hash<H: client::Handler>(
    handle: &Handle<H>,
    cache: &mut Option<Option<HashAlg>>,
    legacy: bool,
) -> Result<Option<HashAlg>> {
    if let Some(h) = cache {
        return Ok(*h);
    }
    let h = match handle.best_supported_rsa_hash().await? {
        // Serwer ogłosił rsa-sha2-*.
        Some(Some(h)) => Some(h),
        // Serwer zna tylko ssh-rsa.
        Some(None) => None,
        // Brak server-sig-algs: rsa-sha2-512, bo OpenSSH >= 8.8 odrzuca ssh-rsa. Stary serwer
        // (tryb starszych algorytmów) tego rozszerzenia nie ma i zna tylko ssh-rsa.
        None if legacy => None,
        None => Some(HashAlg::Sha512),
    };
    *cache = Some(h);
    Ok(h)
}

/// Stan prób na jednym przystanku.
struct Attempts {
    /// Zużyte próby (każdy podpis kluczem i każde hasło).
    used: usize,
    rsa: Option<Option<HashAlg>>,
    /// Przystanek w trybie starszych algorytmów.
    legacy: bool,
}

/// Próbuje kluczy agenta, najwyżej `budget` razy. `Ok(None)`: żaden klucz nie zadziałał.
async fn try_agent<H: client::Handler>(
    handle: &mut Handle<H>,
    username: &str,
    socket: Option<&std::path::Path>,
    asking: &AtomicBool,
    budget: usize,
    att: &mut Attempts,
) -> Result<Option<KeyInfo>> {
    let mut agent = agent(socket).await?;
    // Zablokowany agent może przy liście kluczy poprosić użytkownika o odblokowanie.
    let ids = agent_reply(asking, agent.request_identities())
        .await
        .ok_or(Error::AgentTimeout)?
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
    let mut signer = UserSigner {
        agent: &mut agent,
        asking,
    };
    for key in keys.into_iter().take(budget) {
        let hash = if key.algorithm().is_rsa() {
            rsa_hash(handle, &mut att.rsa, att.legacy).await?
        } else {
            None
        };
        let info = KeyInfo::of_public(&key);
        att.used += 1;
        let res = handle
            .authenticate_publickey_with(username.to_owned(), key, hash, &mut signer)
            .await
            .map_err(|e| match e {
                SignError::Timeout => Error::AgentTimeout,
                other => Error::Protocol(other.to_string()),
            })?;
        if res.success() {
            return Ok(Some(info));
        }
    }
    Ok(None)
}

/// Próbuje metod przystanku po kolei, najwyżej `MAX_AUTH_ATTEMPTS` prób. Agentowi zostawia się
/// po jednej próbie na każdą późniejszą metodę, żeby agent z wieloma kluczami nie wyczerpał
/// limitu przed kluczem albo hasłem. Niedostępny agent (albo agent bez kluczy) jest pomijany,
/// gdy na liście jest inna metoda; jako jedyna metoda zgłasza swój błąd.
async fn authenticate<H: client::Handler>(
    handle: &mut Handle<H>,
    hop: &Hop,
    asking: &AtomicBool,
) -> Result<AuthUsed> {
    if hop.methods.is_empty() {
        return Err(Error::Protocol("brak metod uwierzytelniania".into()));
    }
    let mut att = Attempts {
        used: 0,
        rsa: None,
        legacy: hop.legacy,
    };
    let mut skipped: Option<Error> = None;
    for (i, method) in hop.methods.iter().enumerate() {
        if att.used >= MAX_AUTH_ATTEMPTS {
            break;
        }
        match method {
            Auth::Password(p) => {
                att.used += 1;
                if handle
                    .authenticate_password(hop.username.clone(), p.as_str())
                    .await?
                    .success()
                {
                    return Ok(AuthUsed::Password);
                }
            }
            Auth::Key { key, origin } => {
                let hash = if key.0.algorithm().is_rsa() {
                    rsa_hash(handle, &mut att.rsa, att.legacy).await?
                } else {
                    None
                };
                att.used += 1;
                let signed = PrivateKeyWithHashAlg::new(key.0.clone(), hash);
                if handle
                    .authenticate_publickey(hop.username.clone(), signed)
                    .await?
                    .success()
                {
                    let info = key.info();
                    return Ok(match origin {
                        KeyOrigin::Stored => AuthUsed::StoredKey(info),
                        KeyOrigin::File(path) => AuthUsed::KeyFile {
                            path: path.clone(),
                            info,
                        },
                    });
                }
            }
            Auth::Agent | Auth::AgentSocket(_) => {
                let later = hop.methods[i + 1..]
                    .iter()
                    .filter(|m| !m.is_agent())
                    .count();
                let budget = MAX_AUTH_ATTEMPTS
                    .saturating_sub(att.used)
                    .saturating_sub(later);
                if budget == 0 {
                    continue;
                }
                let socket = match method {
                    Auth::AgentSocket(p) => Some(p.as_path()),
                    _ => None,
                };
                match try_agent(handle, &hop.username, socket, asking, budget, &mut att).await {
                    Ok(Some(info)) => return Ok(AuthUsed::Agent(info)),
                    Ok(None) => {}
                    Err(e @ (Error::AgentUnavailable(_) | Error::NoIdentities))
                        if hop.methods.len() > 1 =>
                    {
                        skipped = Some(e);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    // Żadna próba się nie odbyła, bo jedyne metody to niedostępni agenci: ich błąd jest
    // czytelniejszy niż ogólne "uwierzytelnianie nie powiodło się".
    match skipped {
        Some(e) if att.used == 0 && hop.methods.iter().all(Auth::is_agent) => Err(e),
        _ => Err(Error::AuthFailed),
    }
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
    auth_used: Vec<AuthUsed>,
}

/// Polecenie dla pisarza powłoki. Dane i zmiana rozmiaru idą jedną kolejką, więc rozmiar nie
/// wyprzedza danych wysłanych przed nim.
enum ShellCmd {
    Write(Vec<u8>),
    Resize(u32, u32),
}

/// Uchwyt do wysyłania danych i zmiany rozmiaru okna. `write` i `resize` tylko wstawiają polecenie
/// do kolejki (kolejność wywołań = kolejność w kanale); wysyła je jedno zadanie pisarza,
/// które kończy się po upuszczeniu wszystkich uchwytów, po błędzie zapisu albo po zamknięciu kanału.
#[derive(Clone)]
pub struct ShellHandle {
    writer: Arc<russh::ChannelWriteHalf<client::Msg>>,
    queue: mpsc::UnboundedSender<ShellCmd>,
    /// Przyczyna przerwania pisarza; po jej ustawieniu kolejne zapisy zwracają błąd.
    failed: Arc<std::sync::OnceLock<String>>,
    /// Sygnał końca dla pisarza (zamknięcie powłoki albo koniec kanału); budzi także pisarza
    /// zablokowanego na zerowym oknie kanału, który sam by nie wrócił.
    stop: Arc<tokio::sync::Notify>,
}

impl ShellHandle {
    fn enqueue(&self, cmd: ShellCmd) -> Result<()> {
        if let Some(why) = self.failed.get() {
            return Err(Error::Protocol(why.clone()));
        }
        self.queue
            .send(cmd)
            .map_err(|_| Error::Protocol("kanał powłoki jest zamknięty".into()))
    }

    /// Kolejkuje bajty do wysłania; nie czeka na sieć. Błąd oznacza, że kanał jest już martwy.
    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        self.enqueue(ShellCmd::Write(data))
    }

    pub fn resize(&self, cols: u32, rows: u32) -> Result<()> {
        self.enqueue(ShellCmd::Resize(cols, rows))
    }

    pub async fn close(&self) -> Result<()> {
        let _ = self.failed.set("kanał powłoki jest zamknięty".to_string());
        // `notify_one` zapamiętuje sygnał, więc pisarz zobaczy go także, gdy jeszcze nie czeka.
        self.stop.notify_one();
        self.writer.close().await.map_err(Into::into)
    }
}

/// Zadanie pisarza: wysyła polecenia z kolejki po kolei, aż do błędu albo końca kolejki.
async fn run_writer(
    writer: Arc<russh::ChannelWriteHalf<client::Msg>>,
    mut queue: mpsc::UnboundedReceiver<ShellCmd>,
    failed: Arc<std::sync::OnceLock<String>>,
    stop: Arc<tokio::sync::Notify>,
) {
    while let Some(cmd) = queue.recv().await {
        if failed.get().is_some() {
            return;
        }
        let send = async {
            match cmd {
                ShellCmd::Write(data) => writer.data_bytes(data).await,
                ShellCmd::Resize(cols, rows) => writer.window_change(cols, rows, 0, 0).await,
            }
        };
        let res = tokio::select! {
            biased;
            _ = stop.notified() => return,
            res = send => res,
        };
        if let Err(e) = res {
            let _ = failed.set(format!("zapis do powłoki nie powiódł się: {e}"));
            return;
        }
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
        let mut auth_used = Vec::new();
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
                        client::connect(config(hop.legacy), (hop.host.as_str(), hop.port), handler)
                            .await,
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
                        Ok(
                            client::connect_stream(config(hop.legacy), ch.into_stream(), handler)
                                .await,
                        )
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
            let used = within(authenticate(&mut handle, hop, &asking), limit, &asking)
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
            auth_used.push(used);
            handles.push(handle);
        }
        if handles.is_empty() {
            return Err(Error::Protocol("pusta lista przystanków".into()));
        }
        Ok(Self { handles, auth_used })
    }

    /// Metoda uwierzytelniania, która zadziałała: po jednym wpisie na przystanek, w kolejności
    /// `hops`.
    pub fn auth_used(&self) -> &[AuthUsed] {
        &self.auth_used
    }

    /// Otwiera powłokę z PTY typu `term` (nazwa niepoprawna według `valid_term` jest zastępowana
    /// przez `DEFAULT_TERM`). Zdarzenia płyną kanałem; kanał zamyka się po zakończeniu sesji.
    pub async fn open_shell(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(ShellHandle, mpsc::Receiver<ShellEvent>)> {
        let target = self.handles.last().expect("co najmniej jeden przystanek");
        let channel = target.channel_open_session().await?;
        let term = if valid_term(term) { term } else { DEFAULT_TERM };
        channel
            .request_pty(true, term, cols, rows, 0, 0, &[])
            .await?;
        channel.request_shell(true).await?;
        let (mut reader, writer) = channel.split();
        let (tx, rx) = mpsc::channel(256);
        let failed = Arc::new(std::sync::OnceLock::new());
        let closed = failed.clone();
        let stop = Arc::new(tokio::sync::Notify::new());
        let reader_stop = stop.clone();
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
                    break;
                }
            }
            // Kanał zamknięty (przez serwer albo lokalnie): dalsze zapisy mają zwracać błąd.
            let _ = closed.set("kanał powłoki jest zamknięty".to_string());
            reader_stop.notify_one();
            let _ = tx.send(ShellEvent::Closed).await;
        });
        let writer = Arc::new(writer);
        let (queue, queue_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_writer(
            writer.clone(),
            queue_rx,
            failed.clone(),
            stop.clone(),
        ));
        Ok((
            ShellHandle {
                writer,
                queue,
                failed,
                stop,
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
