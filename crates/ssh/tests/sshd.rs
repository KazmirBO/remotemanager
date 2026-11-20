//! Testy integracyjne na prawdziwym `sshd` i `ssh-agent` uruchomionych w katalogu tymczasowym.
//! Polecenia w powłoce są zgodne z bash i fish (powłoka logowania użytkownika bywa różna).
//! Gdy `sshd`, `ssh-keygen`, `ssh-agent` lub `ssh-add` nie są dostępne, testy kończą się bez błędu.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssh::{
    Auth, AuthUsed, Error, Hop, HostKeyInfo, HostKeyVerifier, KeyInfo, KeyOrigin, SecretKey,
    Session, ShellEvent,
};

/// Hasło zaszyfrowanych kluczy testowych.
const KEY_PASS: &str = "haslo-klucza";

fn find(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|d| Path::new(d).join(bin))
        .find(|p| p.is_file())
}

struct Guard(Vec<Child>);
impl Drop for Guard {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Env {
    _guard: Guard,
    dir: PathBuf,
    port: u16,
    user: String,
    /// Agent z kluczem dopisanym do `authorized_keys`.
    good_agent: PathBuf,
    /// Agent z kluczem, którego serwer nie zna.
    bad_agent: PathBuf,
    /// Agent z sześcioma kluczami, których serwer nie zna (`bad1..bad6`).
    many_bad_agent: PathBuf,
}

/// Katalog z kluczami prywatnymi znika także wtedy, gdy test spanikuje.
impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    /// Ścieżka klucza wygenerowanego w `setup`.
    fn key_path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Klucz z pliku, jak przy ścieżce podanej przez użytkownika.
    fn file_key(&self, name: &str, pass: Option<&str>) -> Auth {
        let path = self.key_path(name);
        let text = ssh::read_key_file(&path).unwrap();
        Auth::Key {
            key: ssh::parse_key(&text, pass).unwrap_or_else(|e| panic!("{name}: {e}")),
            origin: KeyOrigin::File(path.display().to_string()),
        }
    }

    /// Klucz zaimportowany do pliku hostów (odszyfrowany tekst OpenSSH).
    fn stored_key(&self, name: &str) -> (Auth, KeyInfo) {
        let text = ssh::read_key_file(&self.key_path(name)).unwrap();
        let (openssh, info) = ssh::import_key(&text, None).unwrap();
        let key: SecretKey = ssh::parse_key(&openssh, None).unwrap();
        (
            Auth::Key {
                key,
                origin: KeyOrigin::Stored,
            },
            info,
        )
    }

    /// Odcisk klucza według `ssh-keygen -lf`.
    fn fingerprint(&self, name: &str) -> String {
        let out = Command::new(find("ssh-keygen").unwrap())
            .arg("-lf")
            .arg(self.dir.join(format!("{name}.pub")))
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    }
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("uruchomienie polecenia");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn start_agent(
    dir: &Path,
    name: &str,
    keys: &[PathBuf],
    g: &mut Guard,
    add: &Path,
    agent: &Path,
) -> PathBuf {
    let sock = dir.join(format!("{name}.sock"));
    g.0.push(
        Command::new(agent)
            .args(["-D", "-a"])
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Gniazdo pojawia się, zanim agent zacznie nasłuchiwać, więc ssh-add ponawiamy.
    let mut added = false;
    for _ in 0..50 {
        let st = Command::new(add)
            .args(keys)
            .env("SSH_AUTH_SOCK", &sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if st.is_ok_and(|s| s.success()) {
            added = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(added, "ssh-add nie powiódł się");
    sock
}

fn setup() -> Option<Env> {
    setup_with(&[])
}

/// Jak `setup`, z dodatkowymi opcjami `-o` dla sshd (np. `MaxAuthTries=6`).
fn setup_with(sshd_options: &[&str]) -> Option<Env> {
    let (sshd, keygen, agent, add) = (
        find("sshd")?,
        find("ssh-keygen")?,
        find("ssh-agent")?,
        find("ssh-add")?,
    );
    let dir = std::env::temp_dir().join(format!(
        "mrm-ssh-test-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key_with = |n: &str, args: &[&str]| {
        let p = dir.join(n);
        run(Command::new(&keygen).arg("-q").args(args).arg("-f").arg(&p));
        p
    };
    let key = |n: &str| key_with(n, &["-t", "ed25519", "-N", ""]);
    let (host, good, bad) = (key("host"), key("good"), key("bad"));
    key_with("rsa", &["-t", "rsa", "-b", "2048", "-N", ""]);
    key_with(
        "rsa_pem",
        &["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", ""],
    );
    key_with(
        "rsa_pem_enc",
        &["-t", "rsa", "-b", "2048", "-m", "PEM", "-N", KEY_PASS],
    );
    key_with(
        "ecdsa_p8",
        &["-t", "ecdsa", "-b", "256", "-m", "PKCS8", "-N", ""],
    );
    key_with(
        "ecdsa_p8_enc",
        &["-t", "ecdsa", "-b", "256", "-m", "PKCS8", "-N", KEY_PASS],
    );
    key_with("enc", &["-t", "ed25519", "-N", KEY_PASS]);
    let bads: Vec<PathBuf> = (1..=6).map(|i| key(&format!("bad{i}"))).collect();
    let authorized = dir.join("authorized_keys");
    let mut lines = String::new();
    for n in [
        "good",
        "rsa",
        "rsa_pem",
        "rsa_pem_enc",
        "ecdsa_p8",
        "ecdsa_p8_enc",
        "enc",
    ] {
        lines.push_str(
            std::fs::read_to_string(dir.join(format!("{n}.pub")))
                .ok()?
                .trim(),
        );
        lines.push('\n');
    }
    std::fs::write(&authorized, lines).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut guard = Guard(Vec::new());
    guard.0.push(
        Command::new(&sshd)
            .arg("-D")
            .args(["-f", "/dev/null", "-p"])
            .arg(port.to_string())
            .arg("-h")
            .arg(&host)
            .args([
                "-o",
                "ListenAddress=127.0.0.1",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "UsePAM=no",
            ])
            .args([
                "-o",
                "StrictModes=no",
                "-o",
                "PidFile=none",
                "-o",
                "AllowTcpForwarding=yes",
            ])
            .arg("-o")
            .arg(format!("AuthorizedKeysFile={}", authorized.display()))
            .args(sshd_options.iter().flat_map(|o| ["-o", o]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?,
    );
    let mut ready = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "sshd nie wystartował na porcie {port}");
    let good_agent = start_agent(&dir, "good", &[good], &mut guard, &add, &agent);
    let bad_agent = start_agent(&dir, "bad", &[bad], &mut guard, &add, &agent);
    let many_bad_agent = start_agent(&dir, "many_bad", &bads, &mut guard, &add, &agent);
    let user = String::from_utf8(Command::new("id").arg("-un").output().ok()?.stdout)
        .ok()?
        .trim()
        .to_owned();
    Some(Env {
        _guard: guard,
        dir,
        port,
        user,
        good_agent,
        bad_agent,
        many_bad_agent,
    })
}

/// Unikalny przyrostek katalogu: testy działają równolegle w jednym procesie, a zegar bywa za gruby.
fn rand_suffix() -> usize {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn accept_all() -> (HostKeyVerifier, Arc<Mutex<Vec<HostKeyInfo>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let v: HostKeyVerifier = Arc::new(move |info| {
        s2.lock().unwrap().push(info);
        Box::pin(async { true })
    });
    (v, seen)
}

fn hop(env: &Env, methods: Vec<Auth>) -> Hop {
    Hop {
        host: "127.0.0.1".into(),
        port: env.port,
        username: env.user.clone(),
        methods,
        legacy: false,
        keepalive: Some(ssh::DEFAULT_KEEPALIVE),
    }
}

async fn read_until(rx: &mut tokio::sync::mpsc::Receiver<ShellEvent>, needle: &str) -> String {
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !buf.contains(needle) {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "brak \"{needle}\" w ...{:?}",
                    &buf[buf.len().saturating_sub(300)..]
                )
            });
        match ev {
            Some(ShellEvent::Data(d)) => buf.push_str(&String::from_utf8_lossy(&d)),
            Some(_) => {}
            None => panic!("kanał zamknięty, dotychczas: {buf:?}"),
        }
    }
    buf
}

#[tokio::test]
async fn agent_auth_shell_roundtrip_and_fingerprint() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, seen) = accept_all();
    let session = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session
        .open_shell(ssh::DEFAULT_TERM, 100, 30)
        .await
        .unwrap();
    shell.write(b"echo hello-$USER\n".to_vec()).unwrap();
    read_until(&mut rx, &format!("hello-{}", env.user)).await;
    shell.resize(120, 40).unwrap();
    shell.write(b"stty size\n".to_vec()).unwrap();
    read_until(&mut rx, "40 120").await;
    shell.write(b"exit\n".to_vec()).unwrap();
    let mut closed = false;
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
        if matches!(ev, ShellEvent::Closed) {
            closed = true;
            break;
        }
    }
    assert!(closed, "po exit oczekiwano zdarzenia Closed");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].host, "127.0.0.1");
    assert_eq!(seen[0].algorithm, "ssh-ed25519");
    assert!(
        seen[0].fingerprint.starts_with("SHA256:"),
        "{}",
        seen[0].fingerprint
    );
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn rejected_host_key_is_reported() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let verifier: HostKeyVerifier = Arc::new(|_| Box::pin(async { false }));
    let err = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, Error::HostKeyRejected(_)), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn unknown_key_fails_authentication() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let err = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.bad_agent.clone())])],
        verifier,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, Error::AuthFailed), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn missing_agent_is_reported() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let err = Session::connect(
        &[hop(
            &env,
            vec![Auth::AgentSocket(env.dir.join("nie-ma.sock"))],
        )],
        verifier,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, Error::AgentUnavailable(_)), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn proxy_jump_through_bastion() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, seen) = accept_all();
    let a = Auth::AgentSocket(env.good_agent.clone());
    // Bastion i cel to ten sam sshd: drugi przystanek idzie kanałem direct-tcpip przez pierwszy.
    let session = Session::connect(&[hop(&env, vec![a.clone()]), hop(&env, vec![a])], verifier)
        .await
        .unwrap();
    let (shell, mut rx) = session.open_shell(ssh::DEFAULT_TERM, 80, 24).await.unwrap();
    shell.write(b"echo via-$USER\n".to_vec()).unwrap();
    read_until(&mut rx, &format!("via-{}", env.user)).await;
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "klucz każdego przystanku jest weryfikowany"
    );
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Serwer, który przyjmuje TCP i nic nie wysyła, nie może zawiesić łączenia na zawsze.
#[tokio::test]
async fn silent_server_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let keep = tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            open.push(sock);
        }
    });
    let (verifier, _) = accept_all();
    let hop = Hop {
        host: "127.0.0.1".into(),
        port,
        username: "ktos".into(),
        methods: vec![Auth::Agent],
        legacy: false,
        keepalive: Some(ssh::DEFAULT_KEEPALIVE),
    };
    let started = std::time::Instant::now();
    let err = Session::connect_with_timeout(&[hop], verifier, Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    keep.abort();
}

/// Czas pytania o zaufanie nie liczy się do limitu łączenia.
#[tokio::test]
async fn slow_trust_decision_does_not_time_out() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let verifier: HostKeyVerifier = Arc::new(|_| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            true
        })
    });
    let session = Session::connect_with_timeout(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

async fn read_agent_msg(s: &mut tokio::net::UnixStream) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).await.ok()?;
    Some(body)
}

async fn write_agent_msg(s: &mut tokio::net::UnixStream, body: &[u8]) -> Option<()> {
    use tokio::io::AsyncWriteExt;
    s.write_all(&(body.len() as u32).to_be_bytes()).await.ok()?;
    s.write_all(body).await.ok()
}

/// Pośrednik przed prawdziwym agentem, który opóźnia podpis, tak jak agent czekający na
/// potwierdzenie użytkownika albo dotknięcie klucza sprzętowego.
fn slow_agent(real: &Path, dir: &Path, delay: Duration) -> PathBuf {
    /// SSH_AGENTC_SIGN_REQUEST z protokołu agenta.
    const SIGN_REQUEST: u8 = 13;
    let sock = dir.join("wolny.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let real = real.to_owned();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let real = real.clone();
            tokio::spawn(async move {
                let Ok(mut agent) = tokio::net::UnixStream::connect(&real).await else {
                    return;
                };
                while let Some(req) = read_agent_msg(&mut client).await {
                    if req.first() == Some(&SIGN_REQUEST) {
                        tokio::time::sleep(delay).await;
                    }
                    if write_agent_msg(&mut agent, &req).await.is_none() {
                        break;
                    }
                    let Some(resp) = read_agent_msg(&mut agent).await else {
                        break;
                    };
                    if write_agent_msg(&mut client, &resp).await.is_none() {
                        break;
                    }
                }
            });
        }
    });
    sock
}

#[tokio::test]
async fn slow_agent_approval_does_not_time_out() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    // Podpis trwa dłużej niż limit łączenia: czas czekania na agenta nie może się do niego liczyć.
    let sock = slow_agent(&env.good_agent, &env.dir, Duration::from_secs(3));
    let (verifier, _) = accept_all();
    let session = Session::connect_with_timeout(
        &[hop(&env, vec![Auth::AgentSocket(sock)])],
        verifier,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Wiele wywołań `write` (i `resize`) wykonanych po kolei z jednego zadania, bez czekania na sieć,
/// z dużym blokiem pośrodku, musi dotrzeć do zdalnej powłoki w kolejności wywołań i bez przeplotu
/// bloku z krótkimi zapisami. To test kontraktu kolejki w warstwie `ssh`. Kolejność samych
/// wywołań od strony aplikacji zapewnia synchroniczna komenda Tauri (`ssh_write`), czego ten test
/// nie obejmuje.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writes_keep_call_order_without_interleaving() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let session = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session
        .open_shell(ssh::DEFAULT_TERM, 100, 30)
        .await
        .unwrap();
    let out = env.dir.join("order.out");
    shell
        .write(
            format!(
                "stty raw -echo; echo gotowe-$USER; cat > {}\n",
                out.display()
            )
            .into_bytes(),
        )
        .unwrap();
    read_until(&mut rx, &format!("gotowe-{}", env.user)).await;
    // Odbiornik musi być drenowany, inaczej zdarzenia zapchają pętlę odczytu.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });

    let mut expected = Vec::new();
    let mut push = |chunk: Vec<u8>| {
        expected.extend_from_slice(&chunk);
        shell.write(chunk).unwrap();
    };
    // Same znaki drukowalne bez 0x04 i 0x03, żeby tryb raw niczego nie interpretował.
    for i in 0..2000 {
        push(format!("<{i:05}>").into_bytes());
    }
    push((0..600 * 1024).map(|i| b'a' + (i % 26) as u8).collect());
    for i in 0..50 {
        push(format!("[{i:05}]").into_bytes());
    }
    shell.resize(120, 40).unwrap();
    push(b"koniec".to_vec());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let len = std::fs::metadata(&out)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        if len >= expected.len() || tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got.len(), expected.len(), "długość wyjścia");
    assert!(
        got == expected,
        "bajty w innej kolejności albo przeplecione"
    );
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Po zamknięciu kanału zapisy zwracają błąd, a nie znikają po cichu.
#[tokio::test]
async fn write_after_shell_closed_reports_error() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let session = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session
        .open_shell(ssh::DEFAULT_TERM, 100, 30)
        .await
        .unwrap();
    shell.write(b"exit\n".to_vec()).unwrap();
    while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
        if matches!(ev, ShellEvent::Closed) {
            break;
        }
    }
    // Pisarz może zauważyć zamknięcie dopiero przy próbie zapisu, więc kilka prób.
    let mut failed = false;
    for _ in 0..50 {
        if shell.write(b"x".to_vec()).is_err() {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(failed, "zapis po zamknięciu powłoki powinien zwrócić błąd");
    assert!(shell.resize(80, 24).is_err());
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Łączy się z jednym przystankiem i zwraca metodę, która zadziałała.
async fn connect_one(env: &Env, methods: Vec<Auth>) -> Result<AuthUsed, Error> {
    let (verifier, _) = accept_all();
    let session = Session::connect(&[hop(env, methods)], verifier).await?;
    let used = session.auth_used().to_vec();
    session.disconnect().await;
    assert_eq!(used.len(), 1);
    Ok(used.into_iter().next().unwrap())
}

#[tokio::test]
async fn stored_key_auth_shell_roundtrip() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (auth, info) = env.stored_key("good");
    assert_eq!(info.fingerprint, env.fingerprint("good"));
    let (verifier, _) = accept_all();
    let session = Session::connect(&[hop(&env, vec![auth])], verifier)
        .await
        .unwrap();
    assert_eq!(session.auth_used(), &[AuthUsed::StoredKey(info)]);
    let (shell, mut rx) = session.open_shell(ssh::DEFAULT_TERM, 80, 24).await.unwrap();
    shell.write(b"echo klucz-$USER\n".to_vec()).unwrap();
    read_until(&mut rx, &format!("klucz-{}", env.user)).await;
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn key_formats_authenticate() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    for (name, pass, algorithm) in [
        ("good", None, "ssh-ed25519"),
        ("rsa", None, "ssh-rsa"),
        ("rsa_pem", None, "ssh-rsa"),
        ("ecdsa_p8", None, "ecdsa-sha2-nistp256"),
        ("enc", Some(KEY_PASS), "ssh-ed25519"),
        ("rsa_pem_enc", Some(KEY_PASS), "ssh-rsa"),
        ("ecdsa_p8_enc", Some(KEY_PASS), "ecdsa-sha2-nistp256"),
    ] {
        let used = connect_one(&env, vec![env.file_key(name, pass)])
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            used,
            AuthUsed::KeyFile {
                path: env.key_path(name).display().to_string(),
                info: KeyInfo {
                    algorithm: algorithm.into(),
                    fingerprint: env.fingerprint(name),
                },
            },
            "{name}"
        );
    }
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Serwer bez `ssh-rsa` (SHA-1) przyjmuje klucz RSA podpisany rsa-sha2-*.
#[tokio::test]
async fn rsa_key_uses_sha2() {
    let Some(env) = setup_with(&["PubkeyAcceptedAlgorithms=rsa-sha2-256,rsa-sha2-512,ssh-ed25519"])
    else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let used = connect_one(&env, vec![env.file_key("rsa", None)])
        .await
        .unwrap();
    assert!(matches!(used, AuthUsed::KeyFile { .. }), "{used:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn unknown_key_fails_authentication_with_key() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let err = connect_one(&env, vec![env.file_key("bad1", None)])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn unavailable_agent_is_skipped_when_key_follows() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (key, info) = env.stored_key("good");
    let used = connect_one(
        &env,
        vec![Auth::AgentSocket(env.dir.join("nie-ma.sock")), key],
    )
    .await
    .unwrap();
    assert_eq!(used, AuthUsed::StoredKey(info));
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn agent_after_rejected_key() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let used = connect_one(
        &env,
        vec![
            env.file_key("bad1", None),
            Auth::AgentSocket(env.good_agent.clone()),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        used,
        AuthUsed::Agent(KeyInfo {
            algorithm: "ssh-ed25519".into(),
            fingerprint: env.fingerprint("good"),
        })
    );
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Agent z sześcioma złymi kluczami nie może zużyć wszystkich prób przed kluczem z pliku:
/// bez rezerwy sshd (MaxAuthTries 6) rozłączyłby się przed jego próbą.
#[tokio::test]
async fn attempt_budget_leaves_room_for_later_methods() {
    let Some(env) = setup_with(&["MaxAuthTries=6"]) else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (key, info) = env.stored_key("good");
    let used = connect_one(
        &env,
        vec![Auth::AgentSocket(env.many_bad_agent.clone()), key],
    )
    .await
    .unwrap();
    assert_eq!(used, AuthUsed::StoredKey(info));
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Limit prób kończy się czytelnym `AuthFailed`, zanim serwer rozłączy się po szóstej nieudanej
/// próbie. Siedem złych kluczy w dwóch agentach: bez limitu sshd zerwałby połączenie.
#[tokio::test]
async fn attempts_never_exceed_limit() {
    let Some(env) = setup_with(&["MaxAuthTries=6"]) else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let err = connect_one(
        &env,
        vec![
            Auth::AgentSocket(env.many_bad_agent.clone()),
            Auth::AgentSocket(env.bad_agent.clone()),
        ],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::AuthFailed), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn empty_methods_are_rejected() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let err = connect_one(&env, vec![]).await.unwrap_err();
    assert!(matches!(err, Error::Protocol(_)), "{err:?}");
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn proxy_jump_with_key_on_bastion() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let (key, info) = env.stored_key("good");
    let session = Session::connect(
        &[
            hop(&env, vec![key]),
            hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())]),
        ],
        verifier,
    )
    .await
    .unwrap();
    let used = session.auth_used();
    assert_eq!(used.len(), 2);
    assert_eq!(used[0], AuthUsed::StoredKey(info.clone()));
    assert_eq!(used[1], AuthUsed::Agent(info));
    let (shell, mut rx) = session.open_shell(ssh::DEFAULT_TERM, 80, 24).await.unwrap();
    shell.write(b"echo przez-$USER\n".to_vec()).unwrap();
    read_until(&mut rx, &format!("przez-{}", env.user)).await;
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

/// Typ terminala wybrany dla hosta trafia do serwera jako `TERM`; nazwa niepoprawna jest
/// zastępowana domyślną.
#[tokio::test]
async fn terminal_type_reaches_the_server() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    for (asked, expected) in [("vt100", "vt100"), ("zły typ;", ssh::DEFAULT_TERM)] {
        let (verifier, _) = accept_all();
        let session = Session::connect(
            &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
            verifier,
        )
        .await
        .unwrap();
        let (shell, mut rx) = session.open_shell(asked, 80, 24).await.unwrap();
        shell.write(b"echo term=[$TERM]\n".to_vec()).unwrap();
        read_until(&mut rx, &format!("term=[{expected}]")).await;
        shell.close().await.unwrap();
        session.disconnect().await;
    }
}

/// Serwer, który zna tylko stare algorytmy (wymiana kluczy z SHA-1, szyfr CBC, `hmac-sha1`),
/// odrzuca połączenie w trybie domyślnym, a przyjmuje je po włączeniu starszych algorytmów.
/// Tryb starszych algorytmów nie przeszkadza w połączeniu z nowoczesnym serwerem.
#[tokio::test]
async fn legacy_server_needs_legacy_algorithms() {
    let Some(old) = setup_with(&[
        "KexAlgorithms=diffie-hellman-group14-sha1",
        "Ciphers=aes128-cbc",
        "MACs=hmac-sha1",
    ]) else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let methods = || vec![Auth::AgentSocket(old.good_agent.clone())];

    let (verifier, _) = accept_all();
    let modern_only = Session::connect(&[hop(&old, methods())], verifier).await;
    assert!(modern_only.is_err(), "stary serwer przyjął nowe algorytmy");

    let (verifier, _) = accept_all();
    let legacy_hop = Hop {
        legacy: true,
        ..hop(&old, methods())
    };
    let session = Session::connect(&[legacy_hop], verifier).await.unwrap();
    let (shell, mut rx) = session.open_shell("vt100", 80, 24).await.unwrap();
    shell.write(b"echo stary-$USER\n".to_vec()).unwrap();
    read_until(&mut rx, &format!("stary-{}", old.user)).await;
    shell.close().await.unwrap();
    session.disconnect().await;

    let Some(new) = setup() else {
        return;
    };
    let (verifier, _) = accept_all();
    let hop_new = Hop {
        legacy: true,
        ..hop(&new, vec![Auth::AgentSocket(new.good_agent.clone())])
    };
    let session = Session::connect(&[hop_new], verifier).await.unwrap();
    session.disconnect().await;
}

#[tokio::test]
async fn login_command_is_sent_after_shell_opens() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    let (verifier, _) = accept_all();
    let session = Session::connect(
        &[hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session
        .open_shell(ssh::DEFAULT_TERM, 100, 30)
        .await
        .unwrap();
    shell.send_line("echo MRM-$((40+2))").unwrap();
    read_until(&mut rx, "MRM-42").await;
    assert!(shell.send_line("ls\nrm").is_err());
    shell.close().await.unwrap();
    session.disconnect().await;
    let _ = std::fs::remove_dir_all(&env.dir);
}

#[tokio::test]
async fn keepalive_can_be_disabled_or_shortened() {
    let Some(env) = setup() else {
        return eprintln!("pominięto: brak sshd/ssh-agent");
    };
    for keepalive in [None, Some(Duration::from_secs(1))] {
        let (verifier, _) = accept_all();
        let h = Hop {
            keepalive,
            ..hop(&env, vec![Auth::AgentSocket(env.good_agent.clone())])
        };
        let session = Session::connect(&[h], verifier).await.unwrap();
        let (shell, mut rx) = session
            .open_shell(ssh::DEFAULT_TERM, 100, 30)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        shell.write(b"echo KA-$((1+1))\n".to_vec()).unwrap();
        read_until(&mut rx, "KA-2").await;
        shell.close().await.unwrap();
        session.disconnect().await;
    }
    let _ = std::fs::remove_dir_all(&env.dir);
}
