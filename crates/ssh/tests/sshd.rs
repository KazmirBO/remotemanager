//! Testy integracyjne na prawdziwym `sshd` i `ssh-agent` uruchomionych w katalogu tymczasowym.
//! Polecenia w powłoce są zgodne z bash i fish (powłoka logowania użytkownika bywa różna).
//! Gdy `sshd`, `ssh-keygen`, `ssh-agent` lub `ssh-add` nie są dostępne, testy kończą się bez błędu.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssh::{Auth, Error, Hop, HostKeyInfo, HostKeyVerifier, Session, ShellEvent};

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
    key: &Path,
    g: &mut Guard,
    keygen: &Path,
    add: &Path,
    agent: &Path,
) -> PathBuf {
    let _ = keygen;
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
            .arg(key)
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
    let key = |n: &str| {
        let p = dir.join(n);
        run(Command::new(&keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&p));
        p
    };
    let (host, good, bad) = (key("host"), key("good"), key("bad"));
    let authorized = dir.join("authorized_keys");
    std::fs::copy(dir.join("good.pub"), &authorized).unwrap();

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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?,
    );
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let good_agent = start_agent(&dir, "good", &good, &mut guard, &keygen, &add, &agent);
    let bad_agent = start_agent(&dir, "bad", &bad, &mut guard, &keygen, &add, &agent);
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

fn hop(env: &Env, auth: Auth) -> Hop {
    Hop {
        host: "127.0.0.1".into(),
        port: env.port,
        username: env.user.clone(),
        auth,
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
        &[hop(&env, Auth::AgentSocket(env.good_agent.clone()))],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session.open_shell(100, 30).await.unwrap();
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
        &[hop(&env, Auth::AgentSocket(env.good_agent.clone()))],
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
        &[hop(&env, Auth::AgentSocket(env.bad_agent.clone()))],
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
        &[hop(&env, Auth::AgentSocket(env.dir.join("nie-ma.sock")))],
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
    let session = Session::connect(&[hop(&env, a.clone()), hop(&env, a)], verifier)
        .await
        .unwrap();
    let (shell, mut rx) = session.open_shell(80, 24).await.unwrap();
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
        auth: Auth::Agent,
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
        &[hop(&env, Auth::AgentSocket(env.good_agent.clone()))],
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
        &[hop(&env, Auth::AgentSocket(sock))],
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
        &[hop(&env, Auth::AgentSocket(env.good_agent.clone()))],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session.open_shell(100, 30).await.unwrap();
    let out = env.dir.join("order.out");
    shell
        .write(
            format!(
                "echo gotowe-$USER; stty raw -echo; cat > {}\n",
                out.display()
            )
            .into_bytes(),
        )
        .unwrap();
    read_until(&mut rx, &format!("gotowe-{}", env.user)).await;
    // Odbiornik musi być drenowany, inaczej zdarzenia zapchają pętlę odczytu.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tokio::time::sleep(Duration::from_millis(300)).await;

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
        &[hop(&env, Auth::AgentSocket(env.good_agent.clone()))],
        verifier,
    )
    .await
    .unwrap();
    let (shell, mut rx) = session.open_shell(100, 30).await.unwrap();
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
