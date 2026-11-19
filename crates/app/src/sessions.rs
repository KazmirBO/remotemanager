//! Sesje SSH: łączenie, strumień danych do frontendu i decyzje o zaufaniu do kluczy hostów.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use model::{Id, Protocol, TrustedKey};
use serde::Serialize;
use ssh::{Auth, AuthUsed, Hop, HostKeyInfo, HostKeyVerifier, KeyOrigin, ShellEvent};
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody, Request};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

use std::io::Write as _;

use crate::flow::{Flow, SSH_WINDOW};
use crate::session_log;
use crate::state::{AppState, Live, TrustAnswer};

#[derive(Serialize, Clone)]
struct TrustRequest {
    id: Uuid,
    protocol: Protocol,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    /// Zapamiętany wcześniej odcisk, jeśli serwer przedstawił inny: dla tego samego algorytmu sam
    /// odcisk, a dla innego algorytmu z jego nazwą (zmiana algorytmu też jest ostrzeżeniem).
    previous: Option<String>,
}

/// Pytanie o klucz hosta z połączenia, które zaczęło się przed przeładowaniem interfejsu, nie
/// może trafić do nowego interfejsu (nie ma tam karty tej sesji): sprawdzamy licznik przeładowań
/// przed pytaniem i co 200 ms w jego trakcie.
async fn ask_ssh_trust(app: AppHandle, info: HostKeyInfo, reloads: u64) -> bool {
    let state = app.state::<AppState>();
    if state.reloads.load(Ordering::SeqCst) != reloads {
        return false;
    }
    let reloaded = {
        let app = app.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if app.state::<AppState>().reloads.load(Ordering::SeqCst) != reloads {
                    return;
                }
            }
        }
    };
    ask_trust(
        app,
        Protocol::Ssh,
        info.host,
        info.port,
        info.algorithm,
        info.fingerprint,
        reloaded,
    )
    .await
}

/// Sprawdza zapamiętane zaufanie i w razie potrzeby pyta użytkownika (SSH: klucz hosta, RDP: certyfikat).
/// Zakończenie `cancel` (np. zamknięcie sesji w trakcie pytania) zamyka okno w interfejsie i odrzuca klucz.
pub async fn ask_trust(
    app: AppHandle,
    protocol: Protocol,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    cancel: impl std::future::Future<Output = ()>,
) -> bool {
    let info = TrustSubject {
        host,
        port,
        algorithm,
        fingerprint,
    };
    let state = app.state::<AppState>();
    let previous = {
        let guard = state.inner.lock().await;
        let Some(u) = guard.as_ref() else {
            return false;
        };
        let known = u.doc.trusted(protocol, &info.host, info.port);
        match previous_key(&known, &info.algorithm, &info.fingerprint) {
            None => return true,
            Some(previous) => previous,
        }
    };
    let id = Uuid::new_v4();
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.trust.lock().expect("trust").insert(id, tx);
    // Blokada pliku mogła przejść między sprawdzeniem a wstawieniem pytania do mapy (`cancel_trust`
    // jej wtedy nie widział): bez ponownej kontroli pytanie trafiłoby do zablokowanego interfejsu.
    if state.inner.lock().await.is_none() {
        state.trust.lock().expect("trust").remove(&id);
        return false;
    }
    let req = TrustRequest {
        id,
        protocol,
        host: info.host.clone(),
        port: info.port,
        algorithm: info.algorithm.clone(),
        fingerprint: info.fingerprint.clone(),
        previous,
    };
    if app.emit("trust-request", req).is_err() {
        state.trust.lock().expect("trust").remove(&id);
        return false;
    }
    let answer: Option<TrustAnswer> = tokio::select! {
        a = tokio::time::timeout(Duration::from_secs(120), rx) => a.ok().and_then(Result::ok),
        () = cancel => None,
    };
    if state.trust.lock().expect("trust").remove(&id).is_some() {
        // Nikt nie odpowiedział w czasie: interfejs zamyka okno, a połączenie się kończy.
        let _ = app.emit("trust-expired", id);
    }
    match answer {
        Some(a) if a.accept => {
            if a.remember {
                let key = TrustedKey {
                    protocol,
                    host: info.host,
                    port: info.port,
                    algorithm: info.algorithm,
                    fingerprint: info.fingerprint,
                };
                if let Err(e) = state
                    .mutate(|doc| {
                        doc.trust(key);
                        Ok(())
                    })
                    .await
                {
                    state.log(format!("nie udało się zapamiętać zaufanego klucza: {e}"));
                }
            }
            true
        }
        _ => false,
    }
}

/// `None`: klucz jest zaufany. `Some(previous)`: trzeba zapytać; `previous` to zapamiętany odcisk,
/// który się nie zgadza (dla innego algorytmu z jego nazwą), albo `None` przy pierwszym połączeniu.
fn previous_key(
    known: &[&TrustedKey],
    algorithm: &str,
    fingerprint: &str,
) -> Option<Option<String>> {
    if known
        .iter()
        .any(|k| k.algorithm == algorithm && k.fingerprint == fingerprint)
    {
        return None;
    }
    Some(
        known
            .iter()
            .find(|k| k.algorithm == algorithm)
            .map(|k| k.fingerprint.clone())
            .or_else(|| {
                known
                    .first()
                    .map(|k| format!("{} {}", k.algorithm, k.fingerprint))
            }),
    )
}

struct TrustSubject {
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
}

#[tauri::command]
pub async fn answer_trust(
    state: State<'_, AppState>,
    id: Uuid,
    accept: bool,
    remember: bool,
) -> Result<(), String> {
    let tx = state
        .trust
        .lock()
        .expect("trust")
        .remove(&id)
        .ok_or("Pytanie wygasło, a połączenie zostało przerwane. Połącz się ponownie.")?;
    let _ = tx.send(TrustAnswer { accept, remember });
    Ok(())
}

/// Dane przystanku zebrane pod blokadą dokumentu; plik klucza i jego odszyfrowanie dzieją się
/// dopiero w `build_hop`, poza blokadą.
struct HopPlan {
    name: String,
    host: String,
    port: u16,
    username: String,
    stored_key: Option<Zeroizing<String>>,
    key_path: Option<String>,
    password: Option<Zeroizing<String>>,
    /// Starsze algorytmy SSH dla tego przystanku.
    legacy: bool,
    /// Typ terminala (używany tylko dla celu).
    term: Option<String>,
    /// Polecenie po zalogowaniu (używane tylko dla celu). Nie trafia do dziennika.
    login_command: Option<String>,
}

fn plan_for(doc: &model::Document, id: Id) -> Result<HopPlan, String> {
    let host = doc.tree.host(id).ok_or("Nie ma takiego hosta")?;
    let r = doc.tree.resolve(id).map_err(|e| e.to_string())?;
    // Sekrety przenosimy z rozwiązanych pól zamiast klonować, żeby nie zostawiać kopii bez zerowania.
    let model::Fields {
        username,
        ssh_key,
        ssh_key_path,
        password,
        ssh_term,
        ssh_legacy,
        ssh_login_command,
        ..
    } = r.fields;
    let username =
        username.ok_or_else(|| format!("Host {} nie ma ustawionego użytkownika.", host.name))?;
    Ok(HopPlan {
        name: host.name.clone(),
        host: host.address.clone(),
        port: r.port,
        username,
        stored_key: ssh_key.map(|k| Zeroizing::new(k.openssh)),
        key_path: ssh_key_path,
        password: password.map(Zeroizing::new),
        legacy: ssh_legacy.unwrap_or(false),
        term: ssh_term,
        login_command: ssh_login_command,
    })
}

/// Odstęp podtrzymywania połączenia z ustawień (sekundy); 0 wyłącza.
fn keepalive(secs: u16) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs.into()))
}

/// "~/" i "~\\" (Windows) rozwija przez HOME albo USERPROFILE.
fn expand_key_path(path: &str) -> Result<std::path::PathBuf, String> {
    let rest = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\"));
    match rest {
        Some(rest) => {
            let home = std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()))
                .ok_or("Nie można ustalić katalogu domowego dla ścieżki klucza.")?;
            Ok(std::path::PathBuf::from(home).join(rest))
        }
        None => Ok(std::path::PathBuf::from(path)),
    }
}

/// Buduje listę metod w kolejności: klucz z pliku hostów, plik klucza, agent, zapisane hasło.
/// `one_time_password` dotyczy tylko celu i zastępuje wszystkie jego metody.
fn build_hop(
    plan: HopPlan,
    target: bool,
    one_time_password: Option<&str>,
    key_passphrase: Option<&str>,
    keepalive: Option<Duration>,
) -> Result<(Hop, Option<String>), String> {
    let HopPlan {
        name,
        host,
        port,
        username,
        stored_key,
        key_path,
        password,
        legacy,
        term: _,
        login_command: _,
    } = plan;
    let hop = |methods| Hop {
        host: host.clone(),
        port,
        username: username.clone(),
        methods,
        legacy,
        keepalive,
    };
    if let (true, Some(pw)) = (target, one_time_password) {
        return Ok((
            hop(vec![Auth::Password(Arc::new(Zeroizing::new(
                pw.to_owned(),
            )))]),
            None,
        ));
    }
    let mut methods = Vec::new();
    let mut skipped = None;
    if let Some(k) = stored_key {
        let key = ssh::parse_key(&k, None).map_err(|e| {
            format!("Klucz SSH zapisany dla {name} jest uszkodzony: {e}. Zaimportuj go ponownie.")
        })?;
        methods.push(Auth::Key {
            key,
            origin: KeyOrigin::Stored,
        });
    }
    // Ścieżka klucza jest zapisana w pliku hostów, a ten bywa zsynchronizowany między maszynami,
    // z których tylko część ma dany plik. Pliku, którego nie ma albo nie da się otworzyć, nie
    // traktujemy więc jak błędu: metoda jest pomijana, a notatka trafia do dziennika i do
    // komunikatu, gdy nie zadziała także żadna inna metoda.
    let key_text = match key_path {
        None => None,
        Some(p) => match ssh::read_key_file(&expand_key_path(&p)?) {
            Ok(text) => Some((p, text)),
            Err(ssh::KeyError::Unreadable(d)) => {
                skipped = Some(format!("pominięto plik klucza {p}: {d}"));
                None
            }
            Err(ssh::KeyError::TooLarge) => {
                return Err(format!("Plik klucza {p} jest za duży (limit 64 KiB)."));
            }
            Err(other) => return Err(format!("Plik klucza {p}: {other}")),
        },
    };
    if let Some((p, text)) = key_text {
        let pass = if target {
            key_passphrase.filter(|s| !s.is_empty())
        } else {
            None
        };
        let key = ssh::parse_key(&text, pass).map_err(|e| match (e, target) {
            (ssh::KeyError::NeedsPassphrase, true) => {
                format!("NEEDS_KEY_PASSPHRASE:Klucz {p} jest zaszyfrowany. Podaj jego hasło.")
            }
            (ssh::KeyError::WrongPassphrase, true) => {
                format!("NEEDS_KEY_PASSPHRASE:Nieprawidłowe hasło klucza {p}. Spróbuj ponownie.")
            }
            (ssh::KeyError::NeedsPassphrase | ssh::KeyError::WrongPassphrase, false) => format!(
                "Klucz {p} bastionu {name} jest zaszyfrowany. Zaimportuj go do pliku z hostami albo użyj agenta SSH."
            ),
            (ssh::KeyError::Invalid(d), _) => {
                format!("Plik {p} nie zawiera obsługiwanego klucza prywatnego: {d}")
            }
            (ssh::KeyError::TooLarge, _) => format!("Plik klucza {p} jest za duży (limit 64 KiB)."),
            (ssh::KeyError::Unreadable(d), _) => {
                format!("Nie można odczytać pliku klucza {p}: {d}")
            }
        })?;
        methods.push(Auth::Key {
            key,
            origin: KeyOrigin::File(p),
        });
    }
    methods.push(Auth::Agent);
    if let Some(pw) = password {
        methods.push(Auth::Password(Arc::new(pw)));
    }
    Ok((hop(methods), skipped))
}

/// Komunikat dla połączenia przerwanego blokadą pliku albo przeładowaniem interfejsu.
pub fn interrupted_message(locked: bool) -> &'static str {
    if locked {
        "Plik z hostami został zablokowany w trakcie łączenia."
    } else {
        "Interfejs został przeładowany w trakcie łączenia."
    }
}

fn control(json: &str) -> InvokeResponseBody {
    InvokeResponseBody::Json(json.to_owned())
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn connect_ssh(
    app: AppHandle,
    state: State<'_, AppState>,
    host_id: Id,
    cols: u32,
    rows: u32,
    password: Option<String>,
    key_passphrase: Option<String>,
    on_event: Channel<InvokeResponseBody>,
) -> Result<Uuid, String> {
    // Licznik przeładowań musi być odczytany przed pierwszym `await`, inaczej przeładowanie
    // w czasie czekania na blokadę dokumentu uszłoby uwadze kontroli po wstawieniu sesji.
    let reloads = state.reloads.load(Ordering::SeqCst);
    let (plans, host_name, keepalive_secs, settings_term) = state
        .read(|doc| {
            let host = doc.tree.host(host_id).ok_or("Nie ma takiego hosta")?;
            if host.protocol != Protocol::Ssh {
                return Err("Ten host nie używa SSH.".to_string());
            }
            let name = host.name.clone();
            let mut ids = doc.tree.jump_chain(host_id).map_err(|e| e.to_string())?;
            ids.push(host_id);
            let plans = ids
                .into_iter()
                .map(|id| plan_for(doc, id))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((
                plans,
                name,
                doc.settings.ssh_keepalive_secs,
                doc.settings.ssh_term.clone(),
            ))
        })
        .await?;
    // Hasło podane przy łączeniu i hasło klucza dotyczą tylko celu i nie są nigdzie zapisywane.
    let asked_password = password.is_some();
    let target_has_saved_password = plans.last().is_some_and(|p| p.password.is_some());
    let target_key_path = plans.last().and_then(|p| p.key_path.clone());
    let term = plans
        .last()
        .and_then(|p| p.term.clone())
        .unwrap_or(settings_term);
    let login_command = plans.last().and_then(|p| p.login_command.clone());
    let keepalive = keepalive(keepalive_secs);
    let legacy_hops = plans.iter().filter(|p| p.legacy).count();
    let last = plans.len().saturating_sub(1);
    // Odczyt pliku klucza i jego odszyfrowanie (KDF) poza blokadą dokumentu.
    let built = tokio::task::spawn_blocking(move || {
        let key_passphrase = key_passphrase.map(Zeroizing::new);
        let password = password.map(Zeroizing::new);
        plans
            .into_iter()
            .enumerate()
            .map(|(i, plan)| {
                build_hop(
                    plan,
                    i == last,
                    password.as_deref().map(String::as_str),
                    key_passphrase.as_deref().map(String::as_str),
                    keepalive,
                )
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|e| e.to_string())?
    .inspect_err(|e| {
        if !e.starts_with("NEEDS_KEY_PASSPHRASE:") {
            state.log(format!("SSH: {host_name}: {e}"));
        } else if let Some(reason) = e.strip_prefix("NEEDS_KEY_PASSPHRASE:") {
            let path = target_key_path.as_deref().unwrap_or("");
            if reason.starts_with("Nieprawidłowe") {
                state.log(format!(
                    "SSH: {host_name}: nieprawidłowe hasło klucza {path}"
                ));
            } else {
                state.log(format!("SSH: {host_name}: klucz {path} wymaga hasła"));
            }
        }
    })?;
    let (hops, skipped): (Vec<Hop>, Vec<Option<String>>) = built.into_iter().unzip();
    let skipped: Vec<String> = skipped.into_iter().flatten().collect();
    for note in &skipped {
        state.log(format!("SSH: {host_name}: {note}"));
    }
    let hop_addrs: Vec<String> = hops
        .iter()
        .map(|h| format!("{}:{}", h.host, h.port))
        .collect();
    state.log(format!("SSH: łączenie z {host_name}"));
    if legacy_hops > 0 {
        state.log(format!(
            "SSH: {host_name}: starsze algorytmy dozwolone (przystanków: {legacy_hops})"
        ));
    }

    let app2 = app.clone();
    let verifier: HostKeyVerifier = Arc::new(move |info| {
        let app = app2.clone();
        Box::pin(ask_ssh_trust(app, info, reloads))
    });

    let session = match ssh::Session::connect(&hops, verifier).await {
        Ok(s) => s,
        Err(e) => {
            state.log(format!("SSH: {host_name}: {e}"));
            // Brak agenta, kluczy albo odrzucenie kluczy: frontend zapyta o hasło i spróbuje ponownie.
            let needs_password = !asked_password
                && !target_has_saved_password
                && matches!(
                    e,
                    ssh::Error::AgentUnavailable(_)
                        | ssh::Error::NoIdentities
                        | ssh::Error::AuthFailed
                );
            // Pominięty plik klucza bywa właściwą przyczyną niepowodzenia, więc komunikat go wymienia.
            let reason = if skipped.is_empty() {
                e.to_string()
            } else {
                format!("{e} ({})", skipped.join("; "))
            };
            return Err(if needs_password {
                format!("NEEDS_PASSWORD:{reason}")
            } else {
                reason
            });
        }
    };
    let (shell, mut rx) = match session.open_shell(&term, cols, rows).await {
        Ok(v) => v,
        Err(e) => {
            state.log(format!("SSH: {host_name}: {e}"));
            session.disconnect().await;
            return Err(e.to_string());
        }
    };
    state.log(format!("SSH: połączono z {host_name}"));
    for (i, used) in session.auth_used().iter().enumerate() {
        let hop = hop_addrs.get(i).map(String::as_str).unwrap_or("?");
        let how = match used {
            AuthUsed::StoredKey(k) => {
                format!(
                    "kluczem z pliku z hostami ({} {})",
                    k.algorithm, k.fingerprint
                )
            }
            AuthUsed::KeyFile { path, info } => format!(
                "kluczem z pliku {path} ({} {})",
                info.algorithm, info.fingerprint
            ),
            AuthUsed::Agent(k) => {
                format!("kluczem z agenta SSH ({} {})", k.algorithm, k.fingerprint)
            }
            AuthUsed::Password if asked_password && i + 1 == hop_addrs.len() => {
                "hasłem podanym przy łączeniu".to_string()
            }
            AuthUsed::Password => "hasłem zapisanym w pliku z hostami".to_string(),
        };
        state.log(format!("SSH: {host_name}: {hop}: uwierzytelniono {how}"));
    }
    let id = Uuid::new_v4();
    let live = Arc::new(Live { session, shell });
    state
        .sessions
        .lock()
        .expect("sessions")
        .insert(id, live.clone());
    let flow = Arc::new(Flow::new(SSH_WINDOW));
    state
        .ssh_flow
        .lock()
        .expect("flow")
        .insert(id, flow.clone());
    // Blokada pliku najpierw ustawia `inner` na `None`, a potem opróżnia mapę sesji. Sesja wstawiona
    // przed blokadą zostanie zamknięta przez nią, a ta wstawiona po blokadzie widzi `None` i zamyka
    // się tutaj, zanim zostanie zwrócona do interfejsu.
    // Przeładowanie interfejsu w trakcie łączenia (`reset_after_reload`) działa tak samo: nowy
    // interfejs nie ma karty tej sesji.
    let locked = state.inner.lock().await.is_none();
    if locked || state.reloads.load(Ordering::SeqCst) != reloads {
        state.ssh_flow.lock().expect("flow").remove(&id);
        let l = state.sessions.lock().expect("sessions").remove(&id);
        if let Some(l) = l {
            let _ = l.shell.close().await;
            l.session.disconnect().await;
        }
        return Err(interrupted_message(locked).into());
    }
    // Polecenie po zalogowaniu (tylko cel). Treść nigdy nie trafia do dziennika.
    if let Some(cmd) = login_command {
        match live.shell.send_line(&cmd) {
            Ok(()) => state.log(format!(
                "SSH: {host_name}: wysłano polecenie po zalogowaniu"
            )),
            Err(e) => state.log(format!(
                "SSH: {host_name}: nie wysłano polecenia po zalogowaniu: {e}"
            )),
        }
    }

    let app3 = app.clone();
    let log_sessions = state.config.lock().expect("config").log_sessions;
    let mut session_log = if log_sessions {
        let tag = id.simple().to_string();
        match session_log::open(&state.data_dir, &host_name, &tag[..8]) {
            Ok(f) => Some(f),
            Err(e) => {
                state.log(format!(
                    "dziennik sesji: nie można utworzyć pliku dla {host_name}: {e}"
                ));
                None
            }
        }
    } else {
        None
    };
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let mut counted = false;
            let body = match ev {
                ShellEvent::Data(d) => {
                    if let Some(f) = session_log.as_mut()
                        && let Err(e) = f.write_all(&d)
                    {
                        // Pierwszy błąd zapisu (np. pełny dysk) trafia do dziennika, dalszy zapis
                        // jest wyłączony, żeby nie zalewać dziennika.
                        app3.state::<AppState>().log(format!(
                            "dziennik sesji: zapis dla {host_name} przerwany: {e}"
                        ));
                        session_log = None;
                    }
                    // Liczymy przed wysłaniem: potwierdzenie z interfejsu może przyjść, zanim ta
                    // pętla wróci do pracy (jak przy obrazie RDP).
                    flow.sent(d.len() as u64);
                    counted = true;
                    InvokeResponseBody::Raw(d)
                }
                ShellEvent::Exit(code) => control(&format!(r#"{{"t":"exit","code":{code}}}"#)),
                ShellEvent::Closed => control(r#"{"t":"closed"}"#),
            };
            if on_event.send(body).is_err() {
                break;
            }
            // Po przekroczeniu okna przestajemy odbierać zdarzenia z crate'a `ssh`: jego kolejka
            // się zapełnia i czytnik kanału staje, a z nim odbiór z sieci. Koniec sesji (zamknięcie
            // karty, blokada pliku) przerywa czekanie.
            if counted {
                let alive = || {
                    app3.state::<AppState>()
                        .sessions
                        .lock()
                        .expect("sessions")
                        .contains_key(&id)
                };
                if !flow.wait(alive).await {
                    break;
                }
            }
        }
        app3.state::<AppState>()
            .ssh_flow
            .lock()
            .expect("flow")
            .remove(&id);
        let live = app3
            .state::<AppState>()
            .sessions
            .lock()
            .expect("sessions")
            .remove(&id);
        if let Some(live) = live {
            live.session.disconnect().await;
        }
        app3.state::<AppState>()
            .log(format!("SSH: zakończono sesję z {host_name}"));
    });
    Ok(id)
}

fn live(state: &AppState, id: Uuid) -> Result<Arc<Live>, String> {
    state
        .sessions
        .lock()
        .expect("sessions")
        .get(&id)
        .cloned()
        .ok_or_else(|| "Sesja już nie istnieje.".to_string())
}

/// Dane z klawiatury jako surowe bajty; identyfikator sesji w nagłówku `x-session`.
/// Komenda jest synchroniczna celowo (jak `rdp_send`): Tauri wykonuje takie wywołania po kolei,
/// a `write` tylko wstawia bajty do kolejki sesji, z której jedno zadanie pisarza wysyła je do
/// kanału SSH. Komenda `async` byłaby uruchamiana jako osobne zadania i zamieniała porcje miejscami.
#[tauri::command]
pub fn ssh_write(state: State<'_, AppState>, request: Request<'_>) -> Result<(), String> {
    let InvokeBody::Raw(data) = request.body() else {
        return Err("Oczekiwano surowych danych.".into());
    };
    let id = request
        .headers()
        .get("x-session")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or("Brak identyfikatora sesji.")?;
    live(&state, id)?
        .shell
        .write(data.clone())
        .map_err(|e| e.to_string())
}

/// Potwierdzenie z interfejsu: tyle bajtów wyjścia terminala zostało przetworzonych (patrz `Flow`).
/// Synchroniczna jak `ssh_write`: tylko odejmuje od licznika.
#[tauri::command]
pub fn ssh_ack(state: State<'_, AppState>, id: Uuid, bytes: u64) {
    let flow = state.ssh_flow.lock().expect("flow").get(&id).cloned();
    if let Some(flow) = flow {
        flow.ack(bytes);
    }
}

/// Zmiana rozmiaru idzie tą samą kolejką co dane, więc nie wyprzedza bajtów wysłanych przed nią.
#[tauri::command]
pub fn ssh_resize(
    state: State<'_, AppState>,
    id: Uuid,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    live(&state, id)?
        .shell
        .resize(cols, rows)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn ssh_close(state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    let l = state.sessions.lock().expect("sessions").remove(&id);
    if let Some(l) = l {
        let _ = l.shell.close().await;
        l.session.disconnect().await;
    }
    state.ssh_flow.lock().expect("flow").remove(&id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(alg: &str, fp: &str) -> TrustedKey {
        TrustedKey {
            protocol: Protocol::Ssh,
            host: "h".into(),
            port: 22,
            algorithm: alg.into(),
            fingerprint: fp.into(),
        }
    }

    #[test]
    fn changed_algorithm_is_reported_as_a_change() {
        let ed = key("ssh-ed25519", "AAA");
        let known = [&ed];
        assert_eq!(previous_key(&known, "ssh-ed25519", "AAA"), None);
        assert_eq!(
            previous_key(&known, "ssh-ed25519", "BBB"),
            Some(Some("AAA".into()))
        );
        // Inny algorytm przy zapamiętanym kluczu to też zmiana, a nie pierwsze połączenie.
        assert_eq!(
            previous_key(&known, "ecdsa-sha2-nistp256", "CCC"),
            Some(Some("ssh-ed25519 AAA".into()))
        );
        assert_eq!(previous_key(&[], "ssh-ed25519", "AAA"), Some(None));
    }

    fn plan() -> HopPlan {
        HopPlan {
            name: "h".into(),
            host: "h.example".into(),
            port: 22,
            username: "u".into(),
            stored_key: None,
            key_path: None,
            password: None,
            legacy: false,
            term: None,
            login_command: None,
        }
    }

    fn hop4(
        plan: HopPlan,
        target: bool,
        pw: Option<&str>,
        kp: Option<&str>,
    ) -> Result<(Hop, Option<String>), String> {
        build_hop(plan, target, pw, kp, Some(ssh::DEFAULT_KEEPALIVE))
    }

    #[test]
    fn keepalive_from_settings() {
        assert_eq!(keepalive(0), None);
        assert_eq!(keepalive(30), Some(Duration::from_secs(30)));
    }

    #[test]
    fn legacy_flag_reaches_the_hop() {
        let (modern, _) = hop4(plan(), true, None, None).unwrap();
        assert!(!modern.legacy);
        let old = HopPlan {
            legacy: true,
            ..plan()
        };
        // Także przy haśle jednorazowym, które zastępuje metody celu.
        let (hop, _) = hop4(old, true, Some("jednorazowe"), None).unwrap();
        assert!(hop.legacy);
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-sess-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Klucz ed25519 z `ssh-keygen`; `None`, gdy programu nie ma.
    fn keygen(d: &std::path::Path, name: &str, pass: &str) -> Option<std::path::PathBuf> {
        let path = d.join(name);
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", pass, "-f"])
            .arg(&path)
            .status()
            .ok()?
            .success()
            .then_some(path)
    }

    fn stored(text: &str) -> Zeroizing<String> {
        let (t, _) = ssh::import_key(text, None).unwrap();
        t
    }

    #[test]
    fn build_hop_orders_methods() {
        let d = dir("order");
        let Some(k) = keygen(&d, "k", "") else { return };
        let text = std::fs::read_to_string(&k).unwrap();
        let hop = hop4(
            HopPlan {
                stored_key: Some(stored(&text)),
                key_path: Some(k.to_string_lossy().into_owned()),
                password: Some(Zeroizing::new("p".into())),
                ..plan()
            },
            true,
            None,
            None,
        )
        .unwrap()
        .0;
        assert!(matches!(
            hop.methods.as_slice(),
            [
                Auth::Key {
                    origin: KeyOrigin::Stored,
                    ..
                },
                Auth::Key {
                    origin: KeyOrigin::File(_),
                    ..
                },
                Auth::Agent,
                Auth::Password(_)
            ]
        ));
        let (bare, _) = hop4(plan(), true, None, None).unwrap();
        assert!(matches!(bare.methods.as_slice(), [Auth::Agent]));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn one_time_password_replaces_target_methods() {
        let p = HopPlan {
            key_path: Some("/nie/ma/takiego/pliku".into()),
            password: Some(Zeroizing::new("zapisane".into())),
            ..plan()
        };
        // Plik klucza nie jest czytany, więc brak pliku nie przeszkadza.
        let (hop, _) = hop4(p, true, Some("jednorazowe"), None).unwrap();
        assert!(matches!(hop.methods.as_slice(), [Auth::Password(_)]));
        // Bastion nie dostaje hasła jednorazowego.
        let (b, _) = hop4(plan(), false, Some("x"), None).unwrap();
        assert!(matches!(b.methods.as_slice(), [Auth::Agent]));
    }

    #[test]
    fn encrypted_path_key_asks_on_target_only() {
        let d = dir("enc");
        let Some(k) = keygen(&d, "k", "haslo-klucza") else {
            return;
        };
        let p = || HopPlan {
            key_path: Some(k.to_string_lossy().into_owned()),
            ..plan()
        };
        let e = hop4(p(), true, None, None).unwrap_err();
        assert!(e.starts_with("NEEDS_KEY_PASSPHRASE:"), "{e}");
        let e = hop4(p(), false, None, Some("haslo-klucza")).unwrap_err();
        assert!(!e.starts_with("NEEDS_KEY_PASSPHRASE:"), "{e}");
        assert!(e.contains("bastionu") && e.contains("agenta SSH"), "{e}");
        let (ok, _) = hop4(p(), true, None, Some("haslo-klucza")).unwrap();
        assert_eq!(ok.methods.len(), 2);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn wrong_key_passphrase_asks_again() {
        let d = dir("wrong");
        let Some(k) = keygen(&d, "k", "haslo-klucza") else {
            return;
        };
        let p = HopPlan {
            key_path: Some(k.to_string_lossy().into_owned()),
            ..plan()
        };
        let e = hop4(p, true, None, Some("zle")).unwrap_err();
        assert!(
            e.starts_with("NEEDS_KEY_PASSPHRASE:Nieprawidłowe hasło"),
            "{e}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn key_file_over_limit_is_rejected() {
        let d = dir("big");
        let f = d.join("duzy");
        std::fs::write(&f, vec![b'a'; ssh::MAX_KEY_TEXT + 1]).unwrap();
        let p = HopPlan {
            key_path: Some(f.to_string_lossy().into_owned()),
            ..plan()
        };
        let e = hop4(p, true, None, None).unwrap_err();
        assert!(e.contains("za duży"), "{e}");
        let p = HopPlan {
            key_path: Some(d.join("brak").to_string_lossy().into_owned()),
            ..plan()
        };
        // Pliku, którego nie ma, nie traktujemy jak błędu: metoda wypada, pozostałe zostają.
        let (hop, skipped) = hop4(p, true, None, None).unwrap();
        assert!(matches!(hop.methods.as_slice(), [Auth::Agent]));
        let note = skipped.expect("notatka o pominiętym pliku");
        assert!(note.starts_with("pominięto plik klucza"), "{note}");
        assert!(note.contains("brak"), "{note}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn tilde_path_expands_with_home() {
        let e = expand_key_path("/abs/k").unwrap();
        assert_eq!(e, std::path::PathBuf::from("/abs/k"));
        if let Some(h) = std::env::var_os("HOME") {
            assert_eq!(
                expand_key_path("~/.ssh/k").unwrap(),
                std::path::PathBuf::from(h).join(".ssh/k")
            );
        }
    }
}
