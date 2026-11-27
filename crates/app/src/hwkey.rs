//! Klucz sprzętowy FIDO2 przy otwieraniu pliku z hostami: krok odblokowania kluczem oraz
//! dodawanie, usuwanie i sprawdzanie kluczy.
//!
//! Inaczej niż kod TOTP (bramka w programie, patrz `mfa.rs`) klucz jest składnikiem
//! szyfrowania: plik z kluczem da się odszyfrować tylko hasłem głównym razem z sekretem, który
//! zwraca klucz (`vault::KeyChallenge`). Po podaniu hasła w `AppState::pending_key` czeka więc
//! jeszcze zaszyfrowany plik, a nie jego treść. Każdy zarejestrowany klucz otwiera plik sam;
//! drugi klucz jest jedyną drogą odzyskania dostępu po utracie pierwszego.
//!
//! Operacje na kluczu blokują do czasu dotknięcia, więc biegną w wątku blokującym, bez
//! trzymania blokady dokumentu. PIN-u i sekretów nie wolno pisać do dziennika.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fido::{Authenticator, PinEntry};
use model::Document;
use serde::Serialize;
use tauri::State;
use vault::{KeyChallenge, Vault};
use zeroize::{Zeroize, Zeroizing};

use crate::state::{AppState, Unlocked};

/// Błąd `unlock`, po którym interfejs prosi o klucz; po dwukropku tryb PIN-u (`app`, `system`).
pub const NEEDS_KEY: &str = "NEEDS_KEY:";
const LOCKED: &str = "Plik z hostami jest zablokowany";
const UNSUPPORTED: &str = "Ta wersja programu nie obsługuje kluczy sprzętowych na tym systemie.";
/// Tyle czasu plik czeka na klucz po podaniu hasła.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// Tyle czasu jest na dotknięcie wszystkich kluczy, które zostają po usunięciu innego.
const REMOVAL_TTL: Duration = Duration::from_secs(10 * 60);

pub type Key = Arc<dyn Authenticator>;
/// Zgłasza interfejsowi, że zaraz trzeba dotknąć klucza: numer dotknięcia i ich liczba.
pub type Progress = Arc<dyn Fn(u8, u8) + Send + Sync>;
type Pin = Option<Zeroizing<String>>;

/// Plik z kluczem sprzętowym po podaniu hasła, czekający na klucz.
pub struct PendingKey {
    challenge: Arc<KeyChallenge>,
    since: Instant,
}

/// Rozpoczęte usuwanie klucza, gdy zostają inne: plik dostanie nową sól, więc każdy
/// pozostający klucz musi podać dla niej sekret. Sekrety czekają tu na komplet.
pub struct Removal {
    target: Vec<u8>,
    /// Sól pliku z chwili rozpoczęcia: zmiana listy kluczy w trakcie unieważnia usuwanie.
    base_salt: [u8; vault::KEY_SECRET_LEN],
    new_salt: [u8; vault::KEY_SECRET_LEN],
    collected: Vec<(Vec<u8>, Zeroizing<[u8; vault::KEY_SECRET_LEN]>)>,
    since: Instant,
}

/// Odkłada plik do czasu użycia klucza (zastępuje poprzednio odłożony).
pub fn begin(state: &AppState, challenge: KeyChallenge) {
    *state.pending_key.lock().expect("pending_key") = Some(PendingKey {
        challenge: Arc::new(challenge),
        since: Instant::now(),
    });
}

/// Porzuca plik czekający na klucz i niedokończone usuwanie (blokada pliku, przeładowanie interfejsu).
pub fn clear(state: &AppState) {
    *state.pending_key.lock().expect("pending_key") = None;
    *state.key_removal.lock().expect("key_removal") = None;
}

/// Tryb PIN-u w postaci dla interfejsu.
fn pin_mode(key: &dyn Authenticator) -> &'static str {
    match key.pin_entry() {
        PinEntry::App => "app",
        PinEntry::System => "system",
    }
}

/// Błąd `unlock` dla pliku z kluczem.
pub fn needs_key(key: &dyn Authenticator) -> String {
    format!("{NEEDS_KEY}{}", pin_mode(key))
}

/// Klucz sprzętowy tego systemu. Tworzony przy pierwszym użyciu, bo na Windows potrzebuje
/// uchwytu głównego okna; testy wstawiają tu atrapę.
pub fn authenticator(app: &tauri::AppHandle, state: &AppState) -> Option<Key> {
    let mut slot = state.authenticator.lock().expect("authenticator");
    if slot.is_none() {
        *slot = fido::platform(window_handle(app)).map(Arc::from);
    }
    slot.clone()
}

#[cfg(windows)]
fn window_handle(app: &tauri::AppHandle) -> Option<isize> {
    use tauri::Manager;
    let window = app.get_webview_window("main")?;
    window.hwnd().ok().map(|h| h.0 as isize)
}

#[cfg(not(windows))]
fn window_handle(_app: &tauri::AppHandle) -> Option<isize> {
    None
}

fn key_err(e: &fido::Error) -> String {
    use fido::Error as E;
    match e {
        E::NoDevice => "Nie znaleziono klucza sprzętowego. Włóż klucz i spróbuj ponownie.".into(),
        E::ManyDevices => {
            "Podłączono więcej niż jeden klucz. Zostaw tylko ten, którego chcesz użyć.".into()
        }
        E::PinRequired => "Podaj PIN klucza.".into(),
        E::PinInvalid { retries: Some(n) } => {
            format!("Nieprawidłowy PIN klucza. Pozostało prób: {n}.")
        }
        E::PinInvalid { retries: None } => "Nieprawidłowy PIN klucza.".into(),
        E::PinBlocked => {
            "PIN klucza jest zablokowany po zbyt wielu błędnych próbach. Klucz trzeba \
                          zresetować narzędziem producenta."
                .into()
        }
        E::PinAuthBlocked => "Klucz wstrzymał sprawdzanie PIN-u. Wyjmij go, włóż ponownie \
                              i spróbuj jeszcze raz."
            .into(),
        E::PinNotSet => "Ten klucz nie ma ustawionego PIN-u. Ustaw PIN klucza w ustawieniach \
                         systemu albo narzędziem producenta."
            .into(),
        E::NotRegistered => "Ten klucz nie jest zarejestrowany w tym pliku.".into(),
        E::AlreadyRegistered => "Ten klucz jest już zarejestrowany w tym pliku.".into(),
        E::Cancelled => "Operacja na kluczu została anulowana.".into(),
        E::Timeout => "Minął czas na dotknięcie klucza. Spróbuj ponownie.".into(),
        E::Unsupported(why) => {
            format!("Ten klucz albo system nie obsługuje potrzebnej funkcji ({why}).")
        }
        E::Other(why) => format!("Błąd klucza sprzętowego: {why}."),
    }
}

/// Wykonuje blokującą operację na kluczu poza pętlą zdarzeń.
async fn with_key<T: Send + 'static>(
    key: &Key,
    f: impl FnOnce(&dyn Authenticator) -> Result<T, fido::Error> + Send + 'static,
) -> Result<T, String> {
    let key = key.clone();
    tokio::task::spawn_blocking(move || f(key.as_ref()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| key_err(&e))
}

fn pin_str(pin: &Pin) -> Option<&str> {
    pin.as_ref().map(|p| p.as_str())
}

/// Czyta sekret dwa razy i wymaga tego samego wyniku. Sekretem zostanie zaszyfrowany klucz
/// danych, więc klucz, który nie odtwarza sekretu, odciąłby dostęp do pliku.
fn read_twice(
    key: &dyn Authenticator,
    credentials: &[Vec<u8>],
    salt: &[u8; vault::KEY_SECRET_LEN],
    pin: Option<&str>,
    before_second: &dyn Fn(),
) -> Result<fido::Secret, fido::Error> {
    let first = key.secret(credentials, salt, pin)?;
    before_second();
    let second = key.secret(std::slice::from_ref(&first.credential), salt, pin)?;
    if first.credential != second.credential || *first.secret != *second.secret {
        return Err(fido::Error::Other(
            "klucz zwrócił dwa różne sekrety dla tej samej soli".into(),
        ));
    }
    Ok(first)
}

/// Drugi krok odblokowania pliku z kluczem sprzętowym. Błąd `KEY_BAD:` pozwala spróbować
/// ponownie (inny klucz, PIN), `KEY_EXPIRED:` wraca do hasła głównego.
pub(crate) async fn finish_unlock(state: &AppState, key: Key, pin: Pin) -> Result<(), String> {
    let _op = state.key_op.lock().await;
    let challenge = {
        let mut slot = state.pending_key.lock().expect("pending_key");
        match slot.as_ref() {
            Some(p) if p.since.elapsed() <= PENDING_TTL => p.challenge.clone(),
            Some(_) => {
                *slot = None;
                return Err(
                    "KEY_EXPIRED:Minął czas na użycie klucza. Podaj hasło główne ponownie.".into(),
                );
            }
            None => return Err("KEY_EXPIRED:Najpierw podaj hasło główne.".into()),
        }
    };
    let credentials: Vec<Vec<u8>> = challenge.keys().into_iter().map(|k| k.credential).collect();
    let salt = challenge.salt();
    let answer = with_key(&key, move |k| k.secret(&credentials, &salt, pin_str(&pin)))
        .await
        .map_err(|e| format!("KEY_BAD:{e}"))?;
    let opened = challenge.finish::<Document>(&answer.credential, &answer.secret);
    // Blokada pliku albo przeładowanie interfejsu w trakcie czekania na dotknięcie porzuca
    // odblokowanie: wynik nie może wtedy otworzyć pliku.
    // Blok zwalnia blokadę przed `await` niżej.
    let (mut vault, doc) = {
        let mut slot = state.pending_key.lock().expect("pending_key");
        if !slot
            .as_ref()
            .is_some_and(|p| Arc::ptr_eq(&p.challenge, &challenge))
        {
            return Err("KEY_EXPIRED:Odblokowanie przerwano. Podaj hasło główne ponownie.".into());
        }
        match opened {
            Ok(v) => {
                *slot = None;
                v
            }
            Err(vault::Error::KeyRejected) => {
                state.log("odblokowanie: klucz sprzętowy nie pasuje do pliku");
                return Err(
                    "KEY_BAD:Ten klucz odpowiedział, ale jego sekret nie pasuje do pliku.".into(),
                );
            }
            Err(e) => {
                // Hasła nie da się sprawdzić bez klucza, więc złe hasło wychodzi dopiero tutaj.
                *slot = None;
                return Err(format!(
                    "KEY_EXPIRED:{}",
                    crate::commands::unlock_err(e, &state.path)
                ));
            }
        }
    };
    vault.set_backup_count(state.config.lock().expect("config").backup_count);
    if doc.mfa.totp.is_some() {
        crate::mfa::begin_second_step(state, Unlocked { vault, doc });
        return Err(crate::mfa::NEEDS_TOTP.into());
    }
    *state.inner.lock().await = Some(Unlocked { vault, doc });
    state.touch_activity();
    state.log("odblokowano plik z hostami (hasło i klucz sprzętowy)");
    Ok(())
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct KeyView {
    /// Identyfikator poświadczenia szesnastkowo; służy tylko do wskazania klucza przy usuwaniu.
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct RemovalView {
    pub id: String,
    /// Nazwy kluczy, które trzeba jeszcze dotknąć, żeby dokończyć usuwanie.
    pub waiting: Vec<String>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct KeyStatus {
    /// Czy program obsługuje klucze sprzętowe na tym systemie.
    pub available: bool,
    /// Kto pyta o PIN: `app` (pole w programie) albo `system` (okno systemu).
    pub pin: Option<&'static str>,
    pub max: usize,
    pub keys: Vec<KeyView>,
    pub removal: Option<RemovalView>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub(crate) async fn status(state: &AppState, key: Option<&Key>) -> Result<KeyStatus, String> {
    let guard = state.inner.lock().await;
    let u = guard.as_ref().ok_or(LOCKED)?;
    let keys = u.vault.keys();
    let removal = state
        .key_removal
        .lock()
        .expect("key_removal")
        .as_ref()
        .filter(|r| r.since.elapsed() <= REMOVAL_TTL && u.vault.key_salt() == Some(r.base_salt))
        .map(|r| RemovalView {
            id: hex(&r.target),
            waiting: keys
                .iter()
                .filter(|k| {
                    k.credential != r.target && !r.collected.iter().any(|(c, _)| *c == k.credential)
                })
                .map(|k| k.name.clone())
                .collect(),
        });
    Ok(KeyStatus {
        available: key.is_some(),
        pin: key.map(|k| pin_mode(k.as_ref())),
        max: vault::MAX_KEYS,
        keys: keys
            .into_iter()
            .map(|k| KeyView {
                id: hex(&k.credential),
                name: k.name,
            })
            .collect(),
        removal,
    })
}

fn save_err(e: vault::Error) -> String {
    format!("Nie udało się zapisać zmiany kluczy: {e}.")
}

/// Rejestruje klucz: poświadczenie na kluczu, dwukrotny odczyt sekretu i zapis pliku.
/// Klucz trzeba dotknąć trzy razy.
pub(crate) async fn add(
    state: &AppState,
    key: Key,
    pin: Pin,
    name: &str,
    progress: Progress,
) -> Result<KeyStatus, String> {
    let _op = state.key_op.lock().await;
    let name = name.trim().to_owned();
    if name.is_empty() || name.len() > vault::MAX_KEY_NAME || name.chars().any(char::is_control) {
        return Err("Podaj nazwę klucza (najwyżej 64 bajty).".into());
    }
    let (existing, salt) = {
        let guard = state.inner.lock().await;
        let u = guard.as_ref().ok_or(LOCKED)?;
        let keys = u.vault.keys();
        if keys.len() >= vault::MAX_KEYS {
            return Err(format!(
                "Plik ma już {} klucze, czyli tyle, ile najwyżej obsługuje.",
                vault::MAX_KEYS
            ));
        }
        if keys.iter().any(|k| k.name == name) {
            return Err("Klucz o tej nazwie już istnieje.".into());
        }
        let salt = match u.vault.key_salt() {
            Some(salt) => salt,
            None => Vault::new_key_salt().map_err(|e| e.to_string())?,
        };
        let existing: Vec<Vec<u8>> = keys.into_iter().map(|k| k.credential).collect();
        (existing, salt)
    };
    let answer = with_key(&key, move |k| {
        let pin = pin_str(&pin);
        progress(1, 3);
        let credential = k.register(pin, &existing)?;
        progress(2, 3);
        read_twice(k, &[credential], &salt, pin, &|| progress(3, 3))
    })
    .await?;
    {
        let mut guard = state.inner.lock().await;
        let u = guard.as_mut().ok_or(LOCKED)?;
        let pre = state.sync_pre();
        u.vault
            .add_key(&u.doc, &name, &answer.credential, &salt, &answer.secret)
            .map_err(save_err)?;
        state.sync_post(pre);
    }
    // Porzucone usuwanie liczyło sekrety dla listy kluczy sprzed tej zmiany.
    *state.key_removal.lock().expect("key_removal") = None;
    state.log("dodano klucz sprzętowy do pliku z hostami");
    status(state, Some(&key)).await
}

/// Zapisuje plik bez klucza `target`. Wersja formatu wraca do zwykłej, gdy po usunięciu
/// ostatniego klucza dokument nie wymaga już żadnego dodatkowego składnika.
fn write_removal(
    state: &AppState,
    u: &mut Unlocked,
    target: &[u8],
    new_salt: &[u8; vault::KEY_SECRET_LEN],
    remaining: &[(Vec<u8>, [u8; vault::KEY_SECRET_LEN])],
) -> Result<(), String> {
    let pre = state.sync_pre();
    let was_protected = u.vault.protected();
    u.vault.set_protected(!u.doc.mfa.is_empty());
    if let Err(e) = u.vault.remove_key(&u.doc, target, new_salt, remaining) {
        u.vault.set_protected(was_protected);
        return Err(save_err(e));
    }
    state.sync_post(pre);
    Ok(())
}

/// Usuwa klucz. Ostatni klucz trzeba przy tym dotknąć (wyłączenie składnika wymaga jego
/// posiadania). Gdy zostają inne klucze, każdy z nich trzeba dotknąć dwa razy: plik dostaje
/// nowy klucz danych i nową sól, a wywołanie zbiera sekret jednego klucza naraz. Wynik
/// z `removal` oznacza, że trzeba wywołać komendę ponownie z kolejnym kluczem.
pub(crate) async fn remove(
    state: &AppState,
    key: Key,
    id: &str,
    pin: Pin,
    progress: Progress,
) -> Result<KeyStatus, String> {
    let _op = state.key_op.lock().await;
    let target = unhex(id).ok_or("Nieprawidłowy identyfikator klucza.")?;
    let (keys, salt) = {
        let guard = state.inner.lock().await;
        let u = guard.as_ref().ok_or(LOCKED)?;
        (u.vault.keys(), u.vault.key_salt())
    };
    let salt = salt.ok_or("Plik nie ma kluczy sprzętowych.")?;
    if !keys.iter().any(|k| k.credential == target) {
        return Err("Nie ma takiego klucza.".into());
    }
    let remaining: Vec<Vec<u8>> = keys
        .iter()
        .filter(|k| k.credential != target)
        .map(|k| k.credential.clone())
        .collect();

    if remaining.is_empty() {
        let wanted = target.clone();
        let answer = with_key(&key, move |k| {
            progress(1, 1);
            k.secret(&[wanted], &salt, pin_str(&pin))
        })
        .await?;
        let mut guard = state.inner.lock().await;
        let u = guard.as_mut().ok_or(LOCKED)?;
        if !u.vault.key_matches(&answer.credential, &answer.secret) {
            return Err("Ten klucz nie pasuje do pliku.".into());
        }
        let unused = Vault::new_key_salt().map_err(|e| e.to_string())?;
        write_removal(state, u, &target, &unused, &[])?;
        drop(guard);
        *state.key_removal.lock().expect("key_removal") = None;
        state.log("usunięto ostatni klucz sprzętowy: plik otwiera hasło główne");
        return status(state, Some(&key)).await;
    }

    let (new_salt, needed) = {
        let mut slot = state.key_removal.lock().expect("key_removal");
        let current = slot.as_ref().is_some_and(|r| {
            r.target == target && r.base_salt == salt && r.since.elapsed() <= REMOVAL_TTL
        });
        if !current {
            *slot = Some(Removal {
                target: target.clone(),
                base_salt: salt,
                new_salt: Vault::new_key_salt().map_err(|e| e.to_string())?,
                collected: Vec::new(),
                since: Instant::now(),
            });
        }
        let r = slot.as_ref().expect("ustawione wyżej");
        let needed: Vec<Vec<u8>> = remaining
            .iter()
            .filter(|c| !r.collected.iter().any(|(d, _)| d == *c))
            .cloned()
            .collect();
        (r.new_salt, needed)
    };
    let answer = with_key(&key, move |k| {
        progress(1, 2);
        read_twice(k, &needed, &new_salt, pin_str(&pin), &|| progress(2, 2))
    })
    .await?;
    let complete = {
        let mut slot = state.key_removal.lock().expect("key_removal");
        let Some(r) = slot
            .as_mut()
            .filter(|r| r.target == target && r.new_salt == new_salt)
        else {
            return Err("Usuwanie klucza przerwano. Zacznij od nowa.".into());
        };
        if !r.collected.iter().any(|(c, _)| *c == answer.credential) {
            r.collected.push((answer.credential, answer.secret));
        }
        let all = remaining
            .iter()
            .all(|c| r.collected.iter().any(|(d, _)| d == c));
        if all { slot.take() } else { None }
    };
    if let Some(removal) = complete {
        let mut secrets: Vec<(Vec<u8>, [u8; vault::KEY_SECRET_LEN])> = removal
            .collected
            .iter()
            .map(|(c, s)| (c.clone(), **s))
            .collect();
        let written = async {
            let mut guard = state.inner.lock().await;
            let u = guard.as_mut().ok_or(LOCKED)?;
            if u.vault.key_salt() != Some(salt) {
                return Err("Lista kluczy zmieniła się w trakcie. Zacznij od nowa.".to_string());
            }
            write_removal(state, u, &target, &new_salt, &secrets)
        }
        .await;
        for (_, s) in &mut secrets {
            s.zeroize();
        }
        written?;
        state.log("usunięto klucz sprzętowy z pliku z hostami");
    }
    status(state, Some(&key)).await
}

/// Sprawdza, czy podłączony klucz otwiera ten plik, niczego nie zmieniając. Służy do
/// potwierdzenia, że klucz zarejestrowany na innym systemie działa także tutaj.
pub(crate) async fn check(state: &AppState, key: Key, pin: Pin) -> Result<String, String> {
    let _op = state.key_op.lock().await;
    let (keys, salt) = {
        let guard = state.inner.lock().await;
        let u = guard.as_ref().ok_or(LOCKED)?;
        (u.vault.keys(), u.vault.key_salt())
    };
    let salt = salt.ok_or("Plik nie ma kluczy sprzętowych.")?;
    let credentials: Vec<Vec<u8>> = keys.iter().map(|k| k.credential.clone()).collect();
    let answer = with_key(&key, move |k| k.secret(&credentials, &salt, pin_str(&pin))).await?;
    let guard = state.inner.lock().await;
    let u = guard.as_ref().ok_or(LOCKED)?;
    if !u.vault.key_matches(&answer.credential, &answer.secret) {
        state.log("sprawdzenie klucza sprzętowego: sekret nie pasuje do pliku");
        return Err(
            "Klucz odpowiedział, ale jego sekret nie pasuje do pliku. Jeśli klucz był \
             rejestrowany na innym systemie, oznacza to niezgodność między systemami: zgłoś to."
                .into(),
        );
    }
    state.log("sprawdzenie klucza sprzętowego: klucz pasuje do pliku");
    Ok(keys
        .into_iter()
        .find(|k| k.credential == answer.credential)
        .map(|k| k.name)
        .unwrap_or_default())
}

fn progress_events(app: &tauri::AppHandle) -> Progress {
    use tauri::Emitter;
    let app = app.clone();
    Arc::new(move |step, of| {
        let _ = app.emit("key-touch", serde_json::json!({ "step": step, "of": of }));
    })
}

fn pin_arg(pin: Option<String>) -> Pin {
    pin.map(Zeroizing::new)
}

fn platform_key(app: &tauri::AppHandle, state: &AppState) -> Result<Key, String> {
    authenticator(app, state).ok_or_else(|| UNSUPPORTED.to_string())
}

/// Drugi krok odblokowania pliku, który wymaga klucza sprzętowego.
#[tauri::command]
pub async fn unlock_key(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    pin: Option<String>,
) -> Result<(), String> {
    let key = platform_key(&app, &state)?;
    finish_unlock(&state, key, pin_arg(pin)).await
}

#[tauri::command]
pub async fn key_status(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<KeyStatus, String> {
    let key = authenticator(&app, &state);
    status(&state, key.as_ref()).await
}

#[tauri::command]
pub async fn key_add(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    pin: Option<String>,
    name: String,
) -> Result<KeyStatus, String> {
    let key = platform_key(&app, &state)?;
    add(&state, key, pin_arg(pin), &name, progress_events(&app)).await
}

#[tauri::command]
pub async fn key_remove(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: String,
    pin: Option<String>,
) -> Result<KeyStatus, String> {
    let key = platform_key(&app, &state)?;
    remove(&state, key, &id, pin_arg(pin), progress_events(&app)).await
}

/// Porzuca rozpoczęte usuwanie klucza.
#[tauri::command]
pub async fn key_remove_cancel(state: State<'_, AppState>) -> Result<(), String> {
    *state.key_removal.lock().expect("key_removal") = None;
    Ok(())
}

/// Sprawdza podłączony klucz i zwraca nazwę, pod którą jest zarejestrowany.
#[tauri::command]
pub async fn key_check(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    pin: Option<String>,
) -> Result<String, String> {
    let key = platform_key(&app, &state)?;
    check(&state, key, pin_arg(pin)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido::soft::SoftKey;
    use model::mfa::{self, Totp};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use vault::KdfParams;

    const HASLO: &str = "haslo-glowne";
    const NOW: u64 = 1_800_000_000;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-hwkey-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn unlocked_state(dir: &Path) -> AppState {
        let path = dir.join("hosts.mrm");
        let doc = Document::default();
        let vault = Vault::create(&path, HASLO, KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let state = AppState::new(path);
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        state
    }

    fn soft(seed: u8) -> (Arc<SoftKey>, Key) {
        let k = Arc::new(SoftKey::new(seed, "1234"));
        (k.clone(), k as Key)
    }

    fn pin(p: &str) -> Pin {
        Some(Zeroizing::new(p.to_owned()))
    }

    fn quiet() -> Progress {
        Arc::new(|_, _| {})
    }

    async fn lock(state: &AppState) {
        *state.inner.lock().await = None;
        clear(state);
    }

    async fn is_unlocked(state: &AppState) -> bool {
        state.inner.lock().await.is_some()
    }

    fn version(state: &AppState) -> u8 {
        std::fs::read(&state.path).unwrap()[4]
    }

    fn names(status: &KeyStatus) -> Vec<&str> {
        status.keys.iter().map(|k| k.name.as_str()).collect()
    }

    #[tokio::test]
    async fn key_is_needed_together_with_password() {
        let d = dir("odblokuj");
        let state = unlocked_state(&d).await;
        let (a_dev, a) = soft(1);
        let (_, b) = soft(2);
        let empty = status(&state, Some(&a)).await.unwrap();
        assert!(empty.available && empty.keys.is_empty() && empty.removal.is_none());
        assert_eq!((empty.pin, empty.max), (Some("app"), vault::MAX_KEYS));
        assert!(!status(&state, None).await.unwrap().available);

        // Zła nazwa i zły PIN niczego nie zmieniają.
        let e = add(&state, a.clone(), pin("1234"), "  ", quiet())
            .await
            .unwrap_err();
        assert!(e.contains("nazwę"), "{e}");
        let e = add(&state, a.clone(), pin("0000"), "Niebieski", quiet())
            .await
            .unwrap_err();
        assert!(e.contains("Pozostało prób: 7"), "{e}");
        let e = add(&state, a.clone(), None, "Niebieski", quiet())
            .await
            .unwrap_err();
        assert!(e.contains("Podaj PIN"), "{e}");
        assert_eq!(version(&state), vault::FORMAT_VERSION);

        // Rejestracja: trzy dotknięcia, zgłaszane po kolei.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let progress: Progress =
            Arc::new(move |step, of| recorder.lock().unwrap().push((step, of)));
        let after = add(&state, a.clone(), pin("1234"), " Niebieski ", progress)
            .await
            .unwrap();
        assert_eq!(names(&after), ["Niebieski"]);
        assert_eq!(*seen.lock().unwrap(), [(1, 3), (2, 3), (3, 3)]);
        assert_eq!(a_dev.touches(), 3);
        assert_eq!(version(&state), vault::FORMAT_PROTECTED);
        assert_eq!(
            check(&state, a.clone(), pin("1234")).await.unwrap(),
            "Niebieski"
        );
        // Zwykły zapis dokumentu zachowuje klucz.
        state
            .mutate(|doc| {
                doc.settings.confirm_quit = !doc.settings.confirm_quit;
                Ok(())
            })
            .await
            .unwrap();
        lock(&state).await;

        // Klucz bez hasła nic nie daje, a samo hasło nie odblokowuje.
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("KEY_EXPIRED:") && e.contains("Najpierw"),
            "{e}"
        );
        let e = crate::commands::unlock_with(&state, HASLO.into(), None)
            .await
            .unwrap_err();
        assert!(e.contains("nie obsługuje"), "{e}");
        let e = crate::commands::unlock_with(&state, HASLO.into(), Some(a.clone()))
            .await
            .unwrap_err();
        assert_eq!(e, "NEEDS_KEY:app");
        assert!(!is_unlocked(&state).await);
        // Błędy, po których można próbować dalej: zły PIN, brak klucza, cudzy klucz.
        let e = finish_unlock(&state, a.clone(), pin("9999"))
            .await
            .unwrap_err();
        assert!(e.starts_with("KEY_BAD:") && e.contains("PIN"), "{e}");
        a_dev.set_present(false);
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("KEY_BAD:") && e.contains("Nie znaleziono"),
            "{e}"
        );
        a_dev.set_present(true);
        let e = finish_unlock(&state, b.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("KEY_BAD:") && e.contains("nie jest zarejestrowany"),
            "{e}"
        );
        assert!(!is_unlocked(&state).await);
        finish_unlock(&state, a.clone(), pin("1234")).await.unwrap();
        assert!(is_unlocked(&state).await);
        assert_eq!(
            names(&status(&state, Some(&a)).await.unwrap()),
            ["Niebieski"]
        );

        // Złe hasło wychodzi dopiero po użyciu klucza i wraca do kroku hasła.
        lock(&state).await;
        let e = crate::commands::unlock_with(&state, "zle-haslo".into(), Some(a.clone()))
            .await
            .unwrap_err();
        assert_eq!(e, "NEEDS_KEY:app");
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(
            e.starts_with("KEY_EXPIRED:") && e.contains("Nieprawidłowe hasło"),
            "{e}"
        );
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw"), "{e}");
        // Blokada pliku porzuca plik czekający na klucz.
        crate::commands::unlock_with(&state, HASLO.into(), Some(a.clone()))
            .await
            .unwrap_err();
        clear(&state);
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw"), "{e}");
        assert!(!is_unlocked(&state).await);
    }

    #[tokio::test]
    async fn several_keys_and_removal() {
        let d = dir("usun");
        let state = unlocked_state(&d).await;
        let (a_dev, a) = soft(1);
        let (b_dev, b) = soft(2);
        let (c_dev, c) = soft(3);
        add(&state, a.clone(), pin("1234"), "A", quiet())
            .await
            .unwrap();
        // Ten sam klucz drugi raz i ta sama nazwa są odrzucane.
        let e = add(&state, a.clone(), pin("1234"), "A2", quiet())
            .await
            .unwrap_err();
        assert!(e.contains("już zarejestrowany"), "{e}");
        let e = add(&state, b.clone(), pin("1234"), "A", quiet())
            .await
            .unwrap_err();
        assert!(e.contains("tej nazwie"), "{e}");
        add(&state, b.clone(), pin("1234"), "B", quiet())
            .await
            .unwrap();
        let three = add(&state, c.clone(), pin("1234"), "C", quiet())
            .await
            .unwrap();
        assert_eq!(names(&three), ["A", "B", "C"]);
        assert_eq!(check(&state, b.clone(), pin("1234")).await.unwrap(), "B");
        let id_of = |status: &KeyStatus, name: &str| {
            status
                .keys
                .iter()
                .find(|k| k.name == name)
                .unwrap()
                .id
                .clone()
        };
        let id_a = id_of(&three, "A");

        // Usunięcie A wymaga po dwóch dotknięciach B i C, w dowolnej kolejności.
        let e = remove(&state, a.clone(), "zz", pin("1234"), quiet())
            .await
            .unwrap_err();
        assert!(e.contains("identyfikator"), "{e}");
        let e = remove(&state, a.clone(), &id_a, pin("1234"), quiet())
            .await
            .unwrap_err();
        assert!(e.contains("nie jest zarejestrowany"), "{e}");
        let (b_before, c_before) = (b_dev.touches(), c_dev.touches());
        let partial = remove(&state, c.clone(), &id_a, pin("1234"), quiet())
            .await
            .unwrap();
        assert_eq!(names(&partial), ["A", "B", "C"]);
        assert_eq!(
            partial.removal,
            Some(RemovalView {
                id: id_a.clone(),
                waiting: vec!["B".into()]
            })
        );
        // Ten sam klucz drugi raz nie posuwa usuwania: czeka dalej na B.
        let e = remove(&state, c.clone(), &id_a, pin("1234"), quiet())
            .await
            .unwrap_err();
        assert!(e.contains("nie jest zarejestrowany"), "{e}");
        let done = remove(&state, b.clone(), &id_a, pin("1234"), quiet())
            .await
            .unwrap();
        assert_eq!(names(&done), ["B", "C"]);
        assert!(done.removal.is_none());
        assert_eq!(b_dev.touches() - b_before, 2);
        assert_eq!(c_dev.touches() - c_before, 2);
        // Usunięty klucz nie otwiera pliku, pozostałe otwierają.
        lock(&state).await;
        for (key, ok) in [(&a, false), (&b, true), (&c, true)] {
            crate::commands::unlock_with(&state, HASLO.into(), Some(key.clone()))
                .await
                .unwrap_err();
            let r = finish_unlock(&state, key.clone(), pin("1234")).await;
            assert_eq!(r.is_ok(), ok, "{r:?}");
            lock(&state).await;
        }
        crate::commands::unlock_with(&state, HASLO.into(), Some(b.clone()))
            .await
            .unwrap_err();
        finish_unlock(&state, b.clone(), pin("1234")).await.unwrap();

        // Porzucone usuwanie nie zostawia śladu.
        let two = status(&state, Some(&b)).await.unwrap();
        let (id_b, id_c) = (id_of(&two, "B"), id_of(&two, "C"));
        let pending = remove(&state, b.clone(), &id_c, pin("1234"), quiet())
            .await
            .unwrap();
        assert_eq!(names(&pending), ["B"]);
        // Dwa klucze: usunięcie jednego kończy się na dotknięciu drugiego.
        assert!(pending.removal.is_none());
        // Ostatni klucz: trzeba go dotknąć, cudzy klucz nie wystarczy.
        let e = remove(&state, c.clone(), &id_b, pin("1234"), quiet())
            .await
            .unwrap_err();
        assert!(e.contains("nie jest zarejestrowany"), "{e}");
        assert_eq!(version(&state), vault::FORMAT_PROTECTED);
        let none = remove(&state, b.clone(), &id_b, pin("1234"), quiet())
            .await
            .unwrap();
        assert!(none.keys.is_empty());
        assert_eq!(version(&state), vault::FORMAT_VERSION);
        Vault::open::<Document>(state.path.clone(), HASLO).unwrap();
        let e = remove(&state, b.clone(), &id_b, pin("1234"), quiet())
            .await
            .unwrap_err();
        assert!(e.contains("nie ma kluczy"), "{e}");
        let _ = a_dev;
    }

    #[tokio::test]
    async fn key_then_totp_and_format_version() {
        let d = dir("totp");
        let state = unlocked_state(&d).await;
        let (_, a) = soft(1);
        let secret = b"12345678901234567890".to_vec();
        let code = |now: u64| format!("{:06}", mfa::code_at(&secret, now / mfa::PERIOD));
        let totp = Totp::new(secret.clone(), &[]);
        state
            .mutate(|doc| {
                doc.mfa.totp = Some(totp);
                Ok(())
            })
            .await
            .unwrap();
        let one = add(&state, a.clone(), pin("1234"), "A", quiet())
            .await
            .unwrap();
        lock(&state).await;
        // Kolejność: hasło, klucz, kod.
        let e = crate::commands::unlock_with(&state, HASLO.into(), Some(a.clone()))
            .await
            .unwrap_err();
        assert_eq!(e, "NEEDS_KEY:app");
        let e = crate::mfa::finish_unlock(&state, &code(NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw"), "{e}");
        let e = finish_unlock(&state, a.clone(), pin("1234"))
            .await
            .unwrap_err();
        assert_eq!(e, crate::mfa::NEEDS_TOTP);
        assert!(!is_unlocked(&state).await);
        crate::mfa::finish_unlock(&state, &code(NOW), NOW)
            .await
            .unwrap();
        assert!(is_unlocked(&state).await);
        // Po usunięciu ostatniego klucza plik zostaje w wersji 2, bo dalej wymaga kodu.
        remove(&state, a.clone(), &one.keys[0].id, pin("1234"), quiet())
            .await
            .unwrap();
        assert_eq!(version(&state), vault::FORMAT_PROTECTED);
        state
            .mutate(|doc| {
                doc.mfa.totp = None;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(version(&state), vault::FORMAT_VERSION);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backups_of_a_keyed_file() {
        let d = dir("kopie");
        let state = unlocked_state(&d).await;
        let (_, a) = soft(1);
        let (_, b) = soft(2);
        let toggle = |doc: &mut Document| {
            doc.settings.confirm_quit = !doc.settings.confirm_quit;
            Ok(())
        };
        // Kopia nr 1 po dodaniu klucza to plik sprzed klucza: otwiera ją samo hasło.
        add(&state, a.clone(), pin("1234"), "A", quiet())
            .await
            .unwrap();
        crate::maintenance::read_backup(&state, 1, HASLO.into())
            .await
            .unwrap();
        // Kopia z tą samą listą kluczy czyta się bez dotykania klucza.
        state.mutate(toggle).await.unwrap();
        crate::maintenance::read_backup(&state, 1, HASLO.into())
            .await
            .unwrap();
        let e = crate::maintenance::read_backup(&state, 1, "inne-haslo".into())
            .await
            .unwrap_err();
        assert!(e.contains("Nieprawidłowe hasło"), "{e}");
        // Po zmianie listy kluczy starsza kopia z kluczem jest nie do odczytania.
        add(&state, b.clone(), pin("1234"), "B", quiet())
            .await
            .unwrap();
        let e = crate::maintenance::read_backup(&state, 1, HASLO.into())
            .await
            .unwrap_err();
        assert!(e.contains("inną listę kluczy"), "{e}");
    }
}
