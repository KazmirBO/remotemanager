use model::{Document, Id, Protocol, Settings, StoredKey};
use tauri::State;
use vault::{KdfParams, Vault};

use crate::dto::{DocView, FieldsIo, FolderInput, FolderView, HostInput, HostView};
use crate::state::{AppState, Unlocked};

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Mapuje błędy vaulta na komunikaty dla użytkownika.
fn vault_err(e: vault::Error) -> String {
    match e {
        vault::Error::Decrypt => "Nieprawidłowe hasło główne albo uszkodzony plik.".into(),
        other => other.to_string(),
    }
}

/// Błąd odblokowania; przy błędzie odszyfrowania, gdy obok pliku leży kopia sprzed ostatniego
/// pobrania przy synchronizacji, komunikat wskazuje jej pełną ścieżkę.
fn unlock_err(e: vault::Error, path: &std::path::Path) -> String {
    let decrypt = matches!(e, vault::Error::Decrypt);
    let msg = vault_err(e);
    let copy = sync::pre_pull_copy(path);
    if decrypt && copy.exists() {
        format!(
            "{msg} Wersja sprzed ostatniego pobrania przy synchronizacji leży w pliku: {}",
            copy.display()
        )
    } else {
        msg
    }
}

#[tauri::command]
pub async fn vault_state(state: State<'_, AppState>) -> Result<&'static str, String> {
    if state.inner.lock().await.is_some() {
        Ok("unlocked")
    } else if state.path.exists() {
        Ok("locked")
    } else {
        Ok("missing")
    }
}

#[tauri::command]
pub async fn create_vault(state: State<'_, AppState>, password: String) -> Result<(), String> {
    if password.chars().count() < 8 {
        return Err("Hasło główne musi mieć co najmniej 8 znaków.".into());
    }
    let path = state.path.clone();
    let doc = Document::default();
    let (vault, doc) = tokio::task::spawn_blocking(move || {
        Vault::create(path, &password, KdfParams::DEFAULT, &doc).map(|v| (v, doc))
    })
    .await
    .map_err(err)?
    .map_err(vault_err)?;
    *state.inner.lock().await = Some(Unlocked { vault, doc });
    Ok(())
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<(), String> {
    let path = state.path.clone();
    let (vault, doc) =
        tokio::task::spawn_blocking(move || Vault::open::<Document>(path, &password))
            .await
            .map_err(err)?
            .map_err(|e| unlock_err(e, &state.path))?;
    *state.inner.lock().await = Some(Unlocked { vault, doc });
    state.log("odblokowano plik z hostami");
    Ok(())
}

#[tauri::command]
pub async fn lock(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    lock_all(&app, &state, "zablokowano plik z hostami").await;
    Ok(())
}

/// Blokada pliku z dowolnego miejsca (komenda, zasobnik): usuwa klucz z pamięci, zamyka sesje SSH
/// i RDP wraz z pytaniami o zaufanie, a na końcu emituje `vault-locked`, żeby interfejs schował
/// drzewo i karty.
pub async fn lock_all(app: &tauri::AppHandle, state: &AppState, log: &str) {
    use tauri::Emitter;
    // Kolejność jest celowa: najpierw znika klucz w pamięci, potem anulowane są pytania o zaufanie
    // i zamykane sesje. Połączenie, które skończy się po opróżnieniu map, zobaczy już zablokowany plik.
    *state.inner.lock().await = None;
    close_all_sessions(state).await;
    state.log(log);
    let _ = app.emit("vault-locked", ());
}

/// Anuluje pytania o zaufanie i zamyka wszystkie sesje SSH i RDP, nie ruszając blokady pliku.
/// Sesje są najpierw wyjmowane z map, a dopiero potem zamykane: pętle sesji kończą się przez brak
/// wpisu w mapie. Zwraca liczbę zamkniętych sesji.
pub async fn close_all_sessions(state: &AppState) -> usize {
    state.cancel_trust();
    // Przechwytywanie klawiszy należy do sesji RDP: musi zniknąć razem z nimi (na Windows
    // zapomniany hak zatrzymywałby całą klawiaturę, dopóki okno jest na pierwszym planie).
    state.keys.release_all();
    let ssh: Vec<_> = state
        .sessions
        .lock()
        .expect("sessions")
        .drain()
        .map(|(_, l)| l)
        .collect();
    let rdp: Vec<_> = state
        .rdp
        .lock()
        .expect("rdp")
        .drain()
        .map(|(_, c)| c)
        .collect();
    let count = ssh.len() + rdp.len();
    for c in rdp {
        c.close();
    }
    for l in ssh {
        let _ = l.shell.close().await;
        l.session.disconnect().await;
    }
    count
}

/// Początek ładowania strony w głównym oknie. Po przeładowaniu (F5, Ctrl+R, menu WebView) nowy
/// interfejs nie ma uchwytów do działających sesji, więc zostałyby osierocone. Plik zostaje
/// odblokowany. Pierwsze ładowanie przy starcie nie ma sesji i nie ma skutków ubocznych.
pub async fn reset_after_reload(state: &AppState) {
    use std::sync::atomic::Ordering;
    // Najpierw licznik, potem mapy: połączenie w toku widzi zmianę po wstawieniu sesji do mapy.
    state.reloads.fetch_add(1, Ordering::SeqCst);
    let closed = close_all_sessions(state).await;
    if closed > 0 {
        state.log(format!(
            "przeładowano interfejs: zamknięto sesje ({closed})"
        ));
    }
}

#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    old: String,
    new: String,
) -> Result<(), String> {
    if new.chars().count() < 8 {
        return Err("Nowe hasło musi mieć co najmniej 8 znaków.".into());
    }
    // Sprawdzenie starego hasła osobnym otwarciem pliku, żeby nie zaufać samemu stanowi sesji.
    let path = state.path.clone();
    tokio::task::spawn_blocking(move || Vault::open::<Document>(path, &old).map(|_| ()))
        .await
        .map_err(err)?
        .map_err(vault_err)?;
    let mut guard = state.inner.lock().await;
    let u = guard.as_mut().ok_or("Plik z hostami jest zablokowany")?;
    let pre = state.sync_pre();
    // Argon2 (ok. 64 MiB) liczy się długo: `block_in_place` nie zatrzymuje innych zadań tokio.
    tokio::task::block_in_place(|| u.vault.change_password(&new, &u.doc)).map_err(vault_err)?;
    state.sync_post(pre);
    state.log("zmieniono hasło główne");
    Ok(())
}

/// Zmiana nie może zepsuć łańcucha bastionów hosta, który przed nią działał (cykl, bastion RDP,
/// bastion poza drzewem). Hosty zepsute wcześniej nie blokują niezwiązanych zmian.
fn check_jumps(before: &model::Tree, after: &model::Tree) -> Result<(), String> {
    for h in &after.hosts {
        if before.host(h.id).is_some() && before.jump_chain(h.id).is_err() {
            continue;
        }
        if let Err(e) = after.jump_chain(h.id) {
            return Err(format!(
                "Zmiana psuje łańcuch bastionów hosta {}: {e}.",
                h.name
            ));
        }
    }
    Ok(())
}

fn view(doc: &Document) -> DocView {
    DocView {
        folders: doc.tree.folders.iter().map(FolderView::from).collect(),
        hosts: doc.tree.hosts.iter().map(HostView::from).collect(),
        settings: doc.settings.clone(),
        trusted_count: doc.trusted_keys.len(),
    }
}

#[tauri::command]
pub async fn get_doc(state: State<'_, AppState>) -> Result<DocView, String> {
    state.read(|d| Ok(view(d))).await
}

/// Importuje klucz z wejścia poza blokadą dokumentu (KDF klucza bywa wolny).
async fn prepare_input<T: Send + 'static>(
    mut input: T,
    fields: fn(&mut T) -> &mut FieldsIo,
) -> Result<(T, Option<StoredKey>), String> {
    let (input, imported) = tokio::task::spawn_blocking(move || {
        let r = fields(&mut input).prepare();
        (input, r)
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok((input, imported?))
}

/// Do dziennika trafiają tylko algorytm i odcisk, nigdy tekst klucza.
fn import_summary(key: Option<&StoredKey>) -> Option<(String, String)> {
    key.map(|k| (k.algorithm.clone(), k.fingerprint.clone()))
}

fn log_import(state: &AppState, key: Option<(String, String)>, what: &str, name: &str) {
    if let Some((algorithm, fingerprint)) = key {
        state.log(format!(
            "Zaimportowano klucz SSH ({algorithm} {fingerprint}) dla {what} „{name}”"
        ));
    }
}

#[tauri::command]
pub async fn save_folder(state: State<'_, AppState>, input: FolderInput) -> Result<Id, String> {
    if input.name.trim().is_empty() {
        return Err("Nazwa katalogu nie może być pusta.".into());
    }
    let (input, imported) = prepare_input(input, |i| &mut i.fields).await?;
    let name = input.name.trim().to_owned();
    let logged = import_summary(imported.as_ref());
    let id = state
        .mutate(|doc| {
            let before = doc.tree.clone();
            let id = match input.id {
                Some(id) => {
                    let existing = doc
                        .tree
                        .folder(id)
                        .ok_or("Nie ma takiego katalogu")?
                        .clone();
                    if existing.parent != input.parent {
                        doc.tree.move_folder(id, input.parent).map_err(err)?;
                    }
                    id
                }
                None => doc
                    .tree
                    .add_folder(input.name.trim(), input.parent)
                    .map_err(err)?,
            };
            let f = doc
                .tree
                .folders
                .iter_mut()
                .find(|f| f.id == id)
                .expect("istnieje");
            f.name = input.name.trim().to_owned();
            f.fields = input.fields.apply(&f.fields, imported);
            check_jumps(&before, &doc.tree)?;
            Ok(id)
        })
        .await?;
    log_import(&state, logged, "katalogu", &name);
    Ok(id)
}

#[tauri::command]
pub async fn save_host(state: State<'_, AppState>, mut input: HostInput) -> Result<Id, String> {
    if input.name.trim().is_empty() || input.address.trim().is_empty() {
        return Err("Nazwa i adres hosta są wymagane.".into());
    }
    // Formularz RDP nie pokazuje sekcji klucza, więc wklejony wcześniej tekst (przed zmianą
    // protokołu) nie może trafić do pliku jako ukryty sekret.
    if input.protocol == Protocol::Rdp {
        input.fields.ssh_key = None;
        input.fields.ssh_key_passphrase = None;
        // Ukryta ścieżka klucza nie może blokować zapisu błędem o niewidocznym polu.
        input.fields.ssh_key_path = None;
        // To samo dotyczy ukrytego typu terminala.
        input.fields.ssh_term = None;
    }
    let (input, imported) = prepare_input(input, |i| &mut i.fields).await?;
    let name = input.name.trim().to_owned();
    let logged = import_summary(imported.as_ref());
    let id = state
        .mutate(|doc| {
            let before = doc.tree.clone();
            let id = match input.id {
                Some(id) => {
                    doc.tree.host(id).ok_or("Nie ma takiego hosta")?;
                    doc.tree.move_host(id, input.folder).map_err(err)?;
                    id
                }
                None => doc
                    .tree
                    .add_host(
                        input.name.trim(),
                        input.address.trim(),
                        input.protocol,
                        input.folder,
                    )
                    .map_err(err)?,
            };
            let h = doc
                .tree
                .hosts
                .iter_mut()
                .find(|h| h.id == id)
                .expect("istnieje");
            h.name = input.name.trim().to_owned();
            h.address = input.address.trim().to_owned();
            h.protocol = input.protocol;
            h.notes = input.notes;
            h.fields = input.fields.apply(&h.fields, imported);
            // Bastion nie może prowadzić do cyklu ani zepsuć łańcuchów innych hostów (np. zmiana
            // protokołu bastionu na RDP).
            doc.tree.jump_chain(id).map_err(err)?;
            check_jumps(&before, &doc.tree)?;
            Ok(id)
        })
        .await?;
    log_import(&state, logged, "hosta", &name);
    Ok(id)
}

#[tauri::command]
pub async fn delete_folder(state: State<'_, AppState>, id: Id) -> Result<usize, String> {
    state
        .mutate(|doc| doc.tree.remove_folder(id).map(|h| h.len()).map_err(err))
        .await
}

#[tauri::command]
pub async fn delete_host(state: State<'_, AppState>, id: Id) -> Result<(), String> {
    state
        .mutate(|doc| doc.tree.remove_host(id).map(|_| ()).map_err(err))
        .await
}

#[tauri::command]
pub async fn move_host(
    state: State<'_, AppState>,
    id: Id,
    folder: Option<Id>,
) -> Result<(), String> {
    state
        .mutate(|doc| {
            let before = doc.tree.clone();
            doc.tree.move_host(id, folder).map_err(err)?;
            check_jumps(&before, &doc.tree)
        })
        .await
}

#[tauri::command]
pub async fn move_folder(
    state: State<'_, AppState>,
    id: Id,
    parent: Option<Id>,
) -> Result<(), String> {
    state
        .mutate(|doc| {
            let before = doc.tree.clone();
            doc.tree.move_folder(id, parent).map_err(err)?;
            check_jumps(&before, &doc.tree)
        })
        .await
}

#[tauri::command]
pub async fn set_favorite(
    state: State<'_, AppState>,
    id: Id,
    favorite: bool,
) -> Result<(), String> {
    state
        .mutate(|doc| {
            doc.tree
                .hosts
                .iter_mut()
                .find(|h| h.id == id)
                .ok_or("Nie ma takiego hosta")?
                .favorite = favorite;
            Ok(())
        })
        .await
}

#[tauri::command]
pub async fn save_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    validate_settings(&settings)?;
    state
        .mutate(|doc| {
            doc.settings = settings;
            Ok(())
        })
        .await
}

/// Sprawdza ustawienia przed zapisem: motyw, schemat terminala, skróty i rozmiar czcionki.
fn validate_settings(settings: &Settings) -> Result<(), String> {
    if !matches!(settings.theme.as_str(), "dark" | "light" | "system") {
        return Err("Nieznany motyw.".into());
    }
    if !matches!(
        settings.terminal_scheme.as_str(),
        "domyslny" | "szary" | "kontrast"
    ) {
        return Err("Nieznany schemat terminala.".into());
    }
    if settings.shortcuts.len() > 64
        || settings
            .shortcuts
            .iter()
            .any(|(k, v)| k.len() > 64 || v.len() > 64 || v.is_empty())
    {
        return Err("Nieprawidłowe skróty klawiszowe.".into());
    }
    if !(9..=32).contains(&settings.terminal_font_size) {
        return Err("Rozmiar czcionki terminala musi być liczbą od 9 do 32.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{Protocol, Tree};

    #[test]
    fn folder_change_that_creates_bastion_cycle_is_rejected() {
        let mut t = Tree::default();
        let fa = t.add_folder("A", None).unwrap();
        let fb = t.add_folder("B", None).unwrap();
        let a = t.add_host("a", "a", Protocol::Ssh, Some(fa)).unwrap();
        let b = t.add_host("b", "b", Protocol::Ssh, Some(fb)).unwrap();
        t.hosts
            .iter_mut()
            .find(|h| h.id == a)
            .unwrap()
            .fields
            .jump_host = Some(b);
        let before = t.clone();
        // Katalog z bastionem B dostaje bastion A: A -> B -> A.
        t.folders
            .iter_mut()
            .find(|f| f.id == fb)
            .unwrap()
            .fields
            .jump_host = Some(a);
        let e = check_jumps(&before, &t).unwrap_err();
        assert!(e.contains("cykl"), "{e}");
    }

    #[test]
    fn settings_validation_rejects_bad_values() {
        assert!(validate_settings(&Settings::default()).is_ok());

        let with_size = |terminal_font_size| Settings {
            terminal_font_size,
            ..Settings::default()
        };
        assert!(validate_settings(&with_size(8)).is_err());
        assert!(validate_settings(&with_size(33)).is_err());
        assert!(validate_settings(&with_size(9)).is_ok());
        assert!(validate_settings(&with_size(32)).is_ok());

        let unknown_theme = Settings {
            theme: "neon".into(),
            ..Settings::default()
        };
        assert!(validate_settings(&unknown_theme).is_err());

        let unknown_scheme = Settings {
            terminal_scheme: "nieznany".into(),
            ..Settings::default()
        };
        assert!(validate_settings(&unknown_scheme).is_err());
    }

    #[test]
    fn already_broken_host_does_not_block_unrelated_changes() {
        let mut t = Tree::default();
        let x = t.add_host("x", "x", Protocol::Ssh, None).unwrap();
        t.hosts[0].fields.jump_host = Some(uuid::Uuid::new_v4());
        let before = t.clone();
        t.add_host("y", "y", Protocol::Ssh, None).unwrap();
        assert!(t.jump_chain(x).is_err());
        assert!(check_jumps(&before, &t).is_ok());
    }
}
