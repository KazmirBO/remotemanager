use model::{Document, Id, Settings};
use tauri::State;
use vault::{KdfParams, Vault};

use crate::dto::{DocView, FieldsIo, FolderInput, FolderView, HostInput, HostView, ResolvedView};
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
            .map_err(vault_err)?;
    *state.inner.lock().await = Some(Unlocked { vault, doc });
    state.log("odblokowano plik z hostami");
    Ok(())
}

#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Result<(), String> {
    *state.inner.lock().await = None;
    state.log("zablokowano plik z hostami");
    Ok(())
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
    u.vault.change_password(&new, &u.doc).map_err(vault_err)?;
    state.sync_post(pre);
    state.log("zmieniono hasło główne");
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

#[tauri::command]
pub async fn save_folder(state: State<'_, AppState>, input: FolderInput) -> Result<Id, String> {
    if input.name.trim().is_empty() {
        return Err("Nazwa katalogu nie może być pusta.".into());
    }
    state
        .mutate(|doc| {
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
            f.fields = input.fields.apply(&f.fields);
            Ok(id)
        })
        .await
}

#[tauri::command]
pub async fn save_host(state: State<'_, AppState>, input: HostInput) -> Result<Id, String> {
    if input.name.trim().is_empty() || input.address.trim().is_empty() {
        return Err("Nazwa i adres hosta są wymagane.".into());
    }
    state
        .mutate(|doc| {
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
            h.fields = input.fields.apply(&h.fields);
            // Bastion nie może prowadzić do cyklu.
            doc.tree.jump_chain(id).map_err(err)?;
            Ok(id)
        })
        .await
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
        .mutate(|doc| doc.tree.move_host(id, folder).map_err(err))
        .await
}

#[tauri::command]
pub async fn move_folder(
    state: State<'_, AppState>,
    id: Id,
    parent: Option<Id>,
) -> Result<(), String> {
    state
        .mutate(|doc| doc.tree.move_folder(id, parent).map_err(err))
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
pub async fn resolve_host(state: State<'_, AppState>, id: Id) -> Result<ResolvedView, String> {
    state
        .read(|doc| {
            let r = doc.tree.resolve(id).map_err(err)?;
            Ok(ResolvedView {
                fields: FieldsIo::view(&r.fields),
                sources: r.sources,
                port: r.port,
            })
        })
        .await
}

#[tauri::command]
pub async fn save_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    if !matches!(settings.theme.as_str(), "dark" | "light" | "system") {
        return Err("Nieznany motyw.".into());
    }
    state
        .mutate(|doc| {
            doc.settings = settings;
            Ok(())
        })
        .await
}
