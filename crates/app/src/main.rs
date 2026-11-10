// Konsolowe okno na Windows jest zbędne w wersji release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod clipboard;
mod commands;
mod config;
mod dto;
mod maintenance;
mod rdp_sessions;
mod session_log;
mod sessions;
mod state;
mod tray;

/// Link `ssh://` albo `rdp://` z listy argumentów.
fn link_in(args: impl IntoIterator<Item = String>) -> Option<String> {
    args.into_iter().find(|a| {
        let l = a.to_ascii_lowercase();
        l.starts_with("ssh://") || l.starts_with("rdp://")
    })
}

fn main() {
    tauri::Builder::default()
        // Musi być pierwsza: kolejne uruchomienie przekazuje link działającemu oknu i kończy się.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            use tauri::{Emitter, Manager};
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
            if let Some(url) = link_in(argv.into_iter().skip(1)) {
                *app.state::<state::AppState>()
                    .pending_link
                    .lock()
                    .expect("pending") = Some(url);
                let _ = app.emit("open-link", ());
            }
        }))
        .setup(|app| {
            use tauri::Manager;
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            // Pliki pobrane przez schowek RDP z poprzednich uruchomień nie są już potrzebne.
            let _ = std::fs::remove_dir_all(dir.join("clip"));
            let state = state::AppState::new(dir.join("hosts.mrm"));
            // Link ssh:// albo rdp:// z wiersza poleceń czeka na odblokowanie pliku.
            *state.pending_link.lock().expect("pending") = std::env::args().skip(1).find(|a| {
                a.to_ascii_lowercase().starts_with("ssh://")
                    || a.to_ascii_lowercase().starts_with("rdp://")
            });
            app.manage(state);
            tray::setup(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_state,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::change_password,
            commands::get_doc,
            commands::save_folder,
            commands::save_host,
            commands::delete_folder,
            commands::delete_host,
            commands::move_host,
            commands::move_folder,
            commands::set_favorite,
            commands::resolve_host,
            commands::save_settings,
            sessions::connect_ssh,
            sessions::ssh_write,
            sessions::ssh_resize,
            sessions::ssh_close,
            maintenance::sync_status,
            maintenance::sync_set_folder,
            maintenance::sync_run,
            maintenance::list_backups,
            maintenance::restore_backup,
            maintenance::get_diagnostics,
            maintenance::clear_diagnostics,
            maintenance::get_local_config,
            maintenance::set_log_sessions,
            maintenance::set_rdp_clipboard,
            maintenance::resolve_link,
            maintenance::take_pending_link,
            sessions::answer_trust,
            rdp_sessions::connect_rdp,
            rdp_sessions::rdp_send,
            rdp_sessions::rdp_close,
            rdp_sessions::rdp_clipboard_focus,
        ])
        .run(tauri::generate_context!())
        .expect("błąd uruchamiania aplikacji");
}
