// Konsolowe okno na Windows jest zbędne w wersji release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod clipboard;
mod commands;
mod config;
mod dto;
mod flow;
mod idle;
mod keys;
mod maintenance;
mod rdp_sessions;
mod session_log;
mod sessions;
mod state;
mod transfer;
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
        // Wyłącza rejestrację surowego wejścia (Raw Input) myszy i klawiatury, którą biblioteka okna
        // robi domyślnie na Windows. Dopóki proces ma zarejestrowane surowe wejście klawiatury,
        // system nie woła jego własnego haka `WH_KEYBOARD_LL`, gdy okno aplikacji jest aktywne, więc
        // przechwytywanie klawiszy sesji RDP (crate `keygrab`) nie widziało żadnego klawisza.
        // Aplikacja nie używa zdarzeń urządzeń; na pozostałych platformach ustawienie nic nie robi.
        .device_event_filter(tauri::DeviceEventFilter::Always)
        // Musi być pierwsza: kolejne uruchomienie przekazuje link działającemu oknu i kończy się.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            use tauri::{Emitter, Manager};
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
            // `try_state`: druga instancja może się zgłosić, zanim `setup` zarejestruje stan.
            if let (Some(url), Some(state)) = (
                link_in(argv.into_iter().skip(1)),
                app.try_state::<state::AppState>(),
            ) {
                *state.pending_link.lock().expect("pending") = Some(url);
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
            // `args_os`: argument z niepoprawnym UTF-8 nie może zatrzymać startu (std::env::args panikuje).
            *state.pending_link.lock().expect("pending") = link_in(
                std::env::args_os()
                    .skip(1)
                    .filter_map(|a| a.into_string().ok()),
            );
            app.manage(state);
            tray::setup(app.handle())?;
            idle::spawn(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            use tauri::Manager;
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                tauri::async_runtime::spawn(commands::request_quit(window.app_handle().clone()));
            }
        })
        .on_page_load(|webview, payload| {
            use tauri::{Manager, webview::PageLoadEvent};
            if webview.label() != "main" || !matches!(payload.event(), PageLoadEvent::Started) {
                return;
            }
            let app = webview.app_handle().clone();
            tauri::async_runtime::spawn(async move {
                // Przy pierwszym ładowaniu stan może jeszcze nie istnieć (`setup`): nie ma wtedy sesji.
                if let Some(state) = app.try_state::<state::AppState>() {
                    commands::reset_after_reload(&state).await;
                }
            });
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
            commands::save_settings,
            commands::answer_quit,
            idle::user_activity,
            maintenance::set_backup_count,
            clipboard::read_clipboard_text,
            sessions::connect_ssh,
            sessions::ssh_write,
            sessions::ssh_resize,
            sessions::ssh_ack,
            sessions::ssh_close,
            maintenance::sync_status,
            maintenance::sync_set_folder,
            maintenance::sync_run,
            maintenance::sync_diff,
            maintenance::list_backups,
            maintenance::restore_backup,
            maintenance::get_diagnostics,
            maintenance::clear_diagnostics,
            maintenance::get_local_config,
            maintenance::set_log_sessions,
            maintenance::set_rdp_clipboard,
            maintenance::set_check_updates,
            maintenance::open_releases_page,
            maintenance::resolve_link,
            maintenance::take_pending_link,
            transfer::export_default_path,
            transfer::export_hosts,
            transfer::import_preview,
            transfer::import_hosts,
            sessions::answer_trust,
            rdp_sessions::connect_rdp,
            rdp_sessions::rdp_send,
            rdp_sessions::rdp_ack,
            rdp_sessions::rdp_close,
            rdp_sessions::rdp_clipboard_focus,
            keys::rdp_grab_keys,
        ])
        .run(tauri::generate_context!())
        .expect("błąd uruchamiania aplikacji");
}
