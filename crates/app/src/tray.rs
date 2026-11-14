//! Zasobnik systemowy: trzy stany ikony (bezczynny, aktywne sesje, zablokowany) i krótkie menu.

use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

use crate::state::AppState;

const IDLE: &[u8] = include_bytes!("../icons/tray-idle.png");
const ACTIVE: &[u8] = include_bytes!("../icons/tray-active.png");
const LOCKED: &[u8] = include_bytes!("../icons/tray-locked.png");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Idle,
    Active,
    Locked,
}

fn icon(kind: Kind) -> tauri::Result<Image<'static>> {
    Image::from_bytes(match kind {
        Kind::Idle => IDLE,
        Kind::Active => ACTIVE,
        Kind::Locked => LOCKED,
    })
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Pokaż okno", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Zablokuj plik", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Zakończ", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &lock, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(icon(Kind::Locked)?)
        .tooltip("Menedżer sesji")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "lock" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<AppState>();
                    crate::commands::lock_all(
                        &app,
                        &state,
                        "zablokowano plik z hostami (zasobnik)",
                    )
                    .await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    // Stan ikony wynika z blokady i liczby sesji; sprawdzany co sekundę, ikona zmienia się tylko przy zmianie.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last: Option<Kind> = None;
        loop {
            let state = handle.state::<AppState>();
            let unlocked = state.inner.lock().await.is_some();
            let sessions = state.sessions.lock().expect("sessions").len()
                + state.rdp.lock().expect("rdp").len();
            let kind = if !unlocked {
                Kind::Locked
            } else if sessions > 0 {
                Kind::Active
            } else {
                Kind::Idle
            };
            if last != Some(kind) {
                if let (Some(tray), Ok(img)) = (handle.tray_by_id("main"), icon(kind)) {
                    let _ = tray.set_icon(Some(img));
                    let _ = tray.set_tooltip(Some(match kind {
                        Kind::Locked => "Menedżer sesji: zablokowany",
                        Kind::Active => "Menedżer sesji: aktywne sesje",
                        Kind::Idle => "Menedżer sesji",
                    }));
                }
                last = Some(kind);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    Ok(())
}
