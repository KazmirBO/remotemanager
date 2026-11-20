//! Automatyczna blokada pliku z hostami po bezczynności. Licznik jest w backendzie: przeżywa
//! przeładowanie interfejsu i widzi klawisze z haka Windows, które nie docierają do okna.

use std::time::{Duration, Instant, SystemTime};

use tauri::{AppHandle, Manager, State};

use crate::state::AppState;

pub struct Activity {
    mono: Instant,
    wall: SystemTime,
}

impl Activity {
    pub fn now() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// Dłuższy z czasów według zegara monotonicznego i ściennego (monotoniczny na Linuksie stoi
    /// w czasie uśpienia); cofnięty zegar ścienny liczy się jako 0.
    pub fn idle_for(&self) -> Duration {
        let mono = self.mono.elapsed();
        let wall = SystemTime::now()
            .duration_since(self.wall)
            .unwrap_or(Duration::ZERO);
        mono.max(wall)
    }
}

/// Czy po `idle` bezczynności przy ustawieniu `minutes` trzeba zablokować plik.
pub fn should_lock(minutes: u16, idle: Duration) -> bool {
    minutes > 0 && idle >= Duration::from_secs(u64::from(minutes) * 60)
}

/// Zadanie sprawdzające co 5 s, czy minął czas bezczynności.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let state = app.state::<AppState>();
            // Zajęta blokada: pomijamy ten obrót. Brak dokumentu: plik już jest zablokowany.
            let minutes = match state.inner.try_lock() {
                Ok(g) => g.as_ref().map(|u| u.doc.settings.auto_lock_minutes),
                Err(_) => continue,
            };
            let Some(minutes) = minutes else { continue };
            let idle = state.activity.lock().expect("activity").idle_for();
            if should_lock(minutes, idle) {
                crate::commands::lock_all(&app, &state, "zablokowano plik z hostami (bezczynność)")
                    .await;
            }
        }
    });
}

/// Interfejs zgłasza aktywność (klawiatura, mysz w oknie programu).
#[tauri::command]
pub fn user_activity(state: State<'_, AppState>) {
    state.touch_activity();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_threshold() {
        assert!(!should_lock(0, Duration::from_secs(36000)));
        assert!(!should_lock(5, Duration::from_secs(299)));
        assert!(should_lock(5, Duration::from_secs(300)));
    }

    #[test]
    fn fresh_activity_is_not_idle() {
        assert!(Activity::now().idle_for() < Duration::from_secs(5));
    }
}
