//! Kontrola przepływu strumienia do interfejsu (obraz RDP, wyjście terminala SSH).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

/// Okno obrazu RDP: dwa pełne ekrany 4K.
pub const RDP_WINDOW: u64 = 64 * 1024 * 1024;
/// Okno wyjścia terminala SSH. Terminal przetwarza dane wolniej od sieci (np. `cat` dużego pliku),
/// a wiele sesji naraz nie powinno zajmować pamięci ponad miarę.
pub const SSH_WINDOW: u64 = 4 * 1024 * 1024;

/// Kontrola przepływu jednej sesji. Kanał do interfejsu nie ma limitu, więc bez niej wolno
/// rysujący interfejs (albo szybko zmieniający się ekran, szybko płynący terminal) powodowałby
/// nieograniczony wzrost pamięci. Pętla sesji liczy wysłane bajty, interfejs potwierdza odebrane
/// (`rdp_ack`, `ssh_ack`), a po przekroczeniu okna pętla przestaje odbierać zdarzenia ze źródła,
/// co przez kolejkę, potok i sieć spowalnia sam serwer.
pub struct Flow {
    window: u64,
    outstanding: AtomicU64,
    acked: Notify,
}

impl Flow {
    pub fn new(window: u64) -> Self {
        Self {
            window,
            outstanding: AtomicU64::new(0),
            acked: Notify::new(),
        }
    }

    pub fn sent(&self, bytes: u64) {
        self.outstanding.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Interfejs odebrał `bytes` bajtów. Nadmiarowe potwierdzenie zeruje licznik.
    pub fn ack(&self, bytes: u64) {
        // Odejmowanie z nasyceniem w pętli `compare_exchange`: działa na każdej wersji kompilatora
        // (`fetch_update` jest przestarzałe od Rust 1.100, a jego następcy nie ma w starszych).
        let mut current = self.outstanding.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.outstanding.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        self.acked.notify_one();
    }

    fn congested(&self) -> bool {
        self.outstanding.load(Ordering::Relaxed) > self.window
    }

    /// Czeka, aż w oknie będzie miejsce. Zwraca `false`, gdy sesja w tym czasie przestała istnieć
    /// (`alive` jest sprawdzane co 250 ms, żeby zamknięcie sesji nie zostawiło pętli w zawieszeniu).
    pub async fn wait(&self, alive: impl Fn() -> bool) -> bool {
        while self.congested() {
            if !alive() {
                return false;
            }
            let _ = tokio::time::timeout(Duration::from_millis(250), self.acked.notified()).await;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn image_flow_waits_for_acks_and_stops_when_session_is_gone() {
        let flow = Flow::new(RDP_WINDOW);
        // W oknie: bez czekania, także dokładnie na granicy.
        flow.sent(RDP_WINDOW);
        assert!(!flow.congested());
        assert!(flow.wait(|| true).await);
        // Ponad okno: czekanie trwa do potwierdzenia.
        flow.sent(1);
        assert!(flow.congested());
        let waiting = tokio::time::timeout(Duration::from_millis(100), flow.wait(|| true)).await;
        assert!(waiting.is_err(), "bez potwierdzenia pętla czeka");
        flow.ack(1024);
        assert!(flow.wait(|| true).await);
        // Sesja zniknęła w trakcie zatoru: czekanie kończy się wynikiem `false`.
        flow.sent(RDP_WINDOW);
        assert!(!flow.wait(|| false).await);
        // Nadmiarowe potwierdzenie nie przekręca licznika.
        flow.ack(u64::MAX);
        assert!(!flow.congested());
        assert!(flow.wait(|| true).await);
    }

    #[tokio::test]
    async fn ssh_window_is_smaller_and_released_by_acks() {
        assert_eq!(SSH_WINDOW, 4 * 1024 * 1024);
        const { assert!(SSH_WINDOW < RDP_WINDOW) };
        let flow = Flow::new(SSH_WINDOW);
        flow.sent(SSH_WINDOW);
        assert!(
            flow.wait(|| true).await,
            "dokładnie okno jeszcze mieści się"
        );
        flow.sent(1);
        let waiting = tokio::time::timeout(Duration::from_millis(100), flow.wait(|| true)).await;
        assert!(waiting.is_err());
        // Potwierdzenie przychodzące w trakcie czekania budzi pętlę.
        let flow = std::sync::Arc::new(flow);
        let f = flow.clone();
        let waiter = tokio::spawn(async move { f.wait(|| true).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        flow.ack(4096);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiter)
                .await
                .unwrap()
                .unwrap()
        );
        // Zamknięcie sesji przerywa czekanie.
        flow.sent(SSH_WINDOW);
        assert!(!flow.wait(|| false).await);
    }
}
