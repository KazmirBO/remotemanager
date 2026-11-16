//! Przechwytywanie wszystkich klawiszy (także systemowych: Win, Alt+Tab, Ctrl+Esc) dla sesji
//! zdalnego pulpitu, na Windows niskopoziomowym hakiem klawiatury (`WH_KEYBOARD_LL`).
//!
//! Ten crate jest wyjątkiem od workspace'owego zakazu `unsafe` (`unsafe_code = "forbid"`):
//! założenie haka i odczyt struktury `KBDLLHOOKSTRUCT` wymagają wywołań WinAPI. Cały `unsafe`
//! siedzi w jednym, cienkim module `win` (tylko Windows); decyzje podejmuje czysty, niezależny
//! od platformy moduł `logic`, pokryty testami uruchamianymi na każdej platformie.

mod logic;
#[cfg(windows)]
mod win;

use std::fmt;

/// Skrót zwalniający przechwytywanie: klawisz plus dokładny zestaw modyfikatorów (lewy i prawy
/// liczą się tak samo). Scancody jak w `app/ui/src/lib/scancodes.ts` (zestaw 1, RDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Combo {
    pub scancode: u8,
    pub extended: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub meta: bool,
}

/// Zdarzenie klawisza w kodowaniu RDP: scancode zestawu 1 i znacznik klawisza rozszerzonego (E0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub scancode: u8,
    pub extended: bool,
    pub down: bool,
}

/// Powód, dla którego przechwytywanie przestało zatrzymywać klawisze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// Naciśnięto skrót zwalniający.
    Combo,
    /// Okno przestało być na pierwszym planie.
    Foreground,
    /// Hak prawdopodobnie został usunięty przez system (wywołanie zajęło za długo).
    HookLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Key(Key),
    Released(Released),
}

/// Odbiorca zdarzeń. Jest wołany bezpośrednio z funkcji haka, w wątku z pętlą komunikatów, a
/// system po cichu usuwa hak, którego wywołanie trwa zbyt długo (domyślnie ok. 300 ms, najwyżej
/// 1 s). Dlatego implementacja MUSI być nieblokująca: bez I/O, bez czekania na blokadę i bez
/// długich obliczeń; wystarczy włożyć zdarzenie do kanału. Nie wolno z niej wołać `stop()`
/// (blokada stanu jest wtedy już zajęta); `stop()` woła się po otrzymaniu `Event::Released`
/// z innego kontekstu.
pub type Sink = Box<dyn Fn(Event) + Send + Sync + 'static>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Ta platforma nie pozwala przejąć klawiszy systemowych.
    Unsupported,
    /// Przechwytywanie jest już włączone.
    AlreadyActive,
    /// System odmówił założenia haka (kod błędu systemu).
    HookFailed(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported => {
                write!(
                    f,
                    "Przechwytywanie klawiszy systemowych działa tylko w Windows"
                )
            }
            Error::AlreadyActive => write!(f, "Przechwytywanie klawiszy jest już włączone"),
            Error::HookFailed(code) => write!(
                f,
                "Nie udało się założyć haka klawiatury (kod błędu systemu: {code})"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Czy ta platforma potrafi przejąć klawisze systemowe (tylko Windows).
pub fn supported() -> bool {
    cfg!(windows)
}

/// Włącza przechwytywanie dla okna (`window` to uchwyt HWND jako `isize`). Wołać z wątku z pętlą
/// komunikatów okna: system woła hak w wątku, który go założył. Modyfikatory wciśnięte przed
/// `start` nie są znane (śledzimy tylko to, co hak sam zobaczył), więc skrót zwalniający
/// zadziała po ich ponownym naciśnięciu.
pub fn start(window: isize, release: Option<Combo>, sink: Sink) -> Result<(), Error> {
    #[cfg(windows)]
    {
        win::start(window, release, sink)
    }
    #[cfg(not(windows))]
    {
        let _ = (window, release, sink);
        Err(Error::Unsupported)
    }
}

/// Wyłącza przechwytywanie; idempotentne. Po powrocie `sink` nie jest już wołany.
pub fn stop() {
    #[cfg(windows)]
    win::stop();
}

/// Czy przechwytywanie jest teraz aktywne, czyli hak istnieje i nadal zatrzymuje klawisze (po
/// `Event::Released` zwraca false, dopóki wywołujący nie zawoła `stop()`).
pub fn active() -> bool {
    #[cfg(windows)]
    {
        win::active()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform() {
        assert!(!supported());
        assert!(!active());
        assert_eq!(start(0, None, Box::new(|_| {})), Err(Error::Unsupported));
        stop();
        assert!(!active());
    }

    #[test]
    fn error_messages_are_polish() {
        assert!(Error::Unsupported.to_string().contains("Windows"));
        assert!(Error::HookFailed(5).to_string().contains('5'));
    }
}
