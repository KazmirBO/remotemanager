//! Logika przechwytywania niezależna od platformy: tłumaczenie surowych zdarzeń hooka na
//! scancody RDP, śledzenie wciśniętych klawiszy i modyfikatorów, rozpoznawanie skrótu
//! zwalniającego oraz decyzja, czy zdarzenie zatrzymać, czy przepuścić do systemu. Nic tu nie
//! alokuje ani nie blokuje, bo woła to funkcja haka, która musi wracać natychmiast.
//!
//! Poza Windows moduł służy tylko testom.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::{Combo, Event, Key, Released};

/// Bity pola `flags` z `KBDLLHOOKSTRUCT` (wartości `LLKHF_*`).
pub const FLAG_EXTENDED: u32 = 0x01;
pub const FLAG_UP: u32 = 0x80;

// Kody wirtualne, które trzeba rozpoznać po `vkCode`, bo sam scancode ich nie rozróżnia.
const VK_PAUSE: u32 = 0x13;
const VK_NUMLOCK: u32 = 0x90;
const VK_PACKET: u32 = 0xE7;

/// Znaczniki dopisywane przez Windows do scancodu przy zdarzeniach generowanych przez system
/// (fałszywy lewy Ctrl przy AltGr ma 0x21D, fałszywe Shifty przy NumLocku 0x22A i 0x236).
const FAKE_SCANCODE_BIT: u32 = 0x200;

/// Surowe zdarzenie z haka (pola `KBDLLHOOKSTRUCT`, bez czasu i `dwExtraInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawKey {
    pub vk: u32,
    pub scancode: u32,
    pub flags: u32,
}

/// Co hak ma zrobić z zdarzeniem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Zatrzymać (nie wołać `CallNextHookEx`, zwrócić niezerową wartość).
    Swallow,
    /// Przekazać dalej do systemu.
    Pass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Translated {
    Key(u8, bool),
    /// Zdarzenie wygenerowane przez system, bez odpowiednika w RDP (do zatrzymania i pominięcia).
    Fake,
    /// Klawisz, którego kontrakt `Key` nie wyraża (przepuszczamy do systemu).
    Unsupported,
}

fn translate(raw: RawKey) -> Translated {
    match raw.vk {
        // Pause to w RDP sekwencja E1 1D 45, a `Key` niesie jeden scancode i znacznik E0, więc
        // jej nie wyrazimy. Rozpoznajemy po vk, bo scancode 0x45 współdzieli z NumLockiem.
        // VK_PACKET (wstrzyknięty znak Unicode) nie ma scancodu.
        VK_PAUSE | VK_PACKET => return Translated::Unsupported,
        // Windows podaje NumLock jako 0x45 ze znacznikiem rozszerzonym (by odróżnić go od
        // Pause), a RDP zna go bez E0 (jak `NumLock` w scancodes.ts).
        VK_NUMLOCK => return Translated::Key(0x45, false),
        _ => {}
    }
    // PrintScreen (0x2C) zostaje w ogólnej ścieżce: hak podaje 0x37 + E0 (a z Alt 0x54),
    // czyli dokładnie to, co RDP przyjmuje.
    if raw.scancode & FAKE_SCANCODE_BIT != 0 {
        return Translated::Fake;
    }
    match u8::try_from(raw.scancode) {
        Ok(sc) if sc != 0 => Translated::Key(sc, raw.flags & FLAG_EXTENDED != 0),
        _ => Translated::Unsupported,
    }
}

/// Zbiór wciśniętych klawiszy: bit na parę (scancode, rozszerzony). Bez alokacji.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct KeySet([u64; 8]);

impl KeySet {
    fn index(sc: u8, ext: bool) -> usize {
        usize::from(sc) + if ext { 256 } else { 0 }
    }
    fn contains(&self, sc: u8, ext: bool) -> bool {
        let i = Self::index(sc, ext);
        self.0[i / 64] & (1 << (i % 64)) != 0
    }
    fn insert(&mut self, sc: u8, ext: bool) {
        let i = Self::index(sc, ext);
        self.0[i / 64] |= 1 << (i % 64);
    }
    /// Zwraca, czy klawisz był w zbiorze.
    fn remove(&mut self, sc: u8, ext: bool) -> bool {
        let had = self.contains(sc, ext);
        let i = Self::index(sc, ext);
        self.0[i / 64] &= !(1 << (i % 64));
        had
    }
    fn either(&self, sc: u8) -> bool {
        self.contains(sc, false) || self.contains(sc, true)
    }
}

fn is_modifier(sc: u8, ext: bool) -> bool {
    matches!(
        (sc, ext),
        (0x1D | 0x38, _) | (0x2A | 0x36, false) | (0x5B | 0x5C, true)
    )
}

/// Stan przechwytywania.
#[derive(Debug)]
pub struct Logic {
    release: Option<Combo>,
    pressed: KeySet,
    capturing: bool,
}

impl Logic {
    pub fn new(release: Option<Combo>) -> Self {
        Self {
            release,
            pressed: KeySet::default(),
            capturing: true,
        }
    }

    /// Czy nadal zatrzymujemy klawisze.
    pub fn capturing(&self) -> bool {
        self.capturing
    }

    /// Wyłącza zatrzymywanie bez wysyłania czegokolwiek (po panice odbiorcy).
    pub fn disarm(&mut self) {
        self.capturing = false;
    }

    /// Przetwarza jedno zdarzenie; `foreground` mówi, czy wskazane okno jest na pierwszym planie.
    pub fn handle(&mut self, raw: RawKey, foreground: bool, emit: &mut dyn FnMut(Event)) -> Action {
        if !self.capturing {
            return Action::Pass;
        }
        if !foreground {
            self.release_all(Released::Foreground, emit);
            return Action::Pass;
        }
        let (sc, ext) = match translate(raw) {
            Translated::Key(sc, ext) => (sc, ext),
            Translated::Fake => return Action::Swallow,
            Translated::Unsupported => return Action::Pass,
        };
        if raw.flags & FLAG_UP != 0 {
            // Zwolnienie klawisza, którego sesja nie widziała jako wciśniętego (wciśnięty przed
            // włączeniem albo przed skrótem), idzie do systemu: system nie zna tego klawisza
            // jako zwolnionego, bo jego wciśnięcie też mu uciekło lub było jeszcze przed nami.
            if self.pressed.remove(sc, ext) {
                emit(Event::Key(Key {
                    scancode: sc,
                    extended: ext,
                    down: false,
                }));
                return Action::Swallow;
            }
            return Action::Pass;
        }
        if self.matches_release(sc, ext) {
            self.release_all(Released::Combo, emit);
            return Action::Swallow;
        }
        // Powtórzenia (kolejne wciśnięcia bez zwolnienia) idą dalej jako kolejne `down`.
        self.pressed.insert(sc, ext);
        emit(Event::Key(Key {
            scancode: sc,
            extended: ext,
            down: true,
        }));
        Action::Swallow
    }

    fn matches_release(&self, sc: u8, ext: bool) -> bool {
        let Some(c) = self.release else {
            return false;
        };
        c.scancode == sc
            && c.extended == ext
            && c.ctrl == self.pressed.either(0x1D)
            && c.alt == self.pressed.either(0x38)
            && c.shift == (self.pressed.contains(0x2A, false) || self.pressed.contains(0x36, false))
            && c.meta == (self.pressed.contains(0x5B, true) || self.pressed.contains(0x5C, true))
    }

    /// Wysyła zwolnienia wszystkich wciśniętych klawiszy (zwykłe przed modyfikatorami), potem
    /// zdarzenie `Released` i przestaje zatrzymywać. Wołane też z warstwy WinAPI (`HookLost`).
    pub fn release_all(&mut self, reason: Released, emit: &mut dyn FnMut(Event)) {
        if !self.capturing {
            return;
        }
        self.capturing = false;
        for modifiers in [false, true] {
            for ext in [false, true] {
                for sc in 1..=u8::MAX {
                    if is_modifier(sc, ext) == modifiers && self.pressed.remove(sc, ext) {
                        emit(Event::Key(Key {
                            scancode: sc,
                            extended: ext,
                            down: false,
                        }));
                    }
                }
            }
        }
        emit(Event::Released(reason));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn down(vk: u32, sc: u32, ext: bool) -> RawKey {
        RawKey {
            vk,
            scancode: sc,
            flags: if ext { FLAG_EXTENDED } else { 0 },
        }
    }
    fn up(vk: u32, sc: u32, ext: bool) -> RawKey {
        RawKey {
            flags: down(vk, sc, ext).flags | FLAG_UP,
            ..down(vk, sc, ext)
        }
    }
    fn k(scancode: u8, extended: bool, down: bool) -> Event {
        Event::Key(Key {
            scancode,
            extended,
            down,
        })
    }
    /// Podaje zdarzenia (na pierwszym planie) i zwraca decyzje oraz zebrane zdarzenia.
    fn run(l: &mut Logic, evs: &[RawKey]) -> (Vec<Action>, Vec<Event>) {
        run_fg(l, &evs.iter().map(|e| (*e, true)).collect::<Vec<_>>())
    }
    fn run_fg(l: &mut Logic, evs: &[(RawKey, bool)]) -> (Vec<Action>, Vec<Event>) {
        let mut out = Vec::new();
        let mut acts = Vec::new();
        for (e, fg) in evs {
            acts.push(l.handle(*e, *fg, &mut |ev| out.push(ev)));
        }
        (acts, out)
    }

    const A: u32 = 0x41;
    const CTRL: u32 = 0x11;
    const ALT: u32 = 0x12;
    const SHIFT: u32 = 0x10;

    #[test]
    fn plain_key_is_swallowed_and_forwarded() {
        let mut l = Logic::new(None);
        let (acts, ev) = run(&mut l, &[down(A, 0x1E, false), up(A, 0x1E, false)]);
        assert_eq!(acts, [Action::Swallow, Action::Swallow]);
        assert_eq!(ev, [k(0x1E, false, true), k(0x1E, false, false)]);
        assert!(l.capturing());
    }

    #[test]
    fn extended_keys_keep_the_flag() {
        let mut l = Logic::new(None);
        let evs = [
            down(0x25, 0x4B, true),  // strzałka w lewo
            down(0xA3, 0x1D, true),  // prawy Ctrl
            down(0xA5, 0x38, true),  // prawy Alt
            down(0x5B, 0x5B, true),  // lewy Win
            down(0x5C, 0x5C, true),  // prawy Win
            down(0x0D, 0x1C, true),  // Enter z klawiatury numerycznej
            down(0x0D, 0x1C, false), // zwykły Enter
        ];
        let (acts, ev) = run(&mut l, &evs);
        assert!(acts.iter().all(|a| *a == Action::Swallow));
        assert_eq!(
            ev,
            [
                k(0x4B, true, true),
                k(0x1D, true, true),
                k(0x38, true, true),
                k(0x5B, true, true),
                k(0x5C, true, true),
                k(0x1C, true, true),
                k(0x1C, false, true),
            ]
        );
        // Zwolnienie prawego Ctrl nie rusza lewego i odwrotnie.
        let (_, ev) = run(&mut l, &[up(0xA3, 0x1D, true)]);
        assert_eq!(ev, [k(0x1D, true, false)]);
        let (acts, ev) = run(&mut l, &[up(0xA2, 0x1D, false)]);
        assert_eq!((acts, ev), (vec![Action::Pass], vec![]));
    }

    #[test]
    fn altgr_fake_ctrl_is_dropped() {
        let mut l = Logic::new(None);
        let (acts, ev) = run(
            &mut l,
            &[
                down(0xA2, 0x21D, false), // fałszywy lewy Ctrl
                down(0xA5, 0x38, true),   // AltGr jako prawy Alt
                up(0xA5, 0x38, true),
                up(0xA2, 0x21D, false),
            ],
        );
        assert_eq!(acts, [Action::Swallow; 4]);
        assert_eq!(ev, [k(0x38, true, true), k(0x38, true, false)]);
    }

    #[test]
    fn repeats_are_forwarded_as_repeated_downs() {
        let mut l = Logic::new(None);
        let (_, ev) = run(
            &mut l,
            &[
                down(A, 0x1E, false),
                down(A, 0x1E, false),
                down(A, 0x1E, false),
                up(A, 0x1E, false),
            ],
        );
        assert_eq!(
            ev,
            [
                k(0x1E, false, true),
                k(0x1E, false, true),
                k(0x1E, false, true),
                k(0x1E, false, false)
            ]
        );
    }

    #[test]
    fn up_of_unseen_key_goes_to_system() {
        let mut l = Logic::new(None);
        let (acts, ev) = run(&mut l, &[up(A, 0x1E, false)]);
        assert_eq!(acts, [Action::Pass]);
        assert!(ev.is_empty());
    }

    #[test]
    fn unrepresentable_keys_pass_to_system() {
        let mut l = Logic::new(None);
        let evs = [
            down(VK_PAUSE, 0x45, false),
            down(VK_PACKET, 0, false),
            down(0xFF, 0, false),
            down(A, 0x1E1, false),
        ];
        let (acts, ev) = run(&mut l, &evs);
        assert_eq!(acts, [Action::Pass; 4]);
        assert!(ev.is_empty());
    }

    #[test]
    fn numlock_is_normalised_and_printscreen_keeps_e0() {
        let mut l = Logic::new(None);
        let (_, ev) = run(
            &mut l,
            &[
                down(VK_NUMLOCK, 0x45, true),
                down(0x2C, 0x37, true),
                down(0x2C, 0x54, false),
            ],
        );
        assert_eq!(
            ev,
            [
                k(0x45, false, true),
                k(0x37, true, true),
                k(0x54, false, true)
            ]
        );
    }

    fn combo(sc: u8, ext: bool, ctrl: bool, alt: bool, shift: bool, meta: bool) -> Combo {
        Combo {
            scancode: sc,
            extended: ext,
            ctrl,
            alt,
            shift,
            meta,
        }
    }

    #[test]
    fn release_combo_releases_everything_then_stops_capturing() {
        // Ctrl+Alt+Home (Home to klawisz rozszerzony 0x47).
        let mut l = Logic::new(Some(combo(0x47, true, true, true, false, false)));
        let (acts, ev) = run(
            &mut l,
            &[
                down(0x41, 0x1E, false),
                down(CTRL, 0x1D, false),
                down(ALT, 0x38, false),
                down(0x24, 0x47, true),
            ],
        );
        assert_eq!(acts[3], Action::Swallow);
        assert_eq!(
            ev,
            [
                k(0x1E, false, true),
                k(0x1D, false, true),
                k(0x38, false, true),
                // zwykłe klawisze przed modyfikatorami
                k(0x1E, false, false),
                k(0x1D, false, false),
                k(0x38, false, false),
                Event::Released(Released::Combo),
            ]
        );
        assert!(!l.capturing());
        // Po zwolnieniu nic nie jest zatrzymywane ani wysyłane.
        let (acts, ev) = run(
            &mut l,
            &[
                up(0x24, 0x47, true),
                up(ALT, 0x38, false),
                down(A, 0x1E, false),
            ],
        );
        assert_eq!(acts, [Action::Pass; 3]);
        assert!(ev.is_empty());
    }

    #[test]
    fn release_combo_needs_exact_modifiers() {
        let mut l = Logic::new(Some(combo(0x47, true, true, true, false, false)));
        // Dodatkowy Shift: to nie jest skrót, klawisz idzie do sesji.
        let (acts, ev) = run(
            &mut l,
            &[
                down(CTRL, 0x1D, false),
                down(ALT, 0x38, false),
                down(SHIFT, 0x2A, false),
                down(0x24, 0x47, true),
            ],
        );
        assert_eq!(acts, [Action::Swallow; 4]);
        assert_eq!(ev[3], k(0x47, true, true));
        assert!(l.capturing());
        // Brakujący modyfikator: też nie.
        let mut l = Logic::new(Some(combo(0x47, true, true, true, false, false)));
        let (_, ev) = run(&mut l, &[down(CTRL, 0x1D, false), down(0x24, 0x47, true)]);
        assert_eq!(ev[1], k(0x47, true, true));
        // Ten sam scancode bez znacznika rozszerzonego (klawisz numeryczny 7) to inny klawisz.
        let mut l = Logic::new(Some(combo(0x47, true, false, false, false, false)));
        let (_, ev) = run(&mut l, &[down(0x24, 0x47, false)]);
        assert_eq!(ev, [k(0x47, false, true)]);
        assert!(l.capturing());
    }

    #[test]
    fn release_combo_with_any_side_modifiers_and_meta() {
        // Win+Shift+F12 z prawymi modyfikatorami.
        let mut l = Logic::new(Some(combo(0x58, false, false, false, true, true)));
        let (_, ev) = run(
            &mut l,
            &[
                down(0xA1, 0x36, false),
                down(0x5C, 0x5C, true),
                down(0x7B, 0x58, false),
            ],
        );
        assert_eq!(ev.last(), Some(&Event::Released(Released::Combo)));
        assert!(!l.capturing());
    }

    #[test]
    fn no_combo_configured_never_releases() {
        let mut l = Logic::new(None);
        let (_, ev) = run(&mut l, &[down(0x24, 0x47, true)]);
        assert_eq!(ev, [k(0x47, true, true)]);
        assert!(l.capturing());
    }

    #[test]
    fn losing_foreground_releases_and_passes() {
        let mut l = Logic::new(None);
        let (acts, ev) = run_fg(
            &mut l,
            &[
                (down(CTRL, 0x1D, false), true),
                (down(A, 0x1E, false), true),
                (down(0x42, 0x30, false), false), // okno straciło pierwszy plan
                (up(A, 0x1E, false), false),
                (down(0x42, 0x30, false), true), // wróciło, ale już nie przechwytujemy
            ],
        );
        assert_eq!(
            acts,
            [
                Action::Swallow,
                Action::Swallow,
                Action::Pass,
                Action::Pass,
                Action::Pass
            ]
        );
        assert_eq!(
            ev,
            [
                k(0x1D, false, true),
                k(0x1E, false, true),
                k(0x1E, false, false),
                k(0x1D, false, false),
                Event::Released(Released::Foreground),
            ]
        );
        assert!(!l.capturing());
    }

    #[test]
    fn release_happens_once() {
        let mut l = Logic::new(None);
        let mut out = Vec::new();
        l.release_all(Released::HookLost, &mut |e| out.push(e));
        l.release_all(Released::Foreground, &mut |e| out.push(e));
        assert_eq!(out, [Event::Released(Released::HookLost)]);
    }

    #[test]
    fn disarm_stops_silently() {
        let mut l = Logic::new(None);
        let (_, ev) = run(&mut l, &[down(A, 0x1E, false)]);
        assert_eq!(ev.len(), 1);
        l.disarm();
        let (acts, ev) = run(&mut l, &[down(A, 0x1E, false)]);
        assert_eq!((acts, ev), (vec![Action::Pass], vec![]));
    }

    #[test]
    fn keyset_covers_all_scancodes() {
        let mut s = KeySet::default();
        for sc in 0..=u8::MAX {
            for ext in [false, true] {
                assert!(!s.contains(sc, ext));
                s.insert(sc, ext);
                assert!(s.contains(sc, ext));
            }
        }
        for sc in 0..=u8::MAX {
            assert!(s.remove(sc, false));
            assert!(!s.contains(sc, false));
            assert!(s.contains(sc, true));
        }
    }
}
