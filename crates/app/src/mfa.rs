//! Dodatkowy składnik przy otwieraniu pliku z hostami: drugi krok odblokowania kodem TOTP oraz
//! włączanie i wyłączanie tego wymogu.
//!
//! Hasło główne odszyfrowuje plik jak zawsze. Jeśli dokument wymaga kodu, odszyfrowana zawartość
//! czeka w `AppState::pending_unlock` i nie jest dostępna dla żadnej komendy, dopóki `unlock_totp`
//! nie dostanie poprawnego kodu. To bramka w programie, a nie składnik szyfrowania (patrz
//! `model::mfa`). Sekret i kody zapasowe trafiają do interfejsu tylko raz, przy włączaniu, bo
//! użytkownik musi je przepisać; potem nie opuszczają backendu.

use std::time::{Duration, Instant};

use model::mfa::{self, Totp};
use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::state::{AppState, Unlocked};

/// Błąd `unlock`, po którym interfejs pyta o kod.
pub const NEEDS_TOTP: &str = "NEEDS_TOTP:Podaj kod z aplikacji uwierzytelniającej.";
/// Po tylu błędnych kodach trzeba ponownie podać hasło główne.
const MAX_FAILURES: u32 = 5;
/// Tyle czasu odszyfrowany plik czeka na kod.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);
/// Tyle czasu jest na dokończenie włączania.
const ENROLL_TTL: Duration = Duration::from_secs(15 * 60);
/// Opóźnienie po błędnym kodzie.
const FAILURE_DELAY: Duration = Duration::from_millis(500);

/// Plik odszyfrowany hasłem, czekający na kod.
pub struct PendingUnlock {
    unlocked: Unlocked,
    failures: u32,
    since: Instant,
}

/// Sekret wylosowany przy włączaniu, jeszcze niezapisany w dokumencie.
pub struct Enrollment {
    secret: Zeroizing<Vec<u8>>,
    since: Instant,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Odkłada odszyfrowany plik do czasu podania kodu (zastępuje poprzednio odłożony).
pub fn begin_second_step(state: &AppState, unlocked: Unlocked) {
    *state.pending_unlock.lock().expect("pending_unlock") = Some(PendingUnlock {
        unlocked,
        failures: 0,
        since: Instant::now(),
    });
}

/// Porzuca plik czekający na kod i niedokończone włączanie (blokada pliku, przeładowanie interfejsu).
pub fn clear(state: &AppState) {
    *state.pending_unlock.lock().expect("pending_unlock") = None;
    *state.totp_enroll.lock().expect("totp_enroll") = None;
}

/// Drugi krok odblokowania: kod TOTP albo kod zapasowy (ten jest wtedy zużywany).
pub(crate) async fn finish_unlock(state: &AppState, code: &str, now: u64) -> Result<(), String> {
    // Blokada jest zwalniana przed każdym `await`.
    let outcome = {
        let mut slot = state.pending_unlock.lock().expect("pending_unlock");
        let Some(p) = slot.as_mut() else {
            return Err("Najpierw podaj hasło główne.".into());
        };
        if p.since.elapsed() > PENDING_TTL {
            *slot = None;
            return Err(
                "TOTP_EXPIRED:Minął czas na podanie kodu. Podaj hasło główne ponownie.".into(),
            );
        }
        let Some(totp) = p.unlocked.doc.mfa.totp.as_ref() else {
            // Nie powinno się zdarzyć: do schowka trafia tylko dokument z TOTP.
            *slot = None;
            return Err("Najpierw podaj hasło główne.".into());
        };
        let by_code = totp.verify(code, now);
        let by_recovery = !by_code && totp.has_recovery(code);
        if by_code || by_recovery {
            Ok((slot.take().expect("sprawdzone").unlocked, by_recovery))
        } else {
            p.failures += 1;
            if p.failures >= MAX_FAILURES {
                *slot = None;
                Err("TOTP_EXPIRED:Za dużo błędnych kodów. Podaj hasło główne ponownie.")
            } else {
                Err(
                    "TOTP_BAD:Nieprawidłowy kod. Sprawdź, czy zegar telefonu jest dobrze ustawiony.",
                )
            }
        }
    };
    let (unlocked, by_recovery) = match outcome {
        Ok(v) => v,
        Err(e) => {
            tokio::time::sleep(FAILURE_DELAY).await;
            state.log("odblokowanie: błędny kod dodatkowego składnika");
            return Err(e.into());
        }
    };
    *state.inner.lock().await = Some(unlocked);
    if by_recovery {
        // Zużycie kodu zapasowego zmienia dokument, więc idzie zwykłą drogą zapisu. Gdy zapis się
        // nie uda, plik zostaje zablokowany: kod, którego nie dało się zużyć, nie może otwierać.
        let used = state
            .mutate(|doc| {
                doc.mfa
                    .totp
                    .as_mut()
                    .map(|t| t.use_recovery(code))
                    .filter(|used| *used)
                    .map(|_| ())
                    .ok_or_else(|| "Kod zapasowy został już wykorzystany.".to_string())
            })
            .await;
        if let Err(e) = used {
            *state.inner.lock().await = None;
            return Err(e);
        }
        state.log("odblokowano plik z hostami kodem zapasowym");
    } else {
        state.log("odblokowano plik z hostami (hasło i kod)");
    }
    state.touch_activity();
    Ok(())
}

/// Drugi krok odblokowania pliku, który wymaga kodu.
#[tauri::command]
pub async fn unlock_totp(state: State<'_, AppState>, code: String) -> Result<(), String> {
    finish_unlock(&state, &code, now_secs()).await
}

/// Dane do skonfigurowania aplikacji uwierzytelniającej. Pokazywane raz, przy włączaniu.
#[derive(Serialize)]
pub struct TotpSetup {
    /// Sekret w base32, do ręcznego wpisania.
    pub secret: String,
    /// Adres `otpauth://` do wklejenia albo zamiany na kod QR.
    pub uri: String,
}

pub(crate) async fn begin_enrollment(state: &AppState) -> Result<TotpSetup, String> {
    state
        .read(|doc| match doc.mfa.totp {
            Some(_) => Err("Kody jednorazowe są już włączone.".to_string()),
            None => Ok(()),
        })
        .await?;
    let secret = vault::random_bytes::<{ mfa::SECRET_LEN }>().map_err(|e| e.to_string())?;
    let setup = TotpSetup {
        secret: mfa::base32(&secret),
        uri: mfa::otpauth_uri(&secret, "Menedżer sesji", "plik z hostami"),
    };
    *state.totp_enroll.lock().expect("totp_enroll") = Some(Enrollment {
        secret: Zeroizing::new(secret.to_vec()),
        since: Instant::now(),
    });
    Ok(setup)
}

/// Losuje sekret TOTP i zwraca go do pokazania. Wymóg zaczyna obowiązywać dopiero po `totp_enable`.
#[tauri::command]
pub async fn totp_begin(state: State<'_, AppState>) -> Result<TotpSetup, String> {
    begin_enrollment(&state).await
}

pub(crate) async fn finish_enrollment(
    state: &AppState,
    code: &str,
    now: u64,
) -> Result<Vec<String>, String> {
    let secret = {
        let mut slot = state.totp_enroll.lock().expect("totp_enroll");
        match slot.as_ref() {
            Some(e) if e.since.elapsed() <= ENROLL_TTL => e.secret.clone(),
            _ => {
                *slot = None;
                return Err("Zacznij włączanie od nowa: sekret wygasł.".into());
            }
        }
    };
    // Kod dowodzi, że aplikacja uwierzytelniająca ma ten sam sekret; bez tego łatwo zamknąć
    // sobie dostęp do pliku literówką przy przepisywaniu.
    if !mfa::verify(&secret, code, now) {
        return Err("Nieprawidłowy kod. Wpisz bieżący kod z aplikacji uwierzytelniającej.".into());
    }
    let mut codes = Vec::with_capacity(mfa::RECOVERY_CODES);
    for _ in 0..mfa::RECOVERY_CODES {
        let random = vault::random_bytes::<7>().map_err(|e| e.to_string())?;
        codes.push(mfa::recovery_code(&random));
    }
    let totp = Totp::new(secret.to_vec(), &codes);
    state
        .mutate(|doc| {
            if doc.mfa.totp.is_some() {
                return Err("Kody jednorazowe są już włączone.".to_string());
            }
            doc.mfa.totp = Some(totp);
            Ok(())
        })
        .await?;
    *state.totp_enroll.lock().expect("totp_enroll") = None;
    state.log("włączono kody jednorazowe przy otwieraniu pliku");
    Ok(codes)
}

/// Włącza wymóg kodu po sprawdzeniu pierwszego kodu. Zwraca kody zapasowe do jednorazowego pokazania.
#[tauri::command]
pub async fn totp_enable(state: State<'_, AppState>, code: String) -> Result<Vec<String>, String> {
    finish_enrollment(&state, &code, now_secs()).await
}

pub(crate) async fn disable(state: &AppState, code: &str, now: u64) -> Result<(), String> {
    state
        .mutate(|doc| {
            let totp = doc
                .mfa
                .totp
                .as_ref()
                .ok_or("Kody jednorazowe nie są włączone.")?;
            if !totp.verify(code, now) && !totp.has_recovery(code) {
                return Err("Nieprawidłowy kod.".to_string());
            }
            doc.mfa.totp = None;
            Ok(())
        })
        .await?;
    state.log("wyłączono kody jednorazowe przy otwieraniu pliku");
    Ok(())
}

/// Wyłącza wymóg kodu. Wymaga bieżącego kodu albo kodu zapasowego.
#[tauri::command]
pub async fn totp_disable(state: State<'_, AppState>, code: String) -> Result<(), String> {
    disable(&state, &code, now_secs()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::Document;
    use std::path::{Path, PathBuf};
    use vault::{KdfParams, Vault};

    const NOW: u64 = 1_800_000_000;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mrm-mfa-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn unlocked_state(dir: &Path) -> AppState {
        let path = dir.join("hosts.mrm");
        let doc = Document::default();
        let vault = Vault::create(&path, "haslo-glowne", KdfParams::FAST_FOR_TESTS, &doc).unwrap();
        let state = AppState::new(path);
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        state
    }

    /// Kod bieżący dla sekretu podanego w base32 (tak, jak policzyłaby go aplikacja w telefonie).
    fn current(setup: &TotpSetup, now: u64) -> String {
        // Sekret wraca z base32 przez porównanie z dokumentem nie jest możliwe przed włączeniem,
        // więc test dekoduje go sam.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u32;
        let mut buffer = 0u32;
        let mut secret = Vec::new();
        for c in setup.secret.bytes() {
            buffer = (buffer << 5) | alphabet.iter().position(|a| *a == c).unwrap() as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                secret.push((buffer >> bits) as u8);
            }
        }
        format!("{:06}", mfa::code_at(&secret, now / mfa::PERIOD))
    }

    /// Otwiera plik hasłem tak jak komenda `unlock`: dokument z TOTP trafia do schowka.
    async fn open_with_password(state: &AppState) -> Result<(), String> {
        let (vault, doc) = Vault::open::<Document>(state.path.clone(), "haslo-glowne")
            .map_err(|e| e.to_string())?;
        if doc.mfa.totp.is_some() {
            begin_second_step(state, Unlocked { vault, doc });
            return Err(NEEDS_TOTP.into());
        }
        *state.inner.lock().await = Some(Unlocked { vault, doc });
        Ok(())
    }

    async fn is_unlocked(state: &AppState) -> bool {
        state.inner.lock().await.is_some()
    }

    #[tokio::test]
    async fn enabling_requires_a_valid_code_and_protects_the_file() {
        let d = dir("wlacz");
        let state = unlocked_state(&d).await;
        assert_eq!(
            std::fs::read(&state.path).unwrap()[4],
            vault::FORMAT_VERSION
        );
        // Bez rozpoczęcia nie ma czego potwierdzać.
        let e = finish_enrollment(&state, "000000", NOW).await.unwrap_err();
        assert!(e.contains("od nowa"), "{e}");
        let setup = begin_enrollment(&state).await.unwrap();
        assert_eq!(setup.secret.len(), 32);
        assert!(setup.uri.starts_with("otpauth://totp/") && setup.uri.contains(&setup.secret));
        // Zły kod niczego nie włącza i pozwala spróbować ponownie.
        let e = finish_enrollment(&state, "000000", NOW).await.unwrap_err();
        assert!(e.contains("Nieprawidłowy kod"), "{e}");
        state
            .read(|doc| {
                assert!(doc.mfa.is_empty());
                Ok(())
            })
            .await
            .unwrap();
        let codes = finish_enrollment(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap();
        assert_eq!(codes.len(), mfa::RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == mfa::RECOVERY_LEN + 1));
        // Plik jest teraz w wersji 2, a sekret i kody zapasowe nie leżą w nim jawnie.
        let bytes = std::fs::read(&state.path).unwrap();
        assert_eq!(bytes[4], vault::FORMAT_PROTECTED);
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(&setup.secret) && !text.contains(&codes[0]));
        // W dokumencie są skróty kodów zapasowych, nie same kody.
        state
            .read(|doc| {
                let t = doc.mfa.totp.as_ref().unwrap();
                assert_eq!(t.recovery.len(), mfa::RECOVERY_CODES);
                assert!(!t.recovery.contains(&codes[0]));
                Ok(())
            })
            .await
            .unwrap();
        // Drugie włączenie jest odrzucane.
        let e = begin_enrollment(&state).await.err().unwrap();
        assert!(e.contains("już włączone"), "{e}");
    }

    #[tokio::test]
    async fn unlock_needs_password_then_code_and_limits_attempts() {
        let d = dir("odblokuj");
        let state = unlocked_state(&d).await;
        let setup = begin_enrollment(&state).await.unwrap();
        let codes = finish_enrollment(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap();
        *state.inner.lock().await = None;

        // Kod bez hasła nic nie daje.
        let e = finish_unlock(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw podaj hasło"), "{e}");
        // Samo hasło nie odblokowuje.
        assert_eq!(open_with_password(&state).await.unwrap_err(), NEEDS_TOTP);
        assert!(!is_unlocked(&state).await);
        assert!(state.read(|_| Ok(())).await.is_err());
        // Zły kod: nadal zablokowane, można próbować dalej.
        let e = finish_unlock(&state, "000000", NOW).await.unwrap_err();
        assert!(e.starts_with("TOTP_BAD:"), "{e}");
        assert!(!is_unlocked(&state).await);
        // Dobry kod odblokowuje.
        finish_unlock(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap();
        assert!(is_unlocked(&state).await);
        // Kod nie działa drugi raz bez ponownego hasła (schowek jest pusty).
        *state.inner.lock().await = None;
        let e = finish_unlock(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw podaj hasło"), "{e}");

        // Pięć błędnych kodów wymusza ponowne hasło, nawet gdy szósty jest dobry.
        open_with_password(&state).await.unwrap_err();
        for i in 0..MAX_FAILURES {
            let e = finish_unlock(&state, "111111", NOW).await.unwrap_err();
            let last = i + 1 == MAX_FAILURES;
            assert_eq!(e.starts_with("TOTP_EXPIRED:"), last, "{i}: {e}");
        }
        let e = finish_unlock(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw podaj hasło"), "{e}");
        assert!(!is_unlocked(&state).await);

        // Kod zapasowy odblokowuje raz i znika z pliku.
        open_with_password(&state).await.unwrap_err();
        finish_unlock(&state, &codes[0].to_lowercase(), NOW)
            .await
            .unwrap();
        assert!(is_unlocked(&state).await);
        state
            .read(|doc| {
                assert_eq!(
                    doc.mfa.totp.as_ref().unwrap().recovery.len(),
                    mfa::RECOVERY_CODES - 1
                );
                Ok(())
            })
            .await
            .unwrap();
        *state.inner.lock().await = None;
        open_with_password(&state).await.unwrap_err();
        let e = finish_unlock(&state, &codes[0], NOW).await.unwrap_err();
        assert!(e.starts_with("TOTP_BAD:"), "{e}");

        // Blokada pliku porzuca plik czekający na kod.
        clear(&state);
        let e = finish_unlock(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("Najpierw podaj hasło"), "{e}");
    }

    #[tokio::test]
    async fn disabling_requires_a_code_and_returns_file_to_version_1() {
        let d = dir("wylacz");
        let state = unlocked_state(&d).await;
        let setup = begin_enrollment(&state).await.unwrap();
        let codes = finish_enrollment(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap();
        let e = disable(&state, "000000", NOW).await.unwrap_err();
        assert!(e.contains("Nieprawidłowy kod"), "{e}");
        assert_eq!(
            std::fs::read(&state.path).unwrap()[4],
            vault::FORMAT_PROTECTED
        );
        disable(&state, &current(&setup, NOW), NOW).await.unwrap();
        assert_eq!(
            std::fs::read(&state.path).unwrap()[4],
            vault::FORMAT_VERSION
        );
        *state.inner.lock().await = None;
        open_with_password(&state).await.unwrap();
        assert!(is_unlocked(&state).await);
        let e = disable(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap_err();
        assert!(e.contains("nie są włączone"), "{e}");
        // Wyłączenie kodem zapasowym.
        let setup = begin_enrollment(&state).await.unwrap();
        let codes2 = finish_enrollment(&state, &current(&setup, NOW), NOW)
            .await
            .unwrap();
        assert_ne!(codes, codes2);
        disable(&state, &codes2[3], NOW).await.unwrap();
        state
            .read(|doc| {
                assert!(doc.mfa.is_empty());
                Ok(())
            })
            .await
            .unwrap();
    }
}
