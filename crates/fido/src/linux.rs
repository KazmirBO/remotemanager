//! Klucz FIDO2 po USB HID (hidraw) przez bibliotekę `ctap-hid-fido2`.
//!
//! Dostęp do urządzenia daje zwykłemu użytkownikowi systemd (reguły udev oznaczają klucze
//! FIDO, a `uaccess` nadaje prawa zalogowanemu użytkownikowi). PIN podaje program, bo na
//! Linuksie nie ma systemowego okna dla kluczy.

use std::panic::{AssertUnwindSafe, catch_unwind};

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as GetExt;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as MakeExt;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};
use zeroize::Zeroizing;

use crate::{Authenticator, Error, PinEntry, RP_ID, RP_NAME, SECRET_LEN, Secret, prf_salt};

pub struct HidKey;

/// Biblioteka zgłasza błędy tekstem i w kilku miejscach panikuje (brak dostępu do udev,
/// nietypowa odpowiedź urządzenia), więc każde wywołanie idzie przez tę osłonę.
fn guarded<T>(f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(Error::Other("biblioteka klucza przerwała działanie".into())))
}

/// Otwiera jedyny podłączony klucz FIDO.
fn open() -> Result<FidoKeyHid, Error> {
    let mut devices = ctap_hid_fido2::get_fidokey_devices();
    let device = match devices.len() {
        0 => return Err(Error::NoDevice),
        1 => devices.remove(0),
        _ => return Err(Error::ManyDevices),
    };
    let mut cfg = Cfg::init();
    // Biblioteka domyślnie wypisuje prośbę o dotknięcie klucza na standardowe wyjście.
    cfg.enable_keep_alive_msg = false;
    FidoKeyHidFactory::create_by_params(&[device.param], &cfg).map_err(|_| {
        Error::Other("nie udało się otworzyć klucza (brak dostępu do urządzenia?)".into())
    })
}

/// Tłumaczy tekst błędu biblioteki (zawiera nazwę kodu CTAP) na nasz błąd.
fn map_err(device: &FidoKeyHid, e: &str) -> Error {
    let has = |code: &str| e.contains(code);
    if has("CTAP2_ERR_PIN_INVALID") || has("CTAP2_ERR_PIN_AUTH_INVALID") {
        let retries = device
            .get_pin_retries()
            .ok()
            .and_then(|n| u32::try_from(n).ok());
        Error::PinInvalid { retries }
    } else if has("CTAP2_ERR_PIN_AUTH_BLOCKED") {
        Error::PinAuthBlocked
    } else if has("CTAP2_ERR_PIN_BLOCKED") {
        Error::PinBlocked
    } else if has("CTAP2_ERR_PIN_NOT_SET") {
        Error::PinNotSet
    } else if has("CTAP2_ERR_PIN_REQUIRED") || has("pin not set") {
        Error::PinRequired
    } else if has("CTAP2_ERR_NO_CREDENTIALS") || has("CTAP2_ERR_INVALID_CREDENTIAL") {
        Error::NotRegistered
    } else if has("CTAP2_ERR_CREDENTIAL_EXCLUDED") {
        Error::AlreadyRegistered
    } else if has("CTAP2_ERR_USER_ACTION_TIMEOUT") || has("CTAP2_ERR_ACTION_TIMEOUT") {
        Error::Timeout
    } else if has("CTAP2_ERR_KEEPALIVE_CANCEL") || has("CTAP2_ERR_OPERATION_DENIED") {
        Error::Cancelled
    } else if has("CTAP2_ERR_UNSUPPORTED_EXTENSION") || has("CTAP2_ERR_UNSUPPORTED_OPTION") {
        Error::Unsupported("klucz nie obsługuje hmac-secret".into())
    } else {
        // Tekst biblioteki to nazwa kodu stanu albo opis błędu transportu, bez danych użytkownika.
        Error::Other(e.to_owned())
    }
}

fn required(pin: Option<&str>) -> Result<&str, Error> {
    pin.filter(|p| !p.is_empty()).ok_or(Error::PinRequired)
}

impl Authenticator for HidKey {
    fn pin_entry(&self) -> PinEntry {
        PinEntry::App
    }

    fn register(&self, pin: Option<&str>, exclude: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        let pin = required(pin)?;
        guarded(|| {
            let device = open()?;
            let challenge = crate::challenge()?;
            // Poświadczenie nie jest zapisywane na kluczu (bez `rk`), więc nie zajmuje miejsca.
            // Identyfikator użytkownika nic nie znaczy: protokół wymaga, żeby był.
            let user = PublicKeyCredentialUserEntity::new(
                Some(&challenge[..16]),
                Some(RP_NAME),
                Some(RP_NAME),
            );
            let mut builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
                .pin(pin)
                .user_entity(&user)
                .extensions(&[MakeExt::HmacSecret(Some(true))]);
            for id in exclude {
                builder = builder.exclude_authenticator(id);
            }
            let att = device
                .make_credential_with_args(&builder.build())
                .map_err(|e| map_err(&device, &e.to_string()))?;
            let enabled = att
                .extensions
                .iter()
                .any(|e| matches!(e, MakeExt::HmacSecret(Some(true))));
            if !enabled {
                return Err(Error::Unsupported("klucz nie obsługuje hmac-secret".into()));
            }
            if att.credential_descriptor.id.is_empty() {
                return Err(Error::Other("klucz nie zwrócił poświadczenia".into()));
            }
            Ok(att.credential_descriptor.id)
        })
    }

    fn secret(
        &self,
        credentials: &[Vec<u8>],
        salt: &[u8; SECRET_LEN],
        pin: Option<&str>,
    ) -> Result<Secret, Error> {
        let pin = required(pin)?;
        if credentials.is_empty() {
            return Err(Error::NotRegistered);
        }
        guarded(|| {
            let device = open()?;
            let challenge = crate::challenge()?;
            let mut builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
                .pin(pin)
                .extensions(&[GetExt::HmacSecret(Some(prf_salt(salt)))]);
            for id in credentials {
                builder = builder.add_credential_id(id);
            }
            let assertions = device
                .get_assertion_with_args(&builder.build())
                .map_err(|e| map_err(&device, &e.to_string()))?;
            let assertion = assertions
                .into_iter()
                .next()
                .ok_or_else(|| Error::Other("klucz nie odpowiedział".into()))?;
            // Sekret z operacji bez sprawdzenia użytkownika jest inny niż z PIN-em.
            if !assertion.flags.user_verified_result {
                return Err(Error::Other("klucz nie potwierdził PIN-u".into()));
            }
            let secret = assertion
                .extensions
                .iter()
                .find_map(|e| match e {
                    GetExt::HmacSecret(Some(out)) => Some(Zeroizing::new(*out)),
                    _ => None,
                })
                .ok_or_else(|| {
                    Error::Unsupported("klucz nie zwrócił sekretu hmac-secret".into())
                })?;
            // Klucz może pominąć identyfikator, gdy pytanie dotyczyło jednego poświadczenia.
            let credential = if assertion.credential_id.is_empty() && credentials.len() == 1 {
                credentials[0].clone()
            } else {
                assertion.credential_id
            };
            if !credentials.contains(&credential) {
                return Err(Error::Other(
                    "klucz odpowiedział nieznanym poświadczeniem".into(),
                ));
            }
            Ok(Secret { credential, secret })
        })
    }
}
