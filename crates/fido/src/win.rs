//! Klucz FIDO2 przez systemowe API WebAuthn (`webauthn.dll`). Jedyny moduł tego crate'a
//! z `unsafe`: wywołania API i odczyt struktur, które API zwraca.
//!
//! System sam pokazuje okno z prośbą o PIN i dotknięcie klucza, więc program PIN-u nie widzi.
//! Wersje struktur są dobrane do najstarszego API, które zna potrzebne pola (nagłówek
//! `webauthn.h`): opcje rejestracji w wersji 3 (API 1, rozszerzenie hmac-secret jako `BOOL`),
//! opcje odczytu w wersji 6 i wynik w wersji 3 (API 4, sole i sekret hmac-secret). System
//! starszy niż API 4 nie umie zwrócić sekretu, więc `WinKey::new` zwraca wtedy `None`.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    HWND, NTE_DEVICE_NOT_FOUND, NTE_EXISTS, NTE_NOT_FOUND, NTE_NOT_SUPPORTED, NTE_USER_CANCELLED,
};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_CLIENT_DATA, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_CREDENTIAL,
    WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CREDENTIALS,
    WEBAUTHN_EXTENSION, WEBAUTHN_EXTENSIONS, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
    WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES,
    WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
    WebAuthNAuthenticatorMakeCredential, WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation,
    WebAuthNGetApiVersionNumber,
};
use windows_sys::core::{BOOL, HRESULT, PCWSTR};
use zeroize::Zeroizing;

use crate::{Authenticator, Error, PinEntry, RP_ID, RP_NAME, SECRET_LEN, Secret};

/// Najstarsza wersja API, która przyjmuje sole hmac-secret i zwraca sekret.
const MIN_API: u32 = 4;
/// Wersje struktur odpowiadające polom, których używamy.
const MAKE_OPTIONS_VERSION: u32 = 3;
const GET_OPTIONS_VERSION: u32 = 6;
const ASSERTION_WITH_HMAC_SECRET: u32 = 3;
const ATTESTATION_WITH_EXTENSIONS: u32 = 2;
/// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE`: poświadczenia producenta nie sprawdzamy.
const ATTESTATION_NONE: u32 = 1;
/// Czas na PIN i dotknięcie klucza.
const TIMEOUT_MS: u32 = 120_000;
/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)` i `HRESULT_FROM_WIN32(ERROR_TIMEOUT)`.
const E_CANCELLED: HRESULT = 0x800704C7_u32 as HRESULT;
const E_TIMEOUT: HRESULT = 0x800705B4_u32 as HRESULT;
/// Bit "użytkownik sprawdzony" w danych uwierzytelniacza (bajt flag po skrócie RP ID).
const FLAG_UV: u8 = 0x04;

pub struct WinKey {
    /// `HWND` głównego okna jako liczba, żeby typ był `Send + Sync`.
    hwnd: isize,
}

impl WinKey {
    pub fn new(window: Option<isize>) -> Option<Self> {
        let hwnd = window.filter(|h| *h != 0)?;
        // SAFETY: funkcja bez argumentów, zwraca numer wersji API.
        let api = unsafe { WebAuthNGetApiVersionNumber() };
        (api >= MIN_API).then_some(Self { hwnd })
    }

    fn hwnd(&self) -> HWND {
        self.hwnd as HWND
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Dane klienta, których skrót podpisuje klucz. Podpisu nie sprawdzamy, więc wystarczy
/// poprawny kształt z losowym wyzwaniem.
fn client_data(kind: &str) -> Result<Vec<u8>, Error> {
    let challenge: String = crate::challenge()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!(r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{RP_ID}"}}"#).into_bytes())
}

fn map_hr(hr: HRESULT) -> Error {
    match hr {
        NTE_USER_CANCELLED | E_CANCELLED => Error::Cancelled,
        E_TIMEOUT => Error::Timeout,
        NTE_NOT_FOUND => Error::NotRegistered,
        NTE_EXISTS => Error::AlreadyRegistered,
        NTE_DEVICE_NOT_FOUND => Error::NoDevice,
        NTE_NOT_SUPPORTED => Error::Unsupported("system albo klucz odrzucił operację".into()),
        other => Error::Other(format!("WebAuthn zwrócił kod 0x{:08X}", other as u32)),
    }
}

/// Lista poświadczeń w postaci, której oczekuje API. Zwrócone struktury wskazują na bufory
/// z `ids`, więc `ids` musi żyć do końca wywołania API.
fn credential_list(ids: &mut [Vec<u8>]) -> Vec<WEBAUTHN_CREDENTIAL> {
    ids.iter_mut()
        .map(|id| WEBAUTHN_CREDENTIAL {
            dwVersion: 1,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        })
        .collect()
}

/// Kopiuje bufor zwrócony przez API.
///
/// # Safety
/// `ptr` musi wskazywać na `len` czytelnych bajtów albo być pusty.
unsafe fn copy(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: warunek z opisu funkcji.
    unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec()
}

/// Czy wynik rejestracji potwierdza poświadczenie z hmac-secret.
///
/// # Safety
/// `extensions` musi pochodzić z wyniku API, który nie został jeszcze zwolniony.
unsafe fn hmac_secret_enabled(extensions: &WEBAUTHN_EXTENSIONS) -> bool {
    if extensions.pExtensions.is_null() {
        return false;
    }
    let wanted = wide("hmac-secret");
    for i in 0..extensions.cExtensions as usize {
        // SAFETY: API zwraca tablicę `cExtensions` elementów.
        let ext = unsafe { &*extensions.pExtensions.add(i) };
        if ext.pwszExtensionIdentifier.is_null() || ext.pvExtension.is_null() {
            continue;
        }
        // SAFETY: identyfikator to napis zakończony zerem; czytamy najwyżej tyle znaków,
        // ile ma wzorzec, i przerywamy na pierwszej różnicy (także na zerze końcowym).
        let same = wanted
            .iter()
            .enumerate()
            .all(|(n, w)| unsafe { *ext.pwszExtensionIdentifier.add(n) } == *w);
        if same && ext.cbExtension as usize >= size_of::<BOOL>() {
            // SAFETY: dla hmac-secret wynik to `BOOL` (opis w `webauthn.h`).
            return unsafe { *(ext.pvExtension as *const BOOL) } != 0;
        }
    }
    false
}

impl Authenticator for WinKey {
    fn pin_entry(&self) -> PinEntry {
        PinEntry::System
    }

    fn register(&self, _pin: Option<&str>, exclude: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        let rp_id = wide(RP_ID);
        let rp_name = wide(RP_NAME);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: 1,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: null(),
        };
        // Identyfikator użytkownika nic nie znaczy: protokół wymaga, żeby był.
        let mut user_id = crate::challenge()?;
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: 1,
            cbId: 16,
            pbId: user_id.as_mut_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: null(),
            pwszDisplayName: rp_name.as_ptr(),
        };
        let mut alg = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: 1,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let algs = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut alg,
        };
        let mut json = client_data("webauthn.create")?;
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut hmac_on: BOOL = 1;
        let mut ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: size_of::<BOOL>() as u32,
            pvExtension: (&mut hmac_on as *mut BOOL).cast::<c_void>(),
        };
        let mut exclude_ids = exclude.to_vec();
        let mut excluded = credential_list(&mut exclude_ids);
        // SAFETY: struktura z samych liczb i wskaźników; zera to poprawne wartości "brak".
        let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS =
            unsafe { std::mem::zeroed() };
        options.dwVersion = MAKE_OPTIONS_VERSION;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        // W rejestracji ta lista to poświadczenia wykluczone: klucz, który ma jedno z nich, odmawia.
        options.CredentialList = WEBAUTHN_CREDENTIALS {
            cCredentials: excluded.len() as u32,
            pCredentials: if excluded.is_empty() {
                null_mut()
            } else {
                excluded.as_mut_ptr()
            },
        };
        options.Extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut ext,
        };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.bRequireResidentKey = 0;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.dwAttestationConveyancePreference = ATTESTATION_NONE;

        let mut out: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
        // SAFETY: wszystkie wskaźniki wskazują na zmienne lokalne żyjące do końca wywołania,
        // a `dwVersion` opisuje, które pola struktury opcji system może czytać.
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                self.hwnd(),
                &rp,
                &user,
                &algs,
                &client,
                &options,
                &mut out,
            )
        };
        if hr != 0 {
            return Err(map_hr(hr));
        }
        if out.is_null() {
            return Err(Error::Other("system nie zwrócił poświadczenia".into()));
        }
        // SAFETY: po sukcesie `out` wskazuje na strukturę przydzieloną przez API; czytamy
        // tylko pola obecne w jej wersji i zwalniamy ją dokładnie raz.
        let (id, enabled) = unsafe {
            let att = &*out;
            let id = copy(att.pbCredentialId, att.cbCredentialId);
            let enabled = att.dwVersion >= ATTESTATION_WITH_EXTENSIONS
                && hmac_secret_enabled(&att.Extensions);
            WebAuthNFreeCredentialAttestation(out);
            (id, enabled)
        };
        if !enabled {
            return Err(Error::Unsupported("klucz nie obsługuje hmac-secret".into()));
        }
        if id.is_empty() {
            return Err(Error::Other("system nie zwrócił poświadczenia".into()));
        }
        Ok(id)
    }

    fn secret(
        &self,
        credentials: &[Vec<u8>],
        salt: &[u8; SECRET_LEN],
        _pin: Option<&str>,
    ) -> Result<Secret, Error> {
        if credentials.is_empty() {
            return Err(Error::NotRegistered);
        }
        let rp_id = wide(RP_ID);
        let mut json = client_data("webauthn.get")?;
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: 1,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allowed_ids = credentials.to_vec();
        let mut allowed = credential_list(&mut allowed_ids);
        // Sól idzie bez przekształcenia: bez flagi `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`
        // system sam stosuje przekształcenie PRF, to samo co `crate::prf_salt`.
        let mut salt_in = *salt;
        let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: SECRET_LEN as u32,
            pbFirst: salt_in.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: null_mut(),
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut hmac_salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: null_mut(),
        };
        // SAFETY: struktura z samych liczb i wskaźników; zera to poprawne wartości "brak".
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS =
            unsafe { std::mem::zeroed() };
        options.dwVersion = GET_OPTIONS_VERSION;
        options.dwTimeoutMilliseconds = TIMEOUT_MS;
        options.CredentialList = WEBAUTHN_CREDENTIALS {
            cCredentials: allowed.len() as u32,
            pCredentials: allowed.as_mut_ptr(),
        };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
        options.pHmacSecretSaltValues = &mut salts;

        let mut out: *mut WEBAUTHN_ASSERTION = null_mut();
        let rp: PCWSTR = rp_id.as_ptr();
        // SAFETY: wszystkie wskaźniki wskazują na zmienne lokalne żyjące do końca wywołania,
        // a `dwVersion` opisuje, które pola struktury opcji system może czytać.
        let hr = unsafe {
            WebAuthNAuthenticatorGetAssertion(self.hwnd(), rp, &client, &options, &mut out)
        };
        if hr != 0 {
            return Err(map_hr(hr));
        }
        if out.is_null() {
            return Err(Error::Other("system nie zwrócił odpowiedzi klucza".into()));
        }
        // SAFETY: po sukcesie `out` wskazuje na strukturę przydzieloną przez API; czytamy
        // tylko pola obecne w jej wersji, kopiujemy dane i zwalniamy ją dokładnie raz.
        let (credential, auth_data, secret) = unsafe {
            let a = &*out;
            let credential = copy(a.Credential.pbId, a.Credential.cbId);
            let auth_data = copy(a.pbAuthenticatorData, a.cbAuthenticatorData);
            let mut secret = None;
            if a.dwVersion >= ASSERTION_WITH_HMAC_SECRET && !a.pHmacSecret.is_null() {
                let hs = &*a.pHmacSecret;
                if hs.cbFirst as usize == SECRET_LEN && !hs.pbFirst.is_null() {
                    let mut buf = Zeroizing::new([0u8; SECRET_LEN]);
                    buf.copy_from_slice(std::slice::from_raw_parts(hs.pbFirst, SECRET_LEN));
                    secret = Some(buf);
                }
            }
            WebAuthNFreeAssertion(out);
            (credential, auth_data, secret)
        };
        let secret = secret
            .ok_or_else(|| Error::Unsupported("klucz nie zwrócił sekretu hmac-secret".into()))?;
        // Sekret z operacji bez sprawdzenia użytkownika jest inny niż z PIN-em.
        if auth_data.get(32).is_none_or(|flags| flags & FLAG_UV == 0) {
            return Err(Error::Other("klucz nie potwierdził PIN-u".into()));
        }
        if !credentials.contains(&credential) {
            return Err(Error::Other(
                "klucz odpowiedział nieznanym poświadczeniem".into(),
            ));
        }
        Ok(Secret { credential, secret })
    }
}
