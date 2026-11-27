//! Programowa atrapa klucza sprzętowego do testów: zachowuje się jak klucz z hmac-secret
//! (poświadczenia, PIN, ten sam sekret dla tej samej soli), ale niczego nie chroni.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Authenticator, Error, PinEntry, SECRET_LEN, Secret, prf_salt};

pub struct SoftKey {
    device: [u8; 32],
    pin: String,
    entry: PinEntry,
    credentials: Mutex<Vec<Vec<u8>>>,
    present: AtomicBool,
    retries: AtomicU32,
    touches: AtomicU32,
}

impl SoftKey {
    /// Klucz o tajemnicy urządzenia wyprowadzonej z `seed` i podanym PIN-ie.
    pub fn new(seed: u8, pin: &str) -> Self {
        Self {
            device: Sha256::digest([b's', b'o', b'f', b't', seed]).into(),
            pin: pin.to_owned(),
            entry: PinEntry::App,
            credentials: Mutex::new(Vec::new()),
            present: AtomicBool::new(true),
            retries: AtomicU32::new(8),
            touches: AtomicU32::new(0),
        }
    }

    /// Klucz, o którego PIN pyta "system" (PIN z wywołania jest ignorowany).
    pub fn system_pin(mut self) -> Self {
        self.entry = PinEntry::System;
        self
    }

    /// Wyjmuje klucz z gniazda albo wkłada go z powrotem.
    pub fn set_present(&self, present: bool) {
        self.present.store(present, Ordering::SeqCst);
    }

    /// Ile razy klucz został "dotknięty" (udane operacje).
    pub fn touches(&self) -> u32 {
        self.touches.load(Ordering::SeqCst)
    }

    fn check(&self, pin: Option<&str>) -> Result<(), Error> {
        if !self.present.load(Ordering::SeqCst) {
            return Err(Error::NoDevice);
        }
        if self.entry == PinEntry::System {
            return Ok(());
        }
        let pin = pin.filter(|p| !p.is_empty()).ok_or(Error::PinRequired)?;
        if self.retries.load(Ordering::SeqCst) == 0 {
            return Err(Error::PinBlocked);
        }
        if pin != self.pin {
            let left = self.retries.fetch_sub(1, Ordering::SeqCst) - 1;
            return Err(Error::PinInvalid {
                retries: Some(left),
            });
        }
        self.retries.store(8, Ordering::SeqCst);
        Ok(())
    }

    fn mac(&self, key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut m =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC przyjmuje klucz każdej długości");
        m.update(msg);
        m.finalize().into_bytes().into()
    }
}

impl Authenticator for SoftKey {
    fn pin_entry(&self) -> PinEntry {
        self.entry
    }

    fn register(&self, pin: Option<&str>, exclude: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
        self.check(pin)?;
        let mut creds = self.credentials.lock().expect("credentials");
        if creds.iter().any(|c| exclude.contains(c)) {
            return Err(Error::AlreadyRegistered);
        }
        let id = self
            .mac(&self.device, &[b'i', b'd', creds.len() as u8])
            .to_vec();
        creds.push(id.clone());
        self.touches.fetch_add(1, Ordering::SeqCst);
        Ok(id)
    }

    fn secret(
        &self,
        credentials: &[Vec<u8>],
        salt: &[u8; SECRET_LEN],
        pin: Option<&str>,
    ) -> Result<Secret, Error> {
        self.check(pin)?;
        let creds = self.credentials.lock().expect("credentials");
        let credential = credentials
            .iter()
            .find(|c| creds.contains(c))
            .ok_or(Error::NotRegistered)?
            .clone();
        let cred_random = self.mac(&self.device, &credential);
        let secret = Zeroizing::new(self.mac(&cred_random, &prf_salt(salt)));
        self.touches.fetch_add(1, Ordering::SeqCst);
        Ok(Secret { credential, secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_key_behaves_like_hmac_secret() {
        let a = SoftKey::new(1, "1234");
        let b = SoftKey::new(2, "1234");
        let salt = [7u8; SECRET_LEN];
        assert_eq!(a.register(None, &[]), Err(Error::PinRequired));
        assert_eq!(
            a.register(Some("0000"), &[]),
            Err(Error::PinInvalid { retries: Some(7) })
        );
        let ca = a.register(Some("1234"), &[]).unwrap();
        let cb = b.register(Some("1234"), &[]).unwrap();
        assert_ne!(ca, cb);
        // Ten sam klucz, poświadczenie i sól: ten sam sekret; inna sól albo inny klucz: inny.
        let s1 = a
            .secret(std::slice::from_ref(&ca), &salt, Some("1234"))
            .unwrap();
        let s2 = a
            .secret(&[cb.clone(), ca.clone()], &salt, Some("1234"))
            .unwrap();
        assert_eq!(s1.credential, ca);
        assert_eq!(*s1.secret, *s2.secret);
        let other = a
            .secret(std::slice::from_ref(&ca), &[8u8; SECRET_LEN], Some("1234"))
            .unwrap();
        assert_ne!(*s1.secret, *other.secret);
        let sb = b
            .secret(&[ca.clone(), cb.clone()], &salt, Some("1234"))
            .unwrap();
        assert_eq!(sb.credential, cb);
        assert_ne!(*sb.secret, *s1.secret);
        // Cudze poświadczenie, klucz już zarejestrowany, klucz wyjęty.
        assert!(matches!(
            a.secret(std::slice::from_ref(&cb), &salt, Some("1234")),
            Err(Error::NotRegistered)
        ));
        assert_eq!(
            a.register(Some("1234"), std::slice::from_ref(&ca)),
            Err(Error::AlreadyRegistered)
        );
        a.set_present(false);
        assert!(matches!(
            a.secret(std::slice::from_ref(&ca), &salt, Some("1234")),
            Err(Error::NoDevice)
        ));
        assert_eq!(a.touches(), 4);
        // Klucz z PIN-em w oknie systemu nie potrzebuje PIN-u w wywołaniu.
        let w = SoftKey::new(3, "9999").system_pin();
        assert_eq!(w.pin_entry(), PinEntry::System);
        let cw = w.register(None, &[]).unwrap();
        assert!(w.secret(&[cw], &salt, None).is_ok());
    }

    #[test]
    fn pin_blocks_after_eight_failures() {
        let k = SoftKey::new(4, "1234");
        for left in (0..8).rev() {
            assert_eq!(
                k.register(Some("zly"), &[]),
                Err(Error::PinInvalid {
                    retries: Some(left)
                })
            );
        }
        assert_eq!(k.register(Some("1234"), &[]), Err(Error::PinBlocked));
    }
}
