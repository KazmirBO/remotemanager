//! Protokół między aplikacją a procesem `rdp-worker` (IronRDP działa w osobnym procesie, bo jego
//! zależności nie mieszczą się w jednym `Cargo.lock` z `russh`).
//!
//! Ramka: `u32 LE długość | u8 rodzaj | treść`, gdzie długość obejmuje rodzaj i treść.
//! Rodzaj 1: JSON ([`ToWorker`] albo [`FromWorker`]). Rodzaj 2: fragment obrazu
//! (`x,y,w,h` jako `u16 LE`, potem `w*h*4` bajtów RGBA). Rodzaj 3: dane schowka (bajt rodzaju
//! danych, potem dane). Rodzaj 4: bitmapa wskaźnika myszy ([`Pointer`]: `w,h,hot_x,hot_y` jako
//! `u16 LE`, potem `w*h*4` bajtów RGBA, alfa nieprzemnożona, wiersze od góry; bok od 1 do
//! [`MAX_POINTER_SIDE`]).

pub mod clipfmt;

use std::fmt;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Górny limit ramki, żeby uszkodzony strumień nie powodował ogromnej alokacji.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// Wersja protokołu między aplikacją a procesem RDP. Proces podaje ją w pierwszej wiadomości
/// (`FromWorker::Hello`), a aplikacja odrzuca proces, który jej nie podał albo podał inną. Zwiększaj
/// przy każdej zmianie `ToWorker`, `FromWorker` albo ramek: stary proces obok nowej aplikacji działał
/// po cichu bez nowszych funkcji (np. bez schowka), co wyglądało jak błąd w aplikacji.
pub const PROTOCOL: u32 = 4;
const KIND_JSON: u8 = 1;
const KIND_IMAGE: u8 = 2;
const KIND_CLIP: u8 = 3;
const KIND_POINTER: u8 = 4;

/// Największy bok bitmapy wskaźnika (limit "dużego wskaźnika" RDP to 384 x 384). Proces zamienia
/// większe kształty na [`FromWorker::PointerDefault`], a odczyt ramki takiej bitmapy odrzuca.
pub const MAX_POINTER_SIDE: u16 = 384;

/// Profil łącza: dobór ustawień wydajności sesji (tapeta, animacje, motywy).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkProfile {
    /// Sieć lokalna albo szybkie łącze: ustawienia domyślne.
    #[default]
    Fast,
    /// Wolne łącze: bez tapety, animacji, motywów i cienia kursora.
    Slow,
}

/// Przekierowanie czytników kart inteligentnych do sesji (kanał `rdpdr`).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CardRedirect {
    #[default]
    Off,
    /// Czytniki pod prawdziwymi nazwami.
    On,
    /// Czytniki pod neutralnymi nazwami ("Smart Card Reader 1").
    Neutral,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: Option<String>,
    pub password: String,
    pub kerberos: bool,
    /// Adres KDC (`tcp://host:88`) albo proxy KKDCP.
    pub kdc: Option<String>,
    pub width: u16,
    pub height: u16,
    /// Profil łącza; brak pola (starszy nadawca) oznacza `Fast`.
    #[serde(default)]
    pub profile: LinkProfile,
    /// Przekierowanie kluczy bezpieczeństwa (kanał WebAuthn); brak pola oznacza wyłączone.
    #[serde(default)]
    pub webauthn: bool,
    /// Przekierowanie czytników kart inteligentnych; brak pola oznacza wyłączone.
    #[serde(default)]
    pub smartcard: CardRedirect,
}

impl fmt::Debug for ConnectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectParams")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"***")
            .field("kerberos", &self.kerberos)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("profile", &self.profile)
            .field("webauthn", &self.webauthn)
            .field("smartcard", &self.smartcard)
            .finish()
    }
}

/// Polecenia aplikacji dla procesu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToWorker {
    Connect(ConnectParams),
    /// Odpowiedź na [`FromWorker::Cert`].
    Trust {
        accept: bool,
    },
    MouseMove {
        x: u16,
        y: u16,
    },
    /// 0 lewy, 1 środkowy, 2 prawy.
    MouseButton {
        button: u8,
        down: bool,
    },
    Wheel {
        vertical: bool,
        delta: i16,
    },
    Key {
        scancode: u8,
        extended: bool,
        down: bool,
    },
    /// Ctrl+Alt+Del.
    CtrlAltDel,
    /// Prośba o zmianę rozmiaru pulpitu (kanał Display Control); serwer może jej nie obsługiwać.
    Resize {
        width: u16,
        height: u16,
    },
    /// Lokalny schowek zawiera podane formaty: ogłoś je serwerowi (dane pobierze on przez [`FromWorker::ClipRequest`]).
    ClipAnnounce {
        kinds: Vec<ClipKind>,
    },
    /// Lokalny schowek zawiera pliki albo katalogi (ścieżki bezwzględne); proces sam je wylicza i serwuje.
    ClipAnnounceFiles {
        paths: Vec<String>,
    },
    /// Pobierz dane zdalnego schowka w danym formacie (odpowiedź: ramka [`Message::Clip`]).
    ClipFetch {
        kind: ClipKind,
    },
    /// Pobierz listę zdalnych plików (odpowiedź: [`FromWorker::ClipFiles`]).
    ClipFetchFiles,
    /// Pobierz zdalne pliki z ostatniej listy do podanego katalogu.
    ClipDownload {
        dir: String,
    },
    /// Odpowiedź na [`FromWorker::ClipRequest`]: puste dane oznaczają brak danych. Nie jest serializowane
    /// do JSON, bo płynie ramką binarną ([`Message::Clip`]).
    #[serde(skip)]
    ClipData {
        kind: ClipKind,
        data: Vec<u8>,
    },
    Close,
}

/// Rodzaj danych schowka.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ClipKind {
    /// Tekst UTF-8.
    Text,
    /// Fragment HTML w UTF-8 (bez nagłówka CF_HTML).
    Html,
    /// Obraz jako DIB (patrz [`clipfmt`]).
    Image,
}

impl ClipKind {
    fn to_byte(self) -> u8 {
        match self {
            ClipKind::Text => 1,
            ClipKind::Html => 2,
            ClipKind::Image => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(ClipKind::Text),
            2 => Some(ClipKind::Html),
            3 => Some(ClipKind::Image),
            _ => None,
        }
    }
}

/// Zdalny plik albo katalog z listy schowka.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteFile {
    /// Ścieżka względna z separatorem `/`.
    pub path: String,
    pub size: u64,
    pub dir: bool,
}

/// Zdarzenia procesu dla aplikacji.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FromWorker {
    /// Certyfikat serwera czeka na decyzję ([`ToWorker::Trust`]); hasło nie zostało jeszcze wysłane.
    Cert {
        fingerprint: String,
        subject: String,
    },
    Connected {
        width: u16,
        height: u16,
    },
    Resized {
        width: u16,
        height: u16,
    },
    /// Zawartość zdalnego schowka się zmieniła: dostępne formaty.
    ClipRemote {
        kinds: Vec<ClipKind>,
        files: bool,
    },
    /// Serwer prosi o dane w danym formacie (odpowiedź: ramka [`Message::Clip`]).
    ClipRequest {
        kind: ClipKind,
    },
    /// Lista zdalnych plików gotowych do pobrania.
    ClipFiles {
        files: Vec<RemoteFile>,
    },
    /// Pliki pobrane do katalogu; `paths` to elementy najwyższego poziomu.
    ClipFilesDone {
        paths: Vec<String>,
    },
    /// Serwer przywrócił domyślny wskaźnik systemowy (lokalny kursor wraca do strzałki).
    PointerDefault,
    /// Serwer ukrył wskaźnik. Przy kształcie z pamięci podręcznej biblioteka zgłasza to tuż przed
    /// bitmapą ([`Message::Pointer`]), więc odbiorca ma przyjąć stan z ostatniej wiadomości.
    PointerHidden,
    /// Pierwsza wiadomość procesu: wersja protokołu (`PROTOCOL`).
    Hello {
        protocol: u32,
    },
    /// Informacja dla użytkownika (np. błąd przenoszenia plików).
    Notice {
        message: String,
    },
    /// Wpis do dziennika diagnostycznego aplikacji (np. etapy inicjalizacji schowka). Nie trafia do
    /// interfejsu i nie może zawierać treści schowka ani haseł.
    Log {
        message: String,
    },
    Error {
        message: String,
    },
    Closed {
        reason: String,
    },
}

/// Fragment obrazu RGBA.
#[derive(Clone, PartialEq, Eq)]
pub struct Image {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub rgba: Vec<u8>,
}

impl fmt::Debug for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Image {}x{} @ {},{} ({} B)",
            self.width,
            self.height,
            self.x,
            self.y,
            self.rgba.len()
        )
    }
}

/// Bitmapa wskaźnika myszy: RGBA, alfa nieprzemnożona, wiersze od góry; `hot_x`/`hot_y` to punkt
/// zaczepienia w pikselach bitmapy.
#[derive(Clone, PartialEq, Eq)]
pub struct Pointer {
    pub width: u16,
    pub height: u16,
    pub hot_x: u16,
    pub hot_y: u16,
    pub rgba: Vec<u8>,
}

impl fmt::Debug for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pointer {}x{} hot {},{} ({} B)",
            self.width,
            self.height,
            self.hot_x,
            self.hot_y,
            self.rgba.len()
        )
    }
}

impl Pointer {
    /// Czy wymiary są dozwolone (bok od 1 do [`MAX_POINTER_SIDE`]) i zgadzają się z długością danych.
    pub fn is_valid(&self) -> bool {
        (1..=MAX_POINTER_SIDE).contains(&self.width)
            && (1..=MAX_POINTER_SIDE).contains(&self.height)
            && self.rgba.len() == usize::from(self.width) * usize::from(self.height) * 4
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Json(Vec<u8>),
    Image(Image),
    /// Bitmapa wskaźnika myszy (od procesu do aplikacji).
    Pointer(Pointer),
    /// Dane schowka (tekst, HTML albo obraz) w jedną stronę.
    Clip {
        kind: ClipKind,
        data: Vec<u8>,
    },
}

fn write_frame(w: &mut impl Write, kind: u8, parts: &[&[u8]]) -> io::Result<()> {
    let len = 1 + parts.iter().map(|p| p.len()).sum::<usize>();
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ramka za duża"));
    }
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.push(kind);
    for p in parts {
        out.extend_from_slice(p);
    }
    // Jedno `write_all`, żeby ramki z różnych wątków (pod blokadą) się nie przeplatały.
    w.write_all(&out)?;
    w.flush()
}

pub fn write_json<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    write_frame(w, KIND_JSON, &[&body])
}

pub fn write_clip(w: &mut impl Write, kind: ClipKind, data: &[u8]) -> io::Result<()> {
    write_frame(w, KIND_CLIP, &[&[kind.to_byte()], data])
}

pub fn write_image(w: &mut impl Write, img: &Image) -> io::Result<()> {
    if img.rgba.len() != usize::from(img.width) * usize::from(img.height) * 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rozmiar bufora nie pasuje do wymiarów",
        ));
    }
    let mut head = [0u8; 8];
    for (i, v) in [img.x, img.y, img.width, img.height]
        .into_iter()
        .enumerate()
    {
        head[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    write_frame(w, KIND_IMAGE, &[&head, &img.rgba])
}

pub fn write_pointer(w: &mut impl Write, p: &Pointer) -> io::Result<()> {
    if !p.is_valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wymiary wskaźnika są niedozwolone albo nie pasują do bufora",
        ));
    }
    let mut head = [0u8; 8];
    for (i, v) in [p.width, p.height, p.hot_x, p.hot_y]
        .into_iter()
        .enumerate()
    {
        head[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    write_frame(w, KIND_POINTER, &[&head, &p.rgba])
}

/// Czyta kolejną wiadomość; `Ok(None)` przy czystym końcu strumienia.
pub fn read_message(r: &mut impl Read) -> io::Result<Option<Message>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nieprawidłowa długość ramki",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let kind = body[0];
    let payload = &body[1..];
    match kind {
        KIND_JSON => Ok(Some(Message::Json(payload.to_vec()))),
        KIND_IMAGE => {
            if payload.len() < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "obcięty nagłówek obrazu",
                ));
            }
            let u16_at = |i: usize| u16::from_le_bytes([payload[i], payload[i + 1]]);
            let (x, y, width, height) = (u16_at(0), u16_at(2), u16_at(4), u16_at(6));
            let rgba = payload[8..].to_vec();
            if rgba.len() != usize::from(width) * usize::from(height) * 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rozmiar obrazu nie pasuje do wymiarów",
                ));
            }
            Ok(Some(Message::Image(Image {
                x,
                y,
                width,
                height,
                rgba,
            })))
        }
        KIND_POINTER => {
            if payload.len() < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "obcięty nagłówek wskaźnika",
                ));
            }
            let u16_at = |i: usize| u16::from_le_bytes([payload[i], payload[i + 1]]);
            let pointer = Pointer {
                width: u16_at(0),
                height: u16_at(2),
                hot_x: u16_at(4),
                hot_y: u16_at(6),
                rgba: payload[8..].to_vec(),
            };
            if !pointer.is_valid() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wymiary wskaźnika niedozwolone albo niezgodne z rozmiarem danych",
                ));
            }
            Ok(Some(Message::Pointer(pointer)))
        }
        KIND_CLIP => {
            let kind = payload
                .first()
                .copied()
                .and_then(ClipKind::from_byte)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "nieznany rodzaj danych schowka")
                })?;
            Ok(Some(Message::Clip {
                kind,
                data: payload[1..].to_vec(),
            }))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("nieznany rodzaj ramki {other}"),
        )),
    }
}

pub fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ConnectParams {
        ConnectParams {
            host: "dc01".into(),
            port: 3389,
            username: "u".into(),
            domain: Some("D".into()),
            password: "sekret".into(),
            kerberos: false,
            kdc: None,
            width: 1280,
            height: 800,
            profile: LinkProfile::Fast,
            webauthn: false,
            smartcard: CardRedirect::Off,
        }
    }

    #[test]
    fn json_round_trip_and_clean_eof() {
        let mut buf = Vec::new();
        write_json(&mut buf, &ToWorker::Connect(params())).unwrap();
        write_json(
            &mut buf,
            &ToWorker::Key {
                scancode: 0x1e,
                extended: false,
                down: true,
            },
        )
        .unwrap();
        let mut r = buf.as_slice();
        let Some(Message::Json(a)) = read_message(&mut r).unwrap() else {
            panic!()
        };
        assert_eq!(
            parse_json::<ToWorker>(&a).unwrap(),
            ToWorker::Connect(params())
        );
        let Some(Message::Json(b)) = read_message(&mut r).unwrap() else {
            panic!()
        };
        assert_eq!(
            parse_json::<ToWorker>(&b).unwrap(),
            ToWorker::Key {
                scancode: 0x1e,
                extended: false,
                down: true
            }
        );
        assert_eq!(read_message(&mut r).unwrap(), None);
    }

    #[test]
    fn image_round_trip() {
        let img = Image {
            x: 3,
            y: 4,
            width: 2,
            height: 1,
            rgba: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = Vec::new();
        write_image(&mut buf, &img).unwrap();
        assert_eq!(
            read_message(&mut buf.as_slice()).unwrap(),
            Some(Message::Image(img))
        );
    }

    #[test]
    fn rejects_bad_frames() {
        // Zła długość obrazu przy zapisie.
        let bad = Image {
            x: 0,
            y: 0,
            width: 2,
            height: 2,
            rgba: vec![0; 3],
        };
        assert!(write_image(&mut Vec::new(), &bad).is_err());
        // Zerowa i zbyt duża długość.
        assert!(read_message(&mut [0u8, 0, 0, 0].as_slice()).is_err());
        assert!(read_message(&mut u32::MAX.to_le_bytes().as_slice()).is_err());
        // Nieznany rodzaj.
        assert!(read_message(&mut [1u8, 0, 0, 0, 9].as_slice()).is_err());
        // Obcięta treść.
        assert!(read_message(&mut [10u8, 0, 0, 0, 1, b'{'].as_slice()).is_err());
    }

    #[test]
    fn debug_hides_password() {
        let s = format!("{:?}", ToWorker::Connect(params()));
        assert!(!s.contains("sekret"));
        assert!(s.contains("***"));
    }

    #[test]
    fn resize_is_tagged_snake_case() {
        let json = serde_json::to_string(&ToWorker::Resize {
            width: 800,
            height: 600,
        })
        .unwrap();
        assert_eq!(json, r#"{"t":"resize","width":800,"height":600}"#);
    }

    #[test]
    fn clipboard_messages_round_trip() {
        for m in [
            ToWorker::ClipAnnounce {
                kinds: vec![ClipKind::Text, ClipKind::Image],
            },
            ToWorker::ClipAnnounceFiles {
                paths: vec!["/tmp/a b.txt".into()],
            },
            ToWorker::ClipFetch {
                kind: ClipKind::Html,
            },
            ToWorker::ClipFetchFiles,
            ToWorker::ClipDownload {
                dir: "/tmp/x".into(),
            },
        ] {
            let json = serde_json::to_vec(&m).unwrap();
            assert_eq!(parse_json::<ToWorker>(&json).unwrap(), m);
        }
        for ev in [
            FromWorker::ClipRemote {
                kinds: vec![ClipKind::Html],
                files: true,
            },
            FromWorker::ClipRequest {
                kind: ClipKind::Text,
            },
            FromWorker::ClipFiles {
                files: vec![RemoteFile {
                    path: "a/b.txt".into(),
                    size: 5,
                    dir: false,
                }],
            },
            FromWorker::ClipFilesDone {
                paths: vec!["/tmp/x/a".into()],
            },
            FromWorker::Notice {
                message: "zażółć".into(),
            },
            FromWorker::Log {
                message: "schowek: kanał zainicjowany".into(),
            },
            FromWorker::Hello { protocol: PROTOCOL },
        ] {
            assert_eq!(
                parse_json::<FromWorker>(&serde_json::to_vec(&ev).unwrap()).unwrap(),
                ev
            );
        }
        assert_eq!(
            serde_json::to_string(&ToWorker::ClipFetch {
                kind: ClipKind::Image
            })
            .unwrap(),
            r#"{"t":"clip_fetch","kind":"image"}"#
        );
    }

    #[test]
    fn clip_frame_round_trip_and_rejects_unknown_kind() {
        let mut buf = Vec::new();
        write_clip(&mut buf, ClipKind::Html, "<b>x</b>".as_bytes()).unwrap();
        write_clip(&mut buf, ClipKind::Image, &[]).unwrap();
        let mut r = buf.as_slice();
        assert_eq!(
            read_message(&mut r).unwrap(),
            Some(Message::Clip {
                kind: ClipKind::Html,
                data: b"<b>x</b>".to_vec()
            })
        );
        assert_eq!(
            read_message(&mut r).unwrap(),
            Some(Message::Clip {
                kind: ClipKind::Image,
                data: vec![]
            })
        );
        assert!(read_message(&mut [2u8, 0, 0, 0, 3, 99].as_slice()).is_err());
        assert!(read_message(&mut [1u8, 0, 0, 0, 3].as_slice()).is_err());
    }

    fn pointer(w: u16, h: u16) -> Pointer {
        Pointer {
            width: w,
            height: h,
            hot_x: 1,
            hot_y: 2,
            rgba: (0..usize::from(w) * usize::from(h) * 4)
                .map(|i| (i % 251) as u8)
                .collect(),
        }
    }

    #[test]
    fn pointer_frame_round_trip() {
        for (w, h) in [(1, 1), (32, 24), (MAX_POINTER_SIDE, MAX_POINTER_SIDE)] {
            let p = pointer(w, h);
            let mut buf = Vec::new();
            write_pointer(&mut buf, &p).unwrap();
            // Układ ramki: długość, rodzaj 4, cztery pola u16 LE, dane.
            assert_eq!(buf[4], 4);
            assert_eq!(
                &buf[5..13],
                &[w.to_le_bytes(), h.to_le_bytes(), [1, 0], [2, 0]].concat()
            );
            assert_eq!(
                read_message(&mut buf.as_slice()).unwrap(),
                Some(Message::Pointer(p))
            );
        }
    }

    /// Ramka rodzaju 4 złożona ręcznie (obejście walidacji zapisu).
    fn raw_pointer_frame(w: u16, h: u16, data_len: usize) -> Vec<u8> {
        let mut head = Vec::new();
        for v in [w, h, 0, 0] {
            head.extend_from_slice(&v.to_le_bytes());
        }
        let data = vec![0u8; data_len];
        let mut out = Vec::new();
        write_frame(&mut out, KIND_POINTER, &[&head, &data]).unwrap();
        out
    }

    #[test]
    fn pointer_frame_rejects_bad_sizes() {
        let side = usize::from(MAX_POINTER_SIDE);
        for (w, h, len) in [
            (0u16, 4u16, 0usize),
            (4, 0, 0),
            (0, 0, 0),
            // Zgodny z wymiarami, ale ponad limit boku.
            (MAX_POINTER_SIDE + 1, 1, (side + 1) * 4),
            (1, MAX_POINTER_SIDE + 1, (side + 1) * 4),
            // Dane krótsze albo dłuższe niż wymiary.
            (2, 2, 15),
            (2, 2, 17),
            (2, 2, 0),
        ] {
            let frame = raw_pointer_frame(w, h, len);
            assert!(
                read_message(&mut frame.as_slice()).is_err(),
                "{w}x{h} z {len} B"
            );
        }
        // Obcięty nagłówek.
        assert!(read_message(&mut [4u8, 0, 0, 0, 4, 1, 0, 1, 0].as_slice()).is_err());
        // Zapis stosuje te same reguły.
        let mut bad = pointer(2, 2);
        bad.rgba.pop();
        assert!(write_pointer(&mut Vec::new(), &bad).is_err());
        assert!(write_pointer(&mut Vec::new(), &pointer(0, 0)).is_err());
        let mut huge = pointer(1, 1);
        huge.width = MAX_POINTER_SIDE + 1;
        huge.rgba = vec![0; (side + 1) * 4];
        assert!(write_pointer(&mut Vec::new(), &huge).is_err());
    }

    #[test]
    fn pointer_events_and_link_profile_json() {
        assert_eq!(
            serde_json::to_string(&FromWorker::PointerDefault).unwrap(),
            r#"{"t":"pointer_default"}"#
        );
        assert_eq!(
            serde_json::to_string(&FromWorker::PointerHidden).unwrap(),
            r#"{"t":"pointer_hidden"}"#
        );
        assert_eq!(
            serde_json::to_string(&LinkProfile::Slow).unwrap(),
            r#""slow""#
        );
        // Starszy nadawca nie podaje profilu: domyślnie `Fast`.
        let old = r#"{"host":"h","port":1,"username":"u","domain":null,"password":"p","kerberos":false,"kdc":null,"width":1,"height":2}"#;
        assert_eq!(
            parse_json::<ConnectParams>(old.as_bytes()).unwrap().profile,
            LinkProfile::Fast
        );
    }

    #[test]
    fn events_are_tagged_snake_case() {
        let json = serde_json::to_string(&FromWorker::Connected {
            width: 1,
            height: 2,
        })
        .unwrap();
        assert_eq!(json, r#"{"t":"connected","width":1,"height":2}"#);
    }

    /// Migawka serializacji JSON każdego wariantu `ToWorker` i `FromWorker`. Aplikacja i proces
    /// RDP są budowane osobno (osobne workspace'y), a stara kopia procesu pomija nieznane
    /// komunikaty po cichu, więc zmiana kształtu któregokolwiek wariantu bez podbicia [`PROTOCOL`]
    /// psuje sesje bez śladu. Gdy ten test przestaje przechodzić: zmień migawkę i PODBIJ `PROTOCOL`.
    #[test]
    fn wire_format_snapshot_requires_protocol_bump() {
        // Próbki powstają łańcuchem: wyczerpujące dopasowanie (bez wzorca domyślnego) dla każdego
        // wariantu zwraca próbkę następnego. Nowy wariant nie skompiluje się, dopóki nie dostanie
        // ramienia; dopisz go do łańcucha (dotychczasowy ostatni wariant ma zwracać nowy), a wtedy
        // jego JSON musi trafić do migawki poniżej, inaczej porównanie się nie zgodzi.
        fn next_to(prev: Option<&ToWorker>) -> Option<ToWorker> {
            let Some(prev) = prev else {
                return Some(ToWorker::Connect(params()));
            };
            match prev {
                ToWorker::Connect(_) => Some(ToWorker::Trust { accept: true }),
                ToWorker::Trust { .. } => Some(ToWorker::MouseMove { x: 1, y: 2 }),
                ToWorker::MouseMove { .. } => Some(ToWorker::MouseButton {
                    button: 2,
                    down: true,
                }),
                ToWorker::MouseButton { .. } => Some(ToWorker::Wheel {
                    vertical: true,
                    delta: -120,
                }),
                ToWorker::Wheel { .. } => Some(ToWorker::Key {
                    scancode: 30,
                    extended: false,
                    down: true,
                }),
                ToWorker::Key { .. } => Some(ToWorker::CtrlAltDel),
                ToWorker::CtrlAltDel => Some(ToWorker::Resize {
                    width: 800,
                    height: 600,
                }),
                ToWorker::Resize { .. } => Some(ToWorker::ClipAnnounce {
                    kinds: vec![ClipKind::Text, ClipKind::Html, ClipKind::Image],
                }),
                ToWorker::ClipAnnounce { .. } => Some(ToWorker::ClipAnnounceFiles {
                    paths: vec!["/a".into()],
                }),
                ToWorker::ClipAnnounceFiles { .. } => Some(ToWorker::ClipFetch {
                    kind: ClipKind::Image,
                }),
                ToWorker::ClipFetch { .. } => Some(ToWorker::ClipFetchFiles),
                ToWorker::ClipFetchFiles => Some(ToWorker::ClipDownload { dir: "/d".into() }),
                ToWorker::ClipDownload { .. } => Some(ToWorker::ClipData {
                    kind: ClipKind::Text,
                    data: vec![1],
                }),
                ToWorker::ClipData { .. } => Some(ToWorker::Close),
                ToWorker::Close => None,
            }
        }
        fn next_from(prev: Option<&FromWorker>) -> Option<FromWorker> {
            let Some(prev) = prev else {
                return Some(FromWorker::Cert {
                    fingerprint: "ab".into(),
                    subject: "s".into(),
                });
            };
            match prev {
                FromWorker::Cert { .. } => Some(FromWorker::Connected {
                    width: 1,
                    height: 2,
                }),
                FromWorker::Connected { .. } => Some(FromWorker::Resized {
                    width: 3,
                    height: 4,
                }),
                FromWorker::Resized { .. } => Some(FromWorker::ClipRemote {
                    kinds: vec![ClipKind::Text],
                    files: true,
                }),
                FromWorker::ClipRemote { .. } => Some(FromWorker::ClipRequest {
                    kind: ClipKind::Html,
                }),
                FromWorker::ClipRequest { .. } => Some(FromWorker::ClipFiles {
                    files: vec![RemoteFile {
                        path: "a/b".into(),
                        size: 5,
                        dir: false,
                    }],
                }),
                FromWorker::ClipFiles { .. } => Some(FromWorker::ClipFilesDone {
                    paths: vec!["/x".into()],
                }),
                FromWorker::ClipFilesDone { .. } => Some(FromWorker::Hello { protocol: 2 }),
                FromWorker::Hello { .. } => Some(FromWorker::Notice {
                    message: "n".into(),
                }),
                FromWorker::Notice { .. } => Some(FromWorker::Log {
                    message: "l".into(),
                }),
                FromWorker::Log { .. } => Some(FromWorker::Error {
                    message: "e".into(),
                }),
                FromWorker::Error { .. } => Some(FromWorker::Closed { reason: "r".into() }),
                FromWorker::Closed { .. } => Some(FromWorker::PointerDefault),
                FromWorker::PointerDefault => Some(FromWorker::PointerHidden),
                FromWorker::PointerHidden => None,
            }
        }
        let mut to = Vec::new();
        let mut cur = next_to(None);
        while let Some(m) = cur {
            cur = next_to(Some(&m));
            to.push(m);
        }
        let mut from = Vec::new();
        let mut cur = next_from(None);
        while let Some(m) = cur {
            cur = next_from(Some(&m));
            from.push(m);
        }
        // `ClipData` płynie ramką binarną i nie ma postaci JSON; w migawce stoi za nią znacznik.
        let to_json: Vec<String> = to
            .iter()
            .map(|m| serde_json::to_string(m).unwrap_or_else(|_| BINARY_FRAME.into()))
            .collect();
        let from_json: Vec<String> = from
            .iter()
            .map(|m| serde_json::to_string(m).unwrap())
            .collect();
        // Hasło z danych testowych jest wstawiane w miejsce znacznika, żeby migawka nie zawierała
        // literału wyglądającego na zapisane hasło (skanery sekretów zgłaszają taki zapis).
        let expected_to: Vec<String> = EXPECTED_TO
            .iter()
            .map(|s| s.replace(FIXTURE_PASSWORD, &params().password))
            .collect();
        assert_eq!(
            to_json, expected_to,
            "zmiana migawki wymaga podbicia PROTOCOL"
        );
        assert_eq!(
            from_json, EXPECTED_FROM,
            "zmiana migawki wymaga podbicia PROTOCOL"
        );
        // Migawka zapisana dla bieżącej wartości PROTOCOL; przy podbiciu zaktualizuj obie stałe
        // i liczbę w asercji poniżej.
        assert_eq!(PROTOCOL, 4, "po podbiciu PROTOCOL zaktualizuj migawkę");
    }

    /// Migawka układu binarnego: zmiana numerów rodzajów ramek, bajtów `ClipKind`, kolejności pól
    /// nagłówków obrazu i wskaźnika albo limitów wymaga podbicia `PROTOCOL` (testy okrągłe używają
    /// tych samych funkcji po obu stronach, więc takiej zmiany nie wykryją).
    #[test]
    fn binary_layout_snapshot_requires_protocol_bump() {
        const MSG: &str = "zmiana układu binarnego wymaga podbicia PROTOCOL";
        assert_eq!(
            (KIND_JSON, KIND_IMAGE, KIND_CLIP, KIND_POINTER),
            (1, 2, 3, 4),
            "{MSG}"
        );
        assert_eq!(MAX_FRAME, 64 * 1024 * 1024, "{MSG}");
        assert_eq!(MAX_POINTER_SIDE, 384, "{MSG}");

        let mut buf = Vec::new();
        write_image(
            &mut buf,
            &Image {
                x: 1,
                y: 2,
                width: 1,
                height: 1,
                rgba: vec![0xa1, 0xa2, 0xa3, 0xa4],
            },
        )
        .unwrap();
        assert_eq!(
            buf,
            [
                13, 0, 0, 0, 2, 1, 0, 2, 0, 1, 0, 1, 0, 0xa1, 0xa2, 0xa3, 0xa4
            ],
            "{MSG}"
        );

        buf.clear();
        write_pointer(
            &mut buf,
            &Pointer {
                width: 1,
                height: 1,
                hot_x: 3,
                hot_y: 5,
                rgba: vec![0xb1, 0xb2, 0xb3, 0xb4],
            },
        )
        .unwrap();
        assert_eq!(
            buf,
            [
                13, 0, 0, 0, 4, 1, 0, 1, 0, 3, 0, 5, 0, 0xb1, 0xb2, 0xb3, 0xb4
            ],
            "{MSG}"
        );

        for (kind, byte) in [
            (ClipKind::Text, 1u8),
            (ClipKind::Html, 2),
            (ClipKind::Image, 3),
        ] {
            buf.clear();
            write_clip(&mut buf, kind, b"ab").unwrap();
            assert_eq!(buf, [4, 0, 0, 0, 3, byte, b'a', b'b'], "{MSG}");
        }

        buf.clear();
        write_json(&mut buf, &ToWorker::CtrlAltDel).unwrap();
        assert_eq!(
            buf[..5],
            [(1 + br#"{"t":"ctrl_alt_del"}"#.len()) as u8, 0, 0, 0, 1],
            "{MSG}"
        );
    }

    /// Miejsce wariantu `ClipData` w migawce: nie ma postaci JSON.
    const BINARY_FRAME: &str = "(ramka binarna)";
    /// Znacznik w migawce zastępowany hasłem z `params()`.
    const FIXTURE_PASSWORD: &str = "<FIXTURE>";
    const EXPECTED_TO: &[&str] = &[
        r#"{"t":"connect","host":"dc01","port":3389,"username":"u","domain":"D","password":"<FIXTURE>","kerberos":false,"kdc":null,"width":1280,"height":800,"profile":"fast","webauthn":false,"smartcard":"off"}"#,
        r#"{"t":"trust","accept":true}"#,
        r#"{"t":"mouse_move","x":1,"y":2}"#,
        r#"{"t":"mouse_button","button":2,"down":true}"#,
        r#"{"t":"wheel","vertical":true,"delta":-120}"#,
        r#"{"t":"key","scancode":30,"extended":false,"down":true}"#,
        r#"{"t":"ctrl_alt_del"}"#,
        r#"{"t":"resize","width":800,"height":600}"#,
        r#"{"t":"clip_announce","kinds":["text","html","image"]}"#,
        r#"{"t":"clip_announce_files","paths":["/a"]}"#,
        r#"{"t":"clip_fetch","kind":"image"}"#,
        r#"{"t":"clip_fetch_files"}"#,
        r#"{"t":"clip_download","dir":"/d"}"#,
        BINARY_FRAME,
        r#"{"t":"close"}"#,
    ];
    const EXPECTED_FROM: &[&str] = &[
        r#"{"t":"cert","fingerprint":"ab","subject":"s"}"#,
        r#"{"t":"connected","width":1,"height":2}"#,
        r#"{"t":"resized","width":3,"height":4}"#,
        r#"{"t":"clip_remote","kinds":["text"],"files":true}"#,
        r#"{"t":"clip_request","kind":"html"}"#,
        r#"{"t":"clip_files","files":[{"path":"a/b","size":5,"dir":false}]}"#,
        r#"{"t":"clip_files_done","paths":["/x"]}"#,
        r#"{"t":"hello","protocol":2}"#,
        r#"{"t":"notice","message":"n"}"#,
        r#"{"t":"log","message":"l"}"#,
        r#"{"t":"error","message":"e"}"#,
        r#"{"t":"closed","reason":"r"}"#,
        r#"{"t":"pointer_default"}"#,
        r#"{"t":"pointer_hidden"}"#,
    ];
}
