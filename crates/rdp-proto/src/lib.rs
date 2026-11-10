//! Protokół między aplikacją a procesem `rdp-worker` (IronRDP działa w osobnym procesie, bo jego
//! zależności nie mieszczą się w jednym `Cargo.lock` z `russh`).
//!
//! Ramka: `u32 LE długość | u8 rodzaj | treść`, gdzie długość obejmuje rodzaj i treść.
//! Rodzaj 1: JSON ([`ToWorker`] albo [`FromWorker`]). Rodzaj 2: fragment obrazu
//! (`x,y,w,h` jako `u16 LE`, potem `w*h*4` bajtów RGBA).

pub mod clipfmt;

use std::fmt;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Górny limit ramki, żeby uszkodzony strumień nie powodował ogromnej alokacji.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
const KIND_JSON: u8 = 1;
const KIND_IMAGE: u8 = 2;
const KIND_CLIP: u8 = 3;

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
    /// Informacja dla użytkownika (np. błąd przenoszenia plików).
    Notice {
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

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Json(Vec<u8>),
    Image(Image),
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

    #[test]
    fn events_are_tagged_snake_case() {
        let json = serde_json::to_string(&FromWorker::Connected {
            width: 1,
            height: 2,
        })
        .unwrap();
        assert_eq!(json, r#"{"t":"connected","width":1,"height":2}"#);
    }
}
