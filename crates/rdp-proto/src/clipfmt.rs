//! Czyste funkcje formatów schowka RDP: obraz DIB <-> RGBA, nagłówek CF_HTML i bezpieczne ścieżki
//! plików przysłanych przez serwer. Dane z serwera są niezaufane, więc każde parsowanie jest ograniczone.

use std::path::PathBuf;

/// Największy obraz, jaki przyjmujemy (szerokość lub wysokość).
pub const MAX_IMAGE_SIDE: u32 = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rgba {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn i32_at(b: &[u8], o: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Dekoduje bitmapę DIB (nagłówek BITMAPINFOHEADER albo nowszy, 24 lub 32 bity, bez kompresji).
pub fn dib_to_rgba(dib: &[u8]) -> Option<Rgba> {
    let header = u32_at(dib, 0)? as usize;
    if header < 40 || header > dib.len() {
        return None;
    }
    let width = i32_at(dib, 4)?;
    let raw_height = i32_at(dib, 8)?;
    let bits = u16_at(dib, 14)?;
    let compression = u32_at(dib, 16)?;
    let colors_used = u32_at(dib, 32)? as usize;
    // Tablica kolorów jest dla 24 i 32 bitów opcjonalna (optymalizacja palety); przeskakujemy ją.
    if width <= 0 || raw_height == 0 || !(bits == 24 || bits == 32) || colors_used > 256 {
        return None;
    }
    // 0 = BI_RGB, 3 = BI_BITFIELDS (przyjmujemy standardowy układ BGRA).
    if compression != 0 && compression != 3 {
        return None;
    }
    let (w, h) = (width as u32, raw_height.unsigned_abs());
    if w > MAX_IMAGE_SIDE || h > MAX_IMAGE_SIDE {
        return None;
    }
    let top_down = raw_height < 0;
    let mut offset = header;
    if compression == 3 && header == 40 {
        offset += 12; // trzy maski kolorów
    }
    offset += colors_used * 4;
    let bytes_pp = usize::from(bits / 8);
    let stride = (w as usize * bytes_pp).div_ceil(4) * 4;
    let needed = offset.checked_add(stride.checked_mul(h as usize)?)?;
    if dib.len() < needed {
        return None;
    }
    let mut rgba = Vec::with_capacity(w as usize * h as usize * 4);
    for row in 0..h as usize {
        let src_row = if top_down { row } else { h as usize - 1 - row };
        let line = &dib[offset + src_row * stride..][..w as usize * bytes_pp];
        for px in line.chunks_exact(bytes_pp) {
            let alpha = if bytes_pp == 4 { px[3] } else { 255 };
            rgba.extend_from_slice(&[px[2], px[1], px[0], alpha]);
        }
    }
    // Wiele aplikacji zapisuje 32 bity z zerowym kanałem alfa: wtedy obraz ma być nieprzezroczysty.
    if bytes_pp == 4 && rgba.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
        rgba.as_chunks_mut::<4>()
            .0
            .iter_mut()
            .for_each(|p| p[3] = 255);
    }
    Some(Rgba {
        width: w,
        height: h,
        rgba,
    })
}

/// Koduje RGBA jako DIB 32 bity (BITMAPINFOHEADER, od dołu do góry).
pub fn rgba_to_dib(img: &Rgba) -> Option<Vec<u8>> {
    let (w, h) = (img.width, img.height);
    if w == 0
        || h == 0
        || w > MAX_IMAGE_SIDE
        || h > MAX_IMAGE_SIDE
        || img.rgba.len() != w as usize * h as usize * 4
    {
        return None;
    }
    let data_len = w as usize * h as usize * 4;
    let mut out = Vec::with_capacity(40 + data_len);
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&(h as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 16]); // rozdzielczość i palety
    for row in (0..h as usize).rev() {
        for px in img.rgba[row * w as usize * 4..][..w as usize * 4]
            .as_chunks::<4>()
            .0
        {
            out.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }
    Some(out)
}

/// Opakowuje fragment HTML w nagłówek CF_HTML ("HTML Format").
pub fn html_to_cf_html(fragment: &str) -> Vec<u8> {
    const PREFIX: &str = "<html><body>\r\n<!--StartFragment-->";
    const SUFFIX: &str = "<!--EndFragment-->\r\n</body></html>";
    let header = |start_html: usize, end_html: usize, start_frag: usize, end_frag: usize| {
        format!(
            "Version:0.9\r\nStartHTML:{start_html:010}\r\nEndHTML:{end_html:010}\r\nStartFragment:{start_frag:010}\r\nEndFragment:{end_frag:010}\r\n"
        )
    };
    let header_len = header(0, 0, 0, 0).len();
    let start_html = header_len;
    let start_frag = start_html + PREFIX.len();
    let end_frag = start_frag + fragment.len();
    let end_html = end_frag + SUFFIX.len();
    let mut out = header(start_html, end_html, start_frag, end_frag).into_bytes();
    out.extend_from_slice(PREFIX.as_bytes());
    out.extend_from_slice(fragment.as_bytes());
    out.extend_from_slice(SUFFIX.as_bytes());
    out
}

/// Wyciąga fragment HTML z danych CF_HTML. Odporny na brakujące albo błędne przesunięcia.
pub fn cf_html_to_html(data: &[u8]) -> Option<String> {
    let data = match data.iter().position(|&b| b == 0) {
        Some(n) => &data[..n],
        None => data,
    };
    let text = String::from_utf8_lossy(data);
    let field = |name: &str| -> Option<usize> {
        let line = text.lines().take(12).find_map(|l| l.strip_prefix(name))?;
        line.trim().parse().ok()
    };
    if let (Some(s), Some(e)) = (field("StartFragment:"), field("EndFragment:"))
        && s <= e
        && e <= data.len()
        && let Ok(frag) = std::str::from_utf8(&data[s..e])
    {
        return Some(frag.to_owned());
    }
    // Bez poprawnych przesunięć: szukamy znaczników, a w ostateczności bierzemy całość po nagłówku.
    let (a, b) = (
        text.find("<!--StartFragment-->"),
        text.find("<!--EndFragment-->"),
    );
    if let (Some(a), Some(b)) = (a, b) {
        let start = a + "<!--StartFragment-->".len();
        if start <= b {
            return Some(text[start..b].to_owned());
        }
    }
    let html = text.find("<html").or_else(|| text.find('<'))?;
    Some(text[html..].to_owned())
}

/// Nazwy urządzeń Windows (z rozszerzeniem lub bez); `COM¹`-`COM³` i `LPT¹`-`LPT³` to cyfry
/// w indeksie górnym, które Windows też traktuje jak urządzenia.
const RESERVED: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

fn safe_component(c: &str) -> Option<String> {
    if c.is_empty() || c == "." || c == ".." || c.len() > 255 {
        return None;
    }
    if c.chars().any(|ch| {
        ch.is_control() || matches!(ch, ':' | '<' | '>' | '"' | '|' | '?' | '*' | '/' | '\\')
    }) {
        return None;
    }
    let trimmed = c.trim_end_matches(['.', ' ']);
    if trimmed.is_empty() {
        return None;
    }
    // Windows pomija spacje na końcu nazwy urządzenia, więc "CON .txt" to też konsola.
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Bezpieczna ścieżka względna dla elementu listy plików z serwera (separator `\` albo `/`).
/// Zwraca `None` dla ścieżek bezwzględnych, z `..`, dyskami, znakami sterującymi i nazwami zastrzeżonymi.
pub fn safe_relative_path(relative_dir: Option<&str>, name: &str) -> Option<PathBuf> {
    const MAX_DEPTH: usize = 32;
    let mut out = PathBuf::new();
    let mut depth = 0;
    let dir = relative_dir.unwrap_or("");
    if dir.starts_with(['\\', '/']) || name.starts_with(['\\', '/']) {
        return None;
    }
    for part in dir.split(['\\', '/']).filter(|p| !p.is_empty()) {
        out.push(safe_component(part)?);
        depth += 1;
    }
    if name.contains(['\\', '/']) {
        return None;
    }
    out.push(safe_component(name)?);
    depth += 1;
    (depth <= MAX_DEPTH).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn dib_round_trip_keeps_pixels_and_orientation() {
        let img = Rgba {
            width: 3,
            height: 2,
            rgba: vec![
                255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, // górny wiersz
                10, 20, 30, 128, 40, 50, 60, 255, 70, 80, 90, 0, // dolny wiersz
            ],
        };
        let dib = rgba_to_dib(&img).unwrap();
        assert_eq!(dib_to_rgba(&dib).unwrap(), img);
    }

    #[test]
    fn dib_24_bit_with_padding_and_top_down() {
        // 1x2, 24 bity, wiersze dopełnione do 4 bajtów, od góry do dołu (wysokość ujemna).
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&(-2i32).to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&24u16.to_le_bytes());
        dib.extend_from_slice(&[0u8; 24]);
        dib.extend_from_slice(&[1, 2, 3, 0]); // BGR + dopełnienie
        dib.extend_from_slice(&[4, 5, 6, 0]);
        let img = dib_to_rgba(&dib).unwrap();
        assert_eq!(img.rgba, vec![3, 2, 1, 255, 6, 5, 4, 255]);
    }

    #[test]
    fn optional_color_table_in_24_bit_dib_is_skipped() {
        // 1x1, 24 bity, dwa wpisy tablicy kolorów (biClrUsed = 2) przed pikselami.
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&24u16.to_le_bytes());
        dib.extend_from_slice(&[0u8; 16]); // kompresja, rozmiar, rozdzielczość
        dib.extend_from_slice(&2u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        dib.extend_from_slice(&[0xAA; 8]); // tablica kolorów
        dib.extend_from_slice(&[1, 2, 3, 0]);
        let img = dib_to_rgba(&dib).unwrap();
        assert_eq!(img.rgba, vec![3, 2, 1, 255]);
    }

    #[test]
    fn zero_alpha_32_bit_becomes_opaque() {
        let img = Rgba {
            width: 1,
            height: 1,
            rgba: vec![9, 8, 7, 0],
        };
        let out = dib_to_rgba(&rgba_to_dib(&img).unwrap()).unwrap();
        assert_eq!(out.rgba, vec![9, 8, 7, 255]);
    }

    #[test]
    fn hostile_dibs_are_rejected_without_panics() {
        assert!(dib_to_rgba(&[]).is_none());
        assert!(dib_to_rgba(&[0u8; 39]).is_none());
        // Ogromne wymiary.
        let mut big = rgba_to_dib(&Rgba {
            width: 1,
            height: 1,
            rgba: vec![0; 4],
        })
        .unwrap();
        big[4..8].copy_from_slice(&i32::MAX.to_le_bytes());
        assert!(dib_to_rgba(&big).is_none());
        // Obcięte dane pikseli.
        let ok = rgba_to_dib(&Rgba {
            width: 4,
            height: 4,
            rgba: vec![1; 64],
        })
        .unwrap();
        assert!(dib_to_rgba(&ok[..ok.len() - 1]).is_none());
        // Paleta (8 bitów) nie jest obsługiwana.
        let mut pal = ok.clone();
        pal[14..16].copy_from_slice(&8u16.to_le_bytes());
        assert!(dib_to_rgba(&pal).is_none());
        // Nagłówek dłuższy niż dane.
        let mut hdr = ok;
        hdr[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(dib_to_rgba(&hdr).is_none());
        assert!(
            rgba_to_dib(&Rgba {
                width: 2,
                height: 2,
                rgba: vec![0; 3]
            })
            .is_none()
        );
    }

    #[test]
    fn cf_html_round_trip_with_unicode() {
        let frag = "<b>zażółć gęślą jaźń</b>";
        let encoded = html_to_cf_html(frag);
        assert!(String::from_utf8_lossy(&encoded).starts_with("Version:0.9\r\nStartHTML:"));
        assert_eq!(cf_html_to_html(&encoded).as_deref(), Some(frag));
    }

    #[test]
    fn cf_html_tolerates_bad_offsets_and_trailing_nul() {
        let mut bad = html_to_cf_html("<i>x</i>");
        let s = String::from_utf8(bad.clone())
            .unwrap()
            .replace("StartFragment:00000", "StartFragment:99999");
        bad = s.into_bytes();
        bad.push(0);
        assert_eq!(cf_html_to_html(&bad).as_deref(), Some("<i>x</i>"));
        assert_eq!(
            cf_html_to_html(b"<p>goly</p>").as_deref(),
            Some("<p>goly</p>")
        );
        assert_eq!(cf_html_to_html(b"bez znacznikow"), None);
    }

    #[test]
    fn safe_paths_accept_normal_and_reject_traversal() {
        assert_eq!(
            safe_relative_path(None, "plik.txt"),
            Some(Path::new("plik.txt").into())
        );
        assert_eq!(
            safe_relative_path(Some("temp\\sub"), "a.txt"),
            Some(Path::new("temp/sub/a.txt").into())
        );
        assert_eq!(
            safe_relative_path(Some("a/b"), "ż ó.txt").unwrap(),
            Path::new("a/b/ż ó.txt")
        );
        for (dir, name) in [
            (Some("..\\x"), "a"),
            (Some("a\\..\\b"), "c"),
            (None, ".."),
            (None, "."),
            (Some("\\abs"), "a"),
            (Some("/etc"), "passwd"),
            (None, "C:\\Windows\\a"),
            (None, "a:b"),
            (None, "con"),
            (None, "NUL.txt"),
            (Some("ok\\LPT1"), "a"),
            (None, "CONOUT$"),
            (None, "conin$.txt"),
            (None, "COM0"),
            (None, "LPT0.log"),
            (None, "COM\u{b9}"),
            (None, "LPT\u{b3}.txt"),
            (None, "CON .txt"),
            (None, "zly\u{0}znak"),
            (None, ""),
            (None, "a/b"),
        ] {
            assert_eq!(safe_relative_path(dir, name), None, "{dir:?} {name:?}");
        }
        // Końcowe kropki i spacje są przycinane (jak w Windows), a nie przepuszczane.
        assert_eq!(
            safe_relative_path(None, "kropki..."),
            Some(Path::new("kropki").into())
        );
        let deep = "d\\".repeat(40);
        assert_eq!(safe_relative_path(Some(&deep), "a"), None);
    }
}
