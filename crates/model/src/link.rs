//! Parser linków `ssh://[użytkownik@]host[:port]` i `rdp://[użytkownik@]host[:port][?user=..&domain=..]`.
//!
//! Link nigdy nie łączy sam: aplikacja pokazuje go użytkownikowi do potwierdzenia.

use crate::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub protocol: Protocol,
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("nieobsługiwany schemat (oczekiwano ssh:// albo rdp://)")]
    Scheme,
    #[error("brak nazwy hosta")]
    NoHost,
    #[error("nieprawidłowy port")]
    Port,
    #[error("nieprawidłowy adres IPv6")]
    Ipv6,
    #[error("link zawiera niedozwolone znaki")]
    Chars,
}

fn percent_decode(s: &str) -> Result<String, LinkError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or(LinkError::Chars)?;
            // `from_str_radix` przyjmuje też wiodący '+', a RFC 3986 dopuszcza tylko cyfry szesnastkowe.
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(LinkError::Chars);
            }
            out.push(u8::from_str_radix(hex, 16).map_err(|_| LinkError::Chars)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| LinkError::Chars)
}

/// Znaki formatujące Unicode (kategoria Cf): kierunek tekstu, znaki zerowej szerokości, BOM.
/// Pozwalałyby sfałszować adres pokazany w oknie potwierdzenia.
fn is_format_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

fn valid_text(s: &str) -> bool {
    !s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || is_format_char(c))
}

pub fn parse_link(input: &str) -> Result<Link, LinkError> {
    let input = input.trim();
    let (protocol, rest) = if let Some(r) = strip_scheme(input, "ssh://") {
        (Protocol::Ssh, r)
    } else if let Some(r) = strip_scheme(input, "rdp://") {
        (Protocol::Rdp, r)
    } else {
        return Err(LinkError::Scheme);
    };
    if input.chars().any(|c| c.is_control()) {
        return Err(LinkError::Chars);
    }
    // Fragment (`#...`) nie należy do adresu.
    let rest = rest.split('#').next().unwrap_or("");
    let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = authority_path.split('/').next().unwrap_or("");
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    // Hasła w linku są ignorowane celowo: bierzemy tylko nazwę użytkownika.
    let mut username = userinfo
        .map(|u| u.split(':').next().unwrap_or(""))
        .filter(|u| !u.is_empty())
        .map(percent_decode)
        .transpose()?;

    let bracketed = hostport.starts_with('[');
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or(LinkError::Ipv6)?;
        if h.is_empty()
            || !h
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(LinkError::Ipv6);
        }
        // Po nawiasie może być tylko `:port` albo nic.
        let port = match after {
            "" => None,
            a => Some(a.strip_prefix(':').ok_or(LinkError::Ipv6)?),
        };
        (h.to_owned(), port)
    } else {
        match hostport.rsplit_once(':') {
            // Drugi dwukropek oznacza adres IPv6 bez nawiasów (np. `fe80::1`), którego nie da się
            // jednoznacznie odróżnić od portu.
            Some((h, _)) if h.contains(':') => return Err(LinkError::Ipv6),
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (hostport.to_owned(), None),
        }
    };
    let host = percent_decode(&host)?;
    if host.is_empty() {
        return Err(LinkError::NoHost);
    }
    // Host zaczynający się od '-' wyglądałby jak opcja dla narzędzi wiersza poleceń.
    // Po dekodowaniu zostają zabronione też znaki struktury adresu (`%3A`, `%3F` itd.); dwukropek
    // jest dozwolony tylko w adresie IPv6 w nawiasach.
    if !valid_text(&host)
        || host.starts_with('-')
        || host.contains(['/', '\\', '@', '?', '#', '[', ']'])
        || (!bracketed && host.contains(':'))
    {
        return Err(LinkError::Chars);
    }
    let port = match port {
        None | Some("") => None,
        Some(p) => {
            // `parse` przyjmuje też wiodący '+', więc wymagamy samych cyfr ASCII.
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LinkError::Port);
            }
            let n: u16 = p.parse().map_err(|_| LinkError::Port)?;
            if n == 0 {
                return Err(LinkError::Port);
            }
            Some(n)
        }
    };

    let mut domain = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k {
            "user" | "username" if !v.is_empty() => username = Some(v),
            "domain" if !v.is_empty() => domain = Some(v),
            _ => {}
        }
    }
    // Ta sama reguła co dla hosta: wartość zaczynająca się od '-' wyglądałaby jak opcja.
    let bad = |v: &str| !valid_text(v) || v.starts_with('-');
    if username.as_deref().is_some_and(bad) || domain.as_deref().is_some_and(bad) {
        return Err(LinkError::Chars);
    }
    Ok(Link {
        protocol,
        host,
        port,
        username,
        domain,
    })
}

fn strip_scheme<'a>(s: &'a str, scheme: &str) -> Option<&'a str> {
    s.get(..scheme.len())
        .filter(|p| p.eq_ignore_ascii_case(scheme))
        .map(|_| &s[scheme.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Link {
        parse_link(s).unwrap()
    }

    #[test]
    fn parses_ssh_variants() {
        assert_eq!(
            ok("ssh://host"),
            Link {
                protocol: Protocol::Ssh,
                host: "host".into(),
                port: None,
                username: None,
                domain: None
            }
        );
        let l = ok("ssh://admin@db-01.firma.example:2222/");
        assert_eq!(
            (l.username.as_deref(), l.host.as_str(), l.port),
            (Some("admin"), "db-01.firma.example", Some(2222))
        );
        assert_eq!(ok("SSH://Host").host, "Host");
    }

    #[test]
    fn parses_rdp_with_query_and_encoding() {
        let l = ok("rdp://dc01:3390?user=jan%40firma&domain=FIRMA");
        assert_eq!(l.protocol, Protocol::Rdp);
        assert_eq!(
            (l.username.as_deref(), l.domain.as_deref(), l.port),
            (Some("jan@firma"), Some("FIRMA"), Some(3390))
        );
    }

    #[test]
    fn parses_ipv6_and_ignores_password() {
        let l = ok("ssh://root:sekret@[fe80::1]:22");
        assert_eq!(
            (l.host.as_str(), l.port, l.username.as_deref()),
            ("fe80::1", Some(22), Some("root"))
        );
        assert_eq!(ok("ssh://[::1]").host, "::1");
    }

    #[test]
    fn rejects_bad_links() {
        assert_eq!(parse_link("http://x"), Err(LinkError::Scheme));
        assert_eq!(parse_link("ssh://"), Err(LinkError::NoHost));
        assert_eq!(parse_link("ssh://host:99999"), Err(LinkError::Port));
        assert_eq!(parse_link("ssh://host:0"), Err(LinkError::Port));
        assert_eq!(parse_link("ssh://[zz]:22"), Err(LinkError::Ipv6));
        assert_eq!(parse_link("ssh://ho st"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://host%00"), Err(LinkError::Chars));
        assert_eq!(
            parse_link("ssh://host\n--oProxyCommand=x"),
            Err(LinkError::Chars)
        );
        assert_eq!(
            parse_link("ssh://-oProxyCommand=evil"),
            Err(LinkError::Chars)
        );
    }

    #[test]
    fn rejects_encoded_structure_and_format_chars() {
        assert_eq!(parse_link("ssh://a%3Ab"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://h%3Fx"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://h%23x"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://h%5Bx"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://a\u{202e}b"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://a%E2%80%AEb"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://a\u{200b}b@host"), Err(LinkError::Chars));
        assert_eq!(
            parse_link("rdp://host?domain=a%E2%80%AEb"),
            Err(LinkError::Chars)
        );
        // IPv6 w nawiasach nadal działa, podobnie jak nazwy z polskimi znakami (IDN).
        assert_eq!(ok("ssh://[fe80::1]").host, "fe80::1");
        assert_eq!(ok("ssh://zażółć.example").host, "zażółć.example");
    }

    #[test]
    fn rejects_plus_in_percent_escape_and_port() {
        assert_eq!(parse_link("ssh://host%+1"), Err(LinkError::Chars));
        assert_eq!(parse_link("rdp://host?user=a%+1"), Err(LinkError::Chars));
        assert_eq!(parse_link("ssh://host:+80"), Err(LinkError::Port));
        assert_eq!(ok("ssh://host:80").port, Some(80));
    }

    #[test]
    fn rejects_ambiguous_ipv6_garbage_and_option_like_users() {
        // IPv6 bez nawiasów dawało host "fe80:" i port 1.
        assert_eq!(parse_link("ssh://fe80::1"), Err(LinkError::Ipv6));
        assert_eq!(parse_link("ssh://::1"), Err(LinkError::Ipv6));
        assert_eq!(parse_link("ssh://[::1]smieci"), Err(LinkError::Ipv6));
        assert_eq!(parse_link("ssh://[::1]:x"), Err(LinkError::Port));
        assert_eq!(
            parse_link("ssh://-oProxyCommand=x@host"),
            Err(LinkError::Chars)
        );
        assert_eq!(parse_link("rdp://host?domain=-x"), Err(LinkError::Chars));
        // Fragment jest odcinany.
        let l = ok("ssh://host:2200#kotwica");
        assert_eq!((l.host.as_str(), l.port), ("host", Some(2200)));
        assert_eq!(ok("ssh://[::1]:2222").port, Some(2222));
    }
}
