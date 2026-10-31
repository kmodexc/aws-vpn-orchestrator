//! Sanitizer for the `return_to` login parameter (open-redirect protection).

const MAX_LEN: usize = 512;

/// Returns `input` if it is a safe same-origin relative path, else `/`.
///
/// Accepted: starts with exactly one `/`, followed by visible ASCII only, no backslash anywhere,
/// no `//` or `/\` prefix even after percent-decoding, and not pointing back into `/auth/`.
pub fn sanitize_return_to(input: Option<&str>) -> String {
    match input {
        Some(s) if is_safe(s) => s.to_string(),
        _ => "/".to_string(),
    }
}

fn is_safe(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_LEN {
        return false;
    }
    // Visible ASCII only: rules out whitespace, control characters (CR/LF/TAB, which browsers
    // strip from URLs) and non-ASCII look-alikes.
    if !s.bytes().all(|b| b.is_ascii_graphic()) || s.contains('\\') {
        return false;
    }
    if !starts_with_single_slash(s) {
        return false;
    }
    // Reject encoded variants such as /%2F%2Fevil.com or /%5Cevil.com: decode repeatedly and
    // apply the same checks. Anything that does not decode cleanly is rejected.
    let mut current = s.to_string();
    for _ in 0..3 {
        let decoded = match percent_encoding::percent_decode_str(&current).decode_utf8() {
            Ok(d) => d.into_owned(),
            Err(_) => return false,
        };
        if decoded.contains('\\')
            || decoded.chars().any(char::is_control)
            || !starts_with_single_slash(&decoded)
        {
            return false;
        }
        if decoded == current {
            break;
        }
        current = decoded;
    }
    let lower = current.to_ascii_lowercase();
    if lower == "/auth" || lower.starts_with("/auth/") || lower.starts_with("/auth?") {
        return false;
    }
    true
}

fn starts_with_single_slash(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next() == Some('/') && !matches!(chars.next(), Some('/') | Some('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_paths() {
        for ok in ["/", "/dashboard", "/a/b?c=d&e=f#frag", "/events?limit=50"] {
            assert_eq!(sanitize_return_to(Some(ok)), ok, "{ok}");
        }
        assert_eq!(sanitize_return_to(None), "/");
    }

    #[test]
    fn rejects_open_redirects() {
        for bad in [
            "",
            "//evil.com",
            "///evil.com",
            "/\\evil.com",
            "\\\\evil.com",
            "\\/evil.com",
            "https://evil.com",
            "http:/evil.com",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,x",
            "evil.com",
            "/%2F%2Fevil.com",
            "/%2fevil.com",
            "%2F%2Fevil.com",
            "/%5Cevil.com",
            "/%5cevil.com",
            "/%252F%252Fevil.com",
            "/%25252F%25252Fevil.com",
            "/foo%0d%0aSet-Cookie:x=y",
            "/foo\r\nx",
            "/ evil",
            "/\tevil",
            "/caf\u{e9}",
            "/%ff",
            "/auth/login",
            "/auth/callback?x",
            "/AUTH/logout",
        ] {
            assert_eq!(sanitize_return_to(Some(bad)), "/", "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(600));
        assert_eq!(sanitize_return_to(Some(&long)), "/");
    }
}
