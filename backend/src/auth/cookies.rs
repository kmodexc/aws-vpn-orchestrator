//! Cookie helpers. Both cookies use the `__Host-` prefix: Secure, Path=/, no Domain.

use axum::http::{HeaderMap, HeaderValue, header};

pub const SESSION_COOKIE: &str = "__Host-vpncp_session";
pub const LOGIN_COOKIE: &str = "__Host-vpncp_login";

const MAX_VALUE_LEN: usize = 128;

/// Read a cookie value. Only base64url values of bounded length are accepted.
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim().trim_matches('"'))
        .filter(|v| {
            !v.is_empty()
                && v.len() <= MAX_VALUE_LEN
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_string)
}

/// `Set-Cookie` value for a `__Host-` cookie. `value` must be base64url (callers only pass
/// values produced by [`crate::util::random_token`]).
pub fn set_cookie(name: &str, value: &str, max_age_s: u64) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age_s}"
    ))
    .ok()
}

/// `Set-Cookie` value that deletes the cookie.
pub fn clear_cookie(name: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookie_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=b; __Host-vpncp_session=abc_DEF-123; c=d"),
        );
        assert_eq!(
            get_cookie(&h, SESSION_COOKIE).as_deref(),
            Some("abc_DEF-123")
        );
        assert_eq!(get_cookie(&h, LOGIN_COOKIE), None);
    }

    #[test]
    fn rejects_weird_values() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-vpncp_session=a b<script>"),
        );
        assert_eq!(get_cookie(&h, SESSION_COOKIE), None);
    }

    #[test]
    fn cookie_attributes() {
        let v = set_cookie(SESSION_COOKIE, "xyz", 600).unwrap();
        let s = v.to_str().unwrap();
        assert!(s.starts_with("__Host-vpncp_session=xyz;"));
        for attr in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=600",
        ] {
            assert!(s.contains(attr), "{attr}");
        }
        assert!(!s.contains("Domain"));
        assert!(
            clear_cookie(LOGIN_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }
}
