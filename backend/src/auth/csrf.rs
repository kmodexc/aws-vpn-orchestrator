//! CSRF protection for cookie-authenticated, state-changing requests (SPEC §4.4):
//! `X-CSRF-Token` must equal the session token (constant time) AND the request must come from
//! our own origin (`Origin`, or `Referer` when `Origin` is absent).

use axum::http::{HeaderMap, Method, header};

use crate::error::ApiError;
use crate::util::ct_eq_str;

pub const CSRF_HEADER: &str = "x-csrf-token";

/// Methods that never change state and are therefore exempt.
pub fn is_safe_method(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

pub fn verify(
    headers: &HeaderMap,
    expected_token: &str,
    public_base_url: &str,
) -> Result<(), ApiError> {
    let token_ok = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| !t.is_empty() && ct_eq_str(t, expected_token));
    if !token_ok {
        return Err(ApiError::Csrf);
    }
    if !origin_ok(headers, public_base_url) {
        return Err(ApiError::Csrf);
    }
    Ok(())
}

fn origin_ok(headers: &HeaderMap, public_base_url: &str) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin.to_str().is_ok_and(|o| o == public_base_url);
    }
    headers
        .get(header::REFERER)
        .and_then(|r| r.to_str().ok())
        .is_some_and(|r| {
            r.strip_prefix(public_base_url)
                .is_some_and(|rest| rest.starts_with('/'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const BASE: &str = "https://vpn.example.com";
    const TOKEN: &str = "csrf-token-value";

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn accepts_token_and_origin() {
        let h = headers(&[("x-csrf-token", TOKEN), ("origin", BASE)]);
        assert_eq!(verify(&h, TOKEN, BASE), Ok(()));
    }

    #[test]
    fn accepts_token_and_referer_without_origin() {
        let h = headers(&[
            ("x-csrf-token", TOKEN),
            ("referer", "https://vpn.example.com/dash"),
        ]);
        assert_eq!(verify(&h, TOKEN, BASE), Ok(()));
    }

    #[test]
    fn rejects_missing_or_wrong_token() {
        let h = headers(&[("origin", BASE)]);
        assert_eq!(verify(&h, TOKEN, BASE), Err(ApiError::Csrf));
        let h = headers(&[("x-csrf-token", "wrong"), ("origin", BASE)]);
        assert_eq!(verify(&h, TOKEN, BASE), Err(ApiError::Csrf));
        let h = headers(&[("x-csrf-token", ""), ("origin", BASE)]);
        assert_eq!(verify(&h, TOKEN, BASE), Err(ApiError::Csrf));
    }

    #[test]
    fn rejects_foreign_or_missing_origin() {
        for h in [
            headers(&[("x-csrf-token", TOKEN)]),
            headers(&[("x-csrf-token", TOKEN), ("origin", "https://evil.com")]),
            headers(&[("x-csrf-token", TOKEN), ("origin", "null")]),
            headers(&[
                ("x-csrf-token", TOKEN),
                ("origin", "https://vpn.example.com.evil.com"),
            ]),
            headers(&[
                ("x-csrf-token", TOKEN),
                ("origin", "http://vpn.example.com"),
            ]),
            headers(&[
                ("x-csrf-token", TOKEN),
                ("referer", "https://vpn.example.com.evil.com/"),
            ]),
            headers(&[
                ("x-csrf-token", TOKEN),
                ("referer", "https://vpn.example.com"),
            ]),
            // a present but foreign Origin is not rescued by a good Referer
            headers(&[
                ("x-csrf-token", TOKEN),
                ("origin", "https://evil.com"),
                ("referer", "https://vpn.example.com/"),
            ]),
        ] {
            assert_eq!(verify(&h, TOKEN, BASE), Err(ApiError::Csrf), "{h:?}");
        }
    }

    #[test]
    fn safe_methods() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        assert!(!is_safe_method(&Method::POST));
        assert!(!is_safe_method(&Method::OPTIONS));
    }
}
