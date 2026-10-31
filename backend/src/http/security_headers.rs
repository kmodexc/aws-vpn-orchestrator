//! Security headers on every response (SPEC §10), including errors, 404s and static files.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const HEADERS: [(&str, &str); 8] = [
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("x-frame-options", "DENY"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    ),
    ("content-security-policy", CSP),
];

/// Paths whose responses must never be cached (API data, auth redirects, secrets).
fn is_no_store_path(path: &str) -> bool {
    ["/api", "/auth", "/s", "/i"]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

pub fn apply(path: &str, headers: &mut HeaderMap) {
    for (name, value) in HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers.remove(header::SERVER);
    headers.remove("x-powered-by");
    if is_no_store_path(path) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
}

pub async fn security_headers(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    apply(&path, resp.headers_mut());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_store_paths() {
        assert!(is_no_store_path("/api/status"));
        assert!(is_no_store_path("/s/abc"));
        assert!(is_no_store_path("/auth"));
        assert!(!is_no_store_path("/assets/app.js"));
        assert!(!is_no_store_path("/sabc"));
        assert!(!is_no_store_path("/"));
    }
}
