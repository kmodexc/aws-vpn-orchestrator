//! Serves the built SPA from `STATIC_DIR`, with `index.html` as fallback for client-side routes.
//! `/api`, `/auth`, `/s` and `/i` never fall back to `index.html`.
//!
//! Nothing is served without a valid session: an anonymous visitor to a page is redirected to the
//! IdP login and gets a plain 404 for every file. So the app's code and texts never reach anyone
//! who is not signed in; the site looks like a bare login portal.

use std::convert::Infallible;
use std::path::Path;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::app::AppState;
use crate::auth::cookies::{SESSION_COOKIE, get_cookie};
use crate::error::{ApiError, plain_not_found};

#[derive(Debug, Clone)]
pub struct StaticFiles {
    dir: ServeDir,
    index: ServeFile,
}

impl StaticFiles {
    pub fn new(root: &Path) -> Self {
        Self {
            dir: ServeDir::new(root)
                .append_index_html_on_directories(true)
                .redirect_to_trailing_slash(false),
            index: ServeFile::new(root.join("index.html")),
        }
    }
}

/// Paths owned by the backend that must never be answered with the SPA.
pub fn is_reserved(path: &str) -> bool {
    ["/api", "/auth", "/s", "/i"]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// Client-side routes look like `/settings` or `/events/42`; anything with a file extension in
/// the last segment, or under `/assets/`, is a real file and gets a 404 when missing.
fn spa_fallback_allowed(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or_default();
    !path.starts_with("/assets/") && !last.contains('.')
}

fn finish(
    resp: Response<tower_http::services::fs::ServeFileSystemResponseBody>,
    path: &str,
) -> Response {
    let status = resp.status();
    let mut resp = resp.map(Body::new);
    let cache = if path.starts_with("/assets/")
        && (status == StatusCode::OK
            || status == StatusCode::NOT_MODIFIED
            || status == StatusCode::PARTIAL_CONTENT)
    {
        // Vite emits content-hashed file names under /assets/. `private`: only served to a
        // signed-in browser, never to be kept by a shared cache.
        "private, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

fn unreachable_infallible(never: Infallible) -> Response {
    match never {}
}

fn has_session(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    get_cookie(headers, SESSION_COOKIE).is_some_and(|c| state.sessions.get(&c).is_some())
}

fn login_error_code(query: Option<&str>) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(k, _)| k == "login_error")
        .map(|(_, v)| v.into_owned())
}

/// Minimal neutral page for a failed sign-in. Redirecting to the IdP again could loop (an SSO
/// session that keeps failing, e.g. without the required role).
fn login_error_page(code: &str) -> Response {
    let message = match code {
        "denied" => "Sign-in was cancelled.",
        "forbidden" => "This account has no access.",
        "unavailable" => "Sign-in is temporarily unavailable. Please try again later.",
        _ => "Sign-in failed.",
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex, nofollow\"><title>Console</title></head>\
         <body><main><h1>Console</h1><p>{message}</p>\
         <p><a href=\"/auth/login\">Sign in</a></p></main></body></html>"
    );
    let mut resp = (StatusCode::OK, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Anonymous request for a page: straight to the IdP login, back to the same page afterwards.
fn redirect_to_login(state: &AppState, path_and_query: &str) -> Response {
    let mut location = format!("{}/auth/login", state.config.public_base_url);
    if path_and_query != "/" {
        let encoded: String =
            url::form_urlencoded::byte_serialize(path_and_query.as_bytes()).collect();
        location.push_str("?return_to=");
        location.push_str(&encoded);
    }
    let Ok(location) = HeaderValue::from_str(&location) else {
        return plain_not_found();
    };
    let mut resp = StatusCode::FOUND.into_response();
    let h = resp.headers_mut();
    h.insert(header::LOCATION, location);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub async fn serve(State(state): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_owned();
    if is_reserved(&path) {
        return if path == "/api" || path.starts_with("/api/") {
            ApiError::NotFound.into_response()
        } else {
            plain_not_found()
        };
    }
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return plain_not_found();
    }
    let headers = req.headers().clone();
    if !has_session(&state, &headers) {
        if !spa_fallback_allowed(&path) {
            return plain_not_found();
        }
        if let Some(code) = login_error_code(req.uri().query()) {
            return login_error_page(&code);
        }
        let target = req
            .uri()
            .path_and_query()
            .map_or_else(|| path.clone(), |pq| pq.as_str().to_owned());
        return redirect_to_login(&state, &target);
    }

    let resp = match state.static_files.dir.clone().oneshot(req).await {
        Ok(r) => r,
        Err(never) => return unreachable_infallible(never),
    };
    if resp.status() != StatusCode::NOT_FOUND {
        return finish(resp, &path);
    }
    if !spa_fallback_allowed(&path) {
        return plain_not_found();
    }

    let mut index_req = Request::new(Body::empty());
    *index_req.method_mut() = method;
    *index_req.headers_mut() = headers;
    let resp = match state.static_files.index.clone().oneshot(index_req).await {
        Ok(r) => r,
        Err(never) => return unreachable_infallible(never),
    };
    if resp.status() == StatusCode::NOT_FOUND {
        return plain_not_found();
    }
    finish(resp, "/index.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_paths() {
        for p in [
            "/api",
            "/api/x",
            "/auth/login",
            "/s/tok",
            "/i/tok/config.json",
            "/s",
            "/i",
        ] {
            assert!(is_reserved(p), "{p}");
        }
        for p in [
            "/",
            "/index.html",
            "/settings",
            "/assets/app.js",
            "/static",
            "/images",
        ] {
            assert!(!is_reserved(p), "{p}");
        }
    }

    #[test]
    fn spa_fallback_rules() {
        assert!(spa_fallback_allowed("/"));
        assert!(spa_fallback_allowed("/settings/profile"));
        assert!(!spa_fallback_allowed("/favicon.ico"));
        assert!(!spa_fallback_allowed("/assets/missing"));
    }
}
