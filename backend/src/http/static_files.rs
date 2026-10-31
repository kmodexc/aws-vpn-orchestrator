//! Serves the built SPA from `STATIC_DIR`, with `index.html` as fallback for client-side routes.
//! `/api`, `/auth`, `/s` and `/i` never fall back to `index.html`.

use std::convert::Infallible;
use std::path::Path;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::app::AppState;
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
        // Vite emits content-hashed file names under /assets/.
        "public, max-age=31536000, immutable"
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
