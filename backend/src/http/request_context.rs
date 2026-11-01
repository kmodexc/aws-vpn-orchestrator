//! Per-request context: request id, client IP, a tracing span with a redacted path, access
//! logging, and request timeouts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

use crate::app::AppState;
use crate::error::{ApiError, plain_status};

pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const ROTATE_TIMEOUT: Duration = Duration::from_secs(90);
pub const ROTATE_PATH: &str = "/api/ingress/rotate";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Infallible extractor: the client IP resolved by [`request_context`].
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(client_ip_of(&parts.extensions)))
    }
}

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// The client IP stored by [`request_context`] (unspecified if the middleware did not run).
pub fn client_ip_of(ext: &Extensions) -> IpAddr {
    ext.get::<ClientIp>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0)
}

/// With `trust_proxy`, the right-most `X-Forwarded-For` entry (the one appended by our own
/// reverse proxy); otherwise, or if that is unusable, the TCP peer address.
pub fn resolve_client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trust_proxy: bool) -> IpAddr {
    let fallback = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !trust_proxy {
        return fallback;
    }
    let last = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|s| !s.is_empty());
    last.and_then(|s| s.parse::<IpAddr>().ok())
        .map(|ip| match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        })
        .unwrap_or(fallback)
}

/// Path for logs: token paths are redacted and the length is bounded. Query strings are never
/// logged (they may contain OAuth codes and state).
pub fn redact_path(path: &str) -> String {
    if path == "/s" || path.starts_with("/s/") {
        return "/s/<redacted>".to_string();
    }
    if path == "/i" || path.starts_with("/i/") {
        return if path.ends_with("/config.json") {
            "/i/<redacted>/config.json".to_string()
        } else if path.ends_with("/report") {
            "/i/<redacted>/report".to_string()
        } else {
            "/i/<redacted>".to_string()
        };
    }
    crate::util::sanitize_text(path, 200)
}

pub async fn request_context(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = resolve_client_ip(req.headers(), peer, state.config.trust_proxy_headers);
    req.extensions_mut().insert(ClientIp(ip));
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %req.method(),
        path = %redact_path(req.uri().path()),
        client_ip = %ip,
    );
    let started = Instant::now();
    let mut resp = next.run(req).instrument(span.clone()).await;
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    let status = resp.status().as_u16();
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.in_scope(|| {
        if status >= 500 {
            tracing::warn!(status, latency_ms, "request completed");
        } else {
            tracing::info!(status, latency_ms, "request completed");
        }
    });
    resp
}

/// 30 s for everything, 90 s for IP rotation (SPEC §10). Ingress operations run in their own
/// task, so a timeout only ends the HTTP request, never an AWS operation half-way.
pub async fn timeout(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let limit = if path == ROTATE_PATH {
        ROTATE_TIMEOUT
    } else {
        DEFAULT_TIMEOUT
    };
    let is_api = path.starts_with("/api/");
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            tracing::warn!("request timed out");
            if is_api {
                ApiError::Unavailable.into_response()
            } else {
                plain_status(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_token_paths() {
        assert_eq!(redact_path("/s/supersecret"), "/s/<redacted>");
        assert_eq!(
            redact_path("/i/supersecret/config.json"),
            "/i/<redacted>/config.json"
        );
        assert_eq!(redact_path("/i/supersecret"), "/i/<redacted>");
        assert_eq!(redact_path("/api/status"), "/api/status");
    }

    #[test]
    fn client_ip_resolution() {
        let mut h = HeaderMap::new();
        h.append(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        h.append("x-forwarded-for", HeaderValue::from_static("3.3.3.3"));
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = Some(peer_ip);
        assert_eq!(resolve_client_ip(&h, peer, false), peer_ip);
        assert_eq!(
            resolve_client_ip(&h, peer, true),
            "3.3.3.3".parse::<IpAddr>().unwrap()
        );
        let mut bad = HeaderMap::new();
        bad.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, garbage"),
        );
        assert_eq!(resolve_client_ip(&bad, peer, true), peer_ip);
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), None, true),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        let mut mapped = HeaderMap::new();
        mapped.insert(
            "x-forwarded-for",
            HeaderValue::from_static("::ffff:5.5.5.5"),
        );
        assert_eq!(
            resolve_client_ip(&mapped, None, true),
            "5.5.5.5".parse::<IpAddr>().unwrap()
        );
    }
}
