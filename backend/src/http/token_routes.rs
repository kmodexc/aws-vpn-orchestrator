//! Token-in-path endpoints (SPEC §4.5): `/s/{token}`, `/i/{token}/config.json` and
//! `/i/{token}/report`. Wrong tokens get the generic 404 and count as failures for the per-IP
//! failure limiter.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::error::{plain_not_found, plain_status};
use crate::http::request_context::ClientIp;
use crate::singbox;
use crate::telemetry::{IngressReport, ReportReply};
use crate::util::ct_eq_str;

pub async fn subscription(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    token: Result<Path<String>, PathRejection>,
) -> Response {
    let cfg = &state.config;
    let Ok(Path(token)) = token else {
        state.limiter.record_failure(ip);
        return plain_not_found();
    };
    if !ct_eq_str(&token, cfg.sub_token.expose()) {
        state.limiter.record_failure(ip);
        tracing::info!("subscription request with wrong token");
        return plain_not_found();
    }
    let status = match state.orchestrator.status().await {
        Ok(s) => s,
        Err(_) => return plain_status(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"),
    };
    let Some(public_ip) = status.public_ip else {
        return plain_status(StatusCode::SERVICE_UNAVAILABLE, "Ingress has no public IP");
    };
    let settings = state.protocol_settings().await;
    let body = singbox::subscription_body(cfg, &settings, public_ip);
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "profile-update-interval",
        HeaderValue::from(cfg.sub_update_hours),
    );
    if let Ok(v) = HeaderValue::from_str(&singbox::profile_title(cfg)) {
        h.insert("profile-title", v);
    }
    resp
}

pub async fn ingress_config(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    token: Result<Path<String>, PathRejection>,
) -> Response {
    let cfg = &state.config;
    let Ok(Path(token)) = token else {
        state.limiter.record_failure(ip);
        return plain_not_found();
    };
    if !ct_eq_str(&token, cfg.ingress_token.expose()) {
        state.limiter.record_failure(ip);
        tracing::info!("ingress config request with wrong token");
        return plain_not_found();
    }
    let (bytes, _) = state.served_config().await;
    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

/// The ingress reports counters and new log lines (SPEC §5). Plain-text errors like the other
/// token routes; the reply tells the ingress whether its config is stale.
pub async fn report(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    token: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let cfg = &state.config;
    let Ok(Path(token)) = token else {
        state.limiter.record_failure(ip);
        return plain_not_found();
    };
    if !ct_eq_str(&token, cfg.ingress_token.expose()) {
        state.limiter.record_failure(ip);
        tracing::info!("ingress report with wrong token");
        return plain_not_found();
    }
    let body = match body {
        Ok(b) => b,
        Err(r) if r.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return plain_status(StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large");
        }
        Err(_) => return plain_status(StatusCode::BAD_REQUEST, "Bad Request"),
    };
    if !is_json(&headers) {
        return plain_status(StatusCode::BAD_REQUEST, "Bad Request");
    }
    let Ok(report) = serde_json::from_slice::<IngressReport>(&body) else {
        tracing::info!("ingress report rejected: invalid body");
        return plain_status(StatusCode::BAD_REQUEST, "Bad Request");
    };
    if report.config_sha256.len() != 64
        || !report.config_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return plain_status(StatusCode::BAD_REQUEST, "Bad Request");
    }
    let reported = report.config_sha256.to_ascii_lowercase();
    state.telemetry.record(report);
    let (_, current) = state.served_config().await;
    let mut resp = Json(ReportReply {
        config_stale: reported != current,
        config_sha256: current,
    })
    .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub async fn not_found() -> Response {
    plain_not_found()
}
