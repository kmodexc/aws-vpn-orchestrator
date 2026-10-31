//! Token-in-path endpoints (SPEC §4.5): `/s/{token}` and `/i/{token}/config.json`.
//! Wrong tokens get the generic 404 and count as failures for the per-IP failure limiter.

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::error::{plain_not_found, plain_status};
use crate::http::request_context::ClientIp;
use crate::singbox;
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
    let body = singbox::subscription_body(cfg, public_ip);
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
    let mut resp = Json(singbox::server_config(cfg)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub async fn not_found() -> Response {
    plain_not_found()
}
