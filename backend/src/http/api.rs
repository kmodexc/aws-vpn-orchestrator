//! `/api/*` handlers (SPEC §5). Every handler takes a [`Principal`], which enforces
//! authentication, the role check and CSRF.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppState;
use crate::auth::Principal;
use crate::error::ApiError;
use crate::singbox;
use crate::state::Event;

pub const MAX_EVENTS_LIMIT: usize = 200;
pub const DEFAULT_EVENTS_LIMIT: usize = 50;
pub const MAX_REASON_CHARS: usize = 200;

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub csrf_token: Option<String>,
}

pub async fn me(principal: Principal) -> Json<MeResponse> {
    Json(MeResponse {
        csrf_token: principal.csrf_token().map(str::to_string),
        sub: principal.sub,
        username: principal.username,
        email: principal.email,
        roles: principal.roles,
    })
}

pub async fn status(State(state): State<AppState>, _p: Principal) -> Result<Response, ApiError> {
    Ok(Json(state.orchestrator.status_view().await?).into_response())
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({"ok": true}))).into_response()
}

/// Body of `start`/`stop`: empty, or exactly `{}`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyRequest {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

/// Parse an optional JSON body: empty is allowed, otherwise it must be `application/json`
/// and match the schema exactly (`deny_unknown_fields`).
///
/// The body is taken as `Result<Bytes, BytesRejection>` so that an oversized body maps to
/// `413 bad_request` and any other read error to `400 bad_request`, both as JSON.
fn parse_optional_json<T: Default + serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let body = body.map_err(|r| {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::BadRequest("cannot read request body")
        }
    })?;
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    if !is_json(headers) {
        return Err(ApiError::BadRequest(
            "Content-Type must be application/json",
        ));
    }
    // serde would also accept the sequence form of a struct (`[]`, `["reason"]`); only a JSON
    // object is a valid body.
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(ApiError::BadRequest("request body must be a JSON object"));
    }
    serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("invalid JSON body"))
}

// The `Principal` extractor runs first, so authentication, the role check and CSRF are
// enforced before the body is looked at.
pub async fn start(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let EmptyRequest {} = parse_optional_json(&headers, body)?;
    state.orchestrator.start(p.actor()).await?;
    Ok(accepted())
}

pub async fn stop(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let EmptyRequest {} = parse_optional_json(&headers, body)?;
    state.orchestrator.stop(p.actor()).await?;
    Ok(accepted())
}

pub async fn rotate(
    State(state): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let req: RotateRequest = parse_optional_json(&headers, body)?;
    let reason = match req.reason {
        Some(r) if r.chars().count() > MAX_REASON_CHARS => {
            return Err(ApiError::BadRequest(
                "reason must be at most 200 characters",
            ));
        }
        Some(r) => Some(crate::util::sanitize_text(r.trim(), MAX_REASON_CHARS)),
        None => None,
    };
    let ip = state.orchestrator.rotate(p.actor(), reason).await?;
    Ok(Json(json!({"public_ip": ip.to_string()})).into_response())
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
}

pub async fn events(
    State(state): State<AppState>,
    _p: Principal,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Json<Vec<Event>>, ApiError> {
    let Query(q) =
        query.map_err(|_| ApiError::BadRequest("limit must be a non-negative integer"))?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_EVENTS_LIMIT)
        .min(MAX_EVENTS_LIMIT);
    let snap = state.orchestrator.store().snapshot().await;
    Ok(Json(snap.events.into_iter().rev().take(limit).collect()))
}

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub url: String,
    pub links: Option<Vec<String>>,
}

pub async fn subscription(
    State(state): State<AppState>,
    _p: Principal,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let cfg = &state.config;
    let status = state.orchestrator.status().await?;
    Ok(Json(SubscriptionResponse {
        url: format!("{}/s/{}", cfg.public_base_url, cfg.sub_token.expose()),
        links: status.public_ip.map(|ip| singbox::share_links(cfg, ip)),
    }))
}

#[derive(Debug, Serialize)]
pub struct WireGuardResponse {
    pub enabled: bool,
    pub ingress_public_key: Option<String>,
    pub ingress_address: String,
    pub vps_peer_snippet: Option<String>,
}

pub async fn wireguard(State(state): State<AppState>, _p: Principal) -> Json<WireGuardResponse> {
    let wg = &state.config.wireguard;
    let peer = wg.peer.as_ref().filter(|_| wg.enabled);
    Json(WireGuardResponse {
        enabled: wg.enabled,
        ingress_public_key: peer.map(|p| p.ingress_public_key.clone()),
        ingress_address: wg.ingress_address.clone(),
        vps_peer_snippet: peer.map(|p| {
            format!(
                "[Peer]\n# vpn-orchestrator ingress\nPublicKey = {}\nAllowedIPs = {}\n",
                p.ingress_public_key, wg.ingress_address
            )
        }),
    })
}

pub async fn not_found() -> ApiError {
    ApiError::NotFound
}

pub async fn method_not_allowed() -> ApiError {
    ApiError::MethodNotAllowed
}
