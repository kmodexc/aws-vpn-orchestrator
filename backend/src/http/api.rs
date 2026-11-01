//! `/api/*` handlers (SPEC §5). Every handler takes a [`Principal`] (any role) or an [`Admin`],
//! which enforce authentication, the role check and CSRF. A user-role caller may only read
//! `/api/me` and `/api/subscription`.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app::AppState;
use crate::auth::{self, Admin, Principal};
use crate::error::ApiError;
use crate::settings::{ProtocolSettings, SettingsUpdate};
use crate::singbox;
use crate::state::{Event, EventAction};
use crate::util::{sanitize_text, unix_now};

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
    /// Full access (start/stop/rotate, events, settings). `false`: subscription only.
    pub is_admin: bool,
}

pub async fn me(principal: Principal) -> Json<MeResponse> {
    Json(MeResponse {
        csrf_token: principal.csrf_token().map(str::to_string),
        is_admin: principal.is_admin,
        sub: principal.sub,
        username: principal.username,
        email: principal.email,
        roles: principal.roles,
    })
}

pub async fn status(State(state): State<AppState>, _p: Admin) -> Result<Response, ApiError> {
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
    parse_json_body(headers, &body)
}

/// Parse a required JSON object body that must match the schema exactly.
fn parse_json_body<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<T, ApiError> {
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
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("invalid JSON body"))
}

// The `Principal` extractor runs first, so authentication, the role check and CSRF are
// enforced before the body is looked at.
pub async fn start(
    State(state): State<AppState>,
    Admin(p): Admin,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let EmptyRequest {} = parse_optional_json(&headers, body)?;
    state.orchestrator.start(p.actor()).await?;
    Ok(accepted())
}

pub async fn stop(
    State(state): State<AppState>,
    Admin(p): Admin,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let EmptyRequest {} = parse_optional_json(&headers, body)?;
    state.orchestrator.stop(p.actor()).await?;
    Ok(accepted())
}

pub async fn rotate(
    State(state): State<AppState>,
    Admin(p): Admin,
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
    _p: Admin,
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
    let settings = state.protocol_settings().await;
    Ok(Json(SubscriptionResponse {
        url: format!("{}/s/{}", cfg.public_base_url, cfg.sub_token.expose()),
        links: status
            .public_ip
            .map(|ip| singbox::share_links(cfg, &settings, ip)),
    }))
}

#[derive(Debug, Serialize)]
pub struct WireGuardResponse {
    pub enabled: bool,
    pub ingress_public_key: Option<String>,
    pub ingress_address: String,
    pub vps_peer_snippet: Option<String>,
}

pub async fn wireguard(State(state): State<AppState>, _p: Admin) -> Json<WireGuardResponse> {
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

#[derive(Debug, Serialize)]
pub struct Ports {
    pub vless_tcp: u16,
    pub hy2_udp: u16,
    pub ss: u16,
}

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    /// In effect now.
    pub settings: ProtocolSettings,
    /// From `.env`.
    pub defaults: ProtocolSettings,
    /// `true` when `settings` come from `/api/settings`, not `.env`.
    pub overridden: bool,
    /// Read-only: ports are changed in `.env` together with the firewalls.
    pub ports: Ports,
}

fn settings_response(
    cfg: &crate::config::Config,
    stored: Option<ProtocolSettings>,
) -> SettingsResponse {
    let defaults = ProtocolSettings::defaults(cfg);
    SettingsResponse {
        settings: ProtocolSettings::effective(cfg, stored.as_ref()),
        overridden: stored.is_some(),
        defaults,
        ports: Ports {
            vless_tcp: cfg.proxy.vless_port,
            hy2_udp: cfg.proxy.hy2_port,
            ss: cfg.proxy.ss_port,
        },
    }
}

pub async fn get_settings(State(state): State<AppState>, _p: Admin) -> Json<SettingsResponse> {
    let stored = state.orchestrator.store().snapshot().await.protocol;
    Json(settings_response(&state.config, stored))
}

/// Human-readable list of what changed, for the event log.
fn describe_change(old: &ProtocolSettings, new: &ProtocolSettings) -> String {
    let on_off = |b: bool| if b { "on" } else { "off" };
    let mut parts = Vec::new();
    if old.reality_sni != new.reality_sni {
        parts.push(format!("reality_sni={}", new.reality_sni));
    }
    if old.hy2_sni != new.hy2_sni {
        parts.push(format!("hy2_sni={}", new.hy2_sni));
    }
    if old.hysteria2 != new.hysteria2 {
        parts.push(format!("hysteria2={}", on_off(new.hysteria2)));
    }
    if old.hy2_obfs != new.hy2_obfs {
        parts.push(format!("hy2_obfs={}", on_off(new.hy2_obfs)));
    }
    if old.shadowsocks != new.shadowsocks {
        parts.push(format!("shadowsocks={}", on_off(new.shadowsocks)));
    }
    parts.join(", ")
}

/// Store `new` (`None` = back to `.env`) and log the change in the same atomic write. When the
/// stored override would not change, nothing is written or logged. Returns the stored override
/// as it is after this call.
async fn store_settings(
    state: &AppState,
    actor: String,
    new: Option<ProtocolSettings>,
) -> Result<Option<ProtocolSettings>, ApiError> {
    let cfg = &state.config;
    state
        .orchestrator
        .store()
        .update_if(|s| {
            if s.protocol == new {
                return (false, s.protocol.clone());
            }
            let old = ProtocolSettings::effective(cfg, s.protocol.as_ref());
            let next = ProtocolSettings::effective(cfg, new.as_ref());
            let mut detail = describe_change(&old, &next);
            if detail.is_empty() {
                detail = "no effective change".into();
            }
            if new.is_none() {
                detail = format!("reset to .env defaults: {detail}");
            }
            s.protocol = new;
            s.push_event(Event {
                at: unix_now(),
                action: EventAction::Settings,
                ip: None,
                detail: sanitize_text(&detail, 300),
                actor,
            });
            (true, s.protocol.clone())
        })
        .await
        .map_err(ApiError::internal)
}

pub async fn put_settings(
    State(state): State<AppState>,
    Admin(p): Admin,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<SettingsResponse>, ApiError> {
    let body = body.map_err(|r| {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::BadRequest("cannot read request body")
        }
    })?;
    let update: SettingsUpdate = parse_json_body(&headers, &body)?;
    let new = update.validate().map_err(ApiError::BadRequest)?;
    let stored = store_settings(&state, p.actor(), Some(new)).await?;
    Ok(Json(settings_response(&state.config, stored)))
}

pub async fn reset_settings(
    State(state): State<AppState>,
    Admin(p): Admin,
) -> Result<Json<SettingsResponse>, ApiError> {
    let stored = store_settings(&state, p.actor(), None).await?;
    Ok(Json(settings_response(&state.config, stored)))
}

/// Without valid credentials every `/api` path answers 401 — known or not, any method — so
/// the API's routes cannot be enumerated anonymously.
async fn require_caller(
    state: &AppState,
    parts: &axum::http::request::Parts,
) -> Result<(), ApiError> {
    let ip = crate::http::request_context::client_ip_of(&parts.extensions);
    // Probing for existence is not a state change: skip the CSRF check here.
    auth::authenticate(state, &axum::http::Method::GET, &parts.headers, ip)
        .await
        .map(|_| ())
}

pub async fn not_found(State(state): State<AppState>, req: axum::extract::Request) -> ApiError {
    let (parts, _) = req.into_parts();
    match require_caller(&state, &parts).await {
        Ok(()) => ApiError::NotFound,
        Err(e) => e,
    }
}

pub async fn method_not_allowed(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> ApiError {
    let (parts, _) = req.into_parts();
    match require_caller(&state, &parts).await {
        Ok(()) => ApiError::MethodNotAllowed,
        Err(e) => e,
    }
}
