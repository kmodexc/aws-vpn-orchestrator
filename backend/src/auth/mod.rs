//! Authentication and authorization (SPEC §4).

pub mod cookies;
pub mod csrf;
pub mod jwt;
pub mod oidc;
pub mod return_to;
pub mod session;

use std::net::IpAddr;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, header};

use crate::app::AppState;
use crate::error::ApiError;
use crate::http::request_context::client_ip_of;

#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Browser session cookie. Carries the session's CSRF token.
    Session { csrf_token: String },
    /// `Authorization: Bearer <jwt>` (e.g. the Android app).
    Bearer,
}

/// An authenticated and authorized caller (has `OIDC_REQUIRED_ROLE`). Using this extractor in
/// a handler enforces authentication, the role check and, for cookie sessions on state-changing
/// methods, CSRF protection.
#[derive(Debug, Clone)]
pub struct Principal {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub method: AuthMethod,
}

impl Principal {
    /// Name recorded in the event log.
    pub fn actor(&self) -> String {
        crate::util::sanitize_text(&self.username, 64)
    }

    pub fn csrf_token(&self) -> Option<&str> {
        match &self.method {
            AuthMethod::Session { csrf_token } => Some(csrf_token),
            AuthMethod::Bearer => None,
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<Result<String, ()>> {
    let value = headers.get(header::AUTHORIZATION)?;
    let Ok(text) = value.to_str() else {
        return Some(Err(()));
    };
    let mut parts = text.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default().trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Some(Err(()));
    }
    Some(Ok(token.to_string()))
}

/// Authenticate a request. Bearer tokens take precedence and ignore cookies entirely.
pub async fn authenticate(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    client_ip: IpAddr,
) -> Result<Principal, ApiError> {
    let cfg = &state.config;
    if let Some(bearer) = bearer_token(headers) {
        let Ok(token) = bearer else {
            state.limiter.record_failure(client_ip);
            return Err(ApiError::Unauthorized);
        };
        let claims = match state.oidc.validate_bearer(&token).await {
            Ok(c) => c,
            Err(oidc::OidcError::Unavailable(e)) => return Err(ApiError::unavailable(e)),
            Err(oidc::OidcError::Rejected(e)) => {
                tracing::info!(reason = %e, "bearer token rejected");
                state.limiter.record_failure(client_ip);
                return Err(ApiError::Unauthorized);
            }
        };
        let Some(sub) = claims.sub.clone().filter(|s| !s.is_empty()) else {
            state.limiter.record_failure(client_ip);
            return Err(ApiError::Unauthorized);
        };
        if !claims.has_role(&cfg.oidc.required_role, &cfg.oidc.client_id) {
            return Err(ApiError::Forbidden);
        }
        return Ok(Principal {
            username: claims
                .preferred_username
                .clone()
                .unwrap_or_else(|| sub.clone()),
            email: claims.email.clone(),
            roles: claims.roles(&cfg.oidc.client_id),
            sub,
            method: AuthMethod::Bearer,
        });
    }

    let cookie =
        cookies::get_cookie(headers, cookies::SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    let session = state.sessions.get(&cookie).ok_or(ApiError::Unauthorized)?;
    if !session
        .data
        .roles
        .iter()
        .any(|r| *r == cfg.oidc.required_role)
    {
        return Err(ApiError::Forbidden);
    }
    if !csrf::is_safe_method(method) {
        csrf::verify(headers, session.csrf_token.expose(), &cfg.public_base_url)?;
    }
    Ok(Principal {
        sub: session.data.sub,
        username: session.data.username,
        email: session.data.email,
        roles: session.data.roles,
        method: AuthMethod::Session {
            csrf_token: session.csrf_token.expose().clone(),
        },
    })
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ip = client_ip_of(&parts.extensions);
        authenticate(state, &parts.method, &parts.headers, ip).await
    }
}
