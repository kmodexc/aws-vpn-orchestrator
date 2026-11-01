//! Browser login (BFF): `/auth/login`, `/auth/callback`, `/auth/logout` (SPEC §4.1).

use std::time::Instant;

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::app::AppState;
use crate::auth::cookies::{LOGIN_COOKIE, SESSION_COOKIE, clear_cookie, get_cookie, set_cookie};
use crate::auth::csrf;
use crate::auth::oidc::OidcError;
use crate::auth::return_to::sanitize_return_to;
use crate::auth::session::{PENDING_LOGIN_TTL, PendingLogin, SessionData};
use crate::error::ApiError;
use crate::http::request_context::ClientIp;
use crate::secret::Secret;
use crate::util::{b64url, random_token, sha256};

const MAX_PARAM_LEN: usize = 4096;

/// 302 with optional `Set-Cookie` headers.
fn redirect(location: &str, cookies: &[Option<HeaderValue>]) -> Response {
    let Ok(location) = HeaderValue::from_str(location) else {
        return ApiError::internal("redirect location is not a valid header value").into_response();
    };
    let mut resp = StatusCode::FOUND.into_response();
    resp.headers_mut().insert(header::LOCATION, location);
    for c in cookies.iter().flatten() {
        resp.headers_mut().append(header::SET_COOKIE, c.clone());
    }
    resp
}

/// Redirect to the SPA with `?login_error=<code>`; code ∈ denied|invalid|forbidden|unavailable.
fn login_error(state: &AppState, code: &'static str) -> Response {
    redirect(
        &format!("{}/?login_error={code}", state.config.public_base_url),
        &[clear_cookie(LOGIN_COOKIE)],
    )
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub return_to: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    query: Result<Query<LoginQuery>, QueryRejection>,
) -> Response {
    let return_to = sanitize_return_to(query.ok().and_then(|Query(q)| q.return_to).as_deref());
    let (Ok(oauth_state), Ok(nonce), Ok(verifier)) =
        (random_token(), random_token(), random_token())
    else {
        tracing::error!("CSPRNG failure during login");
        return login_error(&state, "unavailable");
    };
    let challenge = b64url(&sha256(verifier.as_bytes()));

    let auth_url = match state
        .oidc
        .authorization_url(&oauth_state, &nonce, &challenge)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "cannot start login");
            return login_error(&state, "unavailable");
        }
    };
    let cookie = match state.sessions.create_pending(PendingLogin {
        state: Secret::new(oauth_state),
        nonce: Secret::new(nonce),
        pkce_verifier: Secret::new(verifier),
        return_to,
        created_at: Instant::now(),
    }) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "cannot create pending login");
            return login_error(&state, "unavailable");
        }
    };
    redirect(
        &auth_url,
        &[set_cookie(
            LOGIN_COOKIE,
            &cookie,
            PENDING_LOGIN_TTL.as_secs(),
        )],
    )
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    // The pending login is consumed no matter what happens next (single use).
    let pending = get_cookie(&headers, LOGIN_COOKIE).and_then(|c| state.sessions.take_pending(&c));
    let fail = |code: &'static str, count_failure: bool| {
        if count_failure {
            state.limiter.record_failure(ip);
        }
        login_error(&state, code)
    };

    let Ok(Query(q)) = query else {
        return fail("invalid", true);
    };
    let Some(pending) = pending else {
        tracing::info!("login callback without a valid pending login");
        return fail("invalid", false);
    };
    if let Some(err) = q.error.as_deref() {
        tracing::info!(error = %crate::util::sanitize_text(err, 64), "IdP returned an error");
        return fail(
            if err == "access_denied" {
                "denied"
            } else {
                "invalid"
            },
            false,
        );
    }
    let (Some(code), Some(returned_state)) = (q.code, q.state) else {
        return fail("invalid", true);
    };
    if code.len() > MAX_PARAM_LEN || returned_state.len() > MAX_PARAM_LEN {
        return fail("invalid", true);
    }
    if !pending.state_matches(&returned_state) {
        tracing::warn!("login callback state mismatch");
        return fail("invalid", true);
    }
    // RFC 9207 mix-up protection when the IdP sends `iss`.
    if q.iss
        .as_deref()
        .is_some_and(|iss| iss != state.oidc.issuer())
    {
        tracing::warn!("login callback iss mismatch");
        return fail("invalid", true);
    }

    let tokens = match state
        .oidc
        .exchange_code(&code, pending.pkce_verifier.expose())
        .await
    {
        Ok(t) => t,
        Err(OidcError::Unavailable(e)) => {
            tracing::error!(error = %e, "code exchange failed");
            return fail("unavailable", false);
        }
        Err(OidcError::Rejected(e)) => {
            tracing::warn!(error = %e, "code exchange rejected");
            return fail("invalid", true);
        }
    };
    let (id, access) = match state
        .oidc
        .validate_login_tokens(&tokens, pending.nonce.expose())
        .await
    {
        Ok(v) => v,
        Err(OidcError::Unavailable(e)) => {
            tracing::error!(error = %e, "token validation unavailable");
            return fail("unavailable", false);
        }
        Err(OidcError::Rejected(e)) => {
            tracing::warn!(error = %e, "login tokens rejected");
            return fail("invalid", true);
        }
    };

    let cfg = &state.config;
    if crate::auth::access_of_claims(cfg, &access).is_none() {
        tracing::info!(sub = %id.sub, "login denied: missing required role");
        return fail("forbidden", false);
    }

    let username = id
        .preferred_username
        .clone()
        .or_else(|| access.preferred_username.clone())
        .unwrap_or_else(|| id.sub.clone());
    let data = SessionData {
        roles: access.roles(&cfg.oidc.client_id),
        email: id.email.clone().or_else(|| access.email.clone()),
        username: crate::util::sanitize_text(&username, 128),
        sub: id.sub,
        id_token: Some(tokens.id_token),
    };
    // Never reuse a session id that existed before authentication.
    if let Some(old) = get_cookie(&headers, SESSION_COOKIE) {
        state.sessions.remove(&old);
    }
    let session_cookie = match state.sessions.create(data) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "cannot create session");
            return fail("unavailable", false);
        }
    };
    tracing::info!("login succeeded");
    redirect(
        &format!("{}{}", cfg.public_base_url, pending.return_to),
        &[
            set_cookie(
                SESSION_COOKIE,
                &session_cookie,
                state.sessions.absolute_timeout().as_secs(),
            ),
            clear_cookie(LOGIN_COOKIE),
        ],
    )
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cfg = &state.config;
    let Some(cookie) = get_cookie(&headers, SESSION_COOKIE) else {
        return ApiError::Unauthorized.into_response();
    };
    let Some(session) = state.sessions.get(&cookie) else {
        let mut resp = ApiError::Unauthorized.into_response();
        if let Some(c) = clear_cookie(SESSION_COOKIE) {
            resp.headers_mut().append(header::SET_COOKIE, c);
        }
        return resp;
    };
    if let Err(e) = csrf::verify(&headers, session.csrf_token.expose(), &cfg.public_base_url) {
        return e.into_response();
    }
    state.sessions.remove(&cookie);

    let home = format!("{}/", cfg.public_base_url);
    let id_token_hint = session.data.id_token.as_ref().map(|t| t.expose().as_str());
    let logout_url = state
        .oidc
        .logout_url(id_token_hint, &home)
        .await
        .unwrap_or(home);
    let mut resp = Json(json!({ "logout_url": logout_url })).into_response();
    if let Some(c) = clear_cookie(SESSION_COOKIE) {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
    resp
}
