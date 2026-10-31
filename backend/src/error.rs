//! API error type. Every error maps to `{"error": "<code>", "message": "<text>"}` and never
//! carries internal details; those are logged server-side inside the request span (which
//! carries the request id that is also returned in `X-Request-Id`).

use std::fmt::Display;

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Unauthorized,
    Forbidden,
    Csrf,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    BadRequest(&'static str),
    Cooldown { retry_after_s: u64 },
    RateLimited { retry_after_s: u64 },
    Conflict,
    Unavailable,
    Internal,
}

impl ApiError {
    /// Log an internal error with full detail and return the opaque client error.
    pub fn internal(err: impl Display) -> Self {
        tracing::error!(error = %err, "internal error");
        Self::Internal
    }

    /// Log an upstream (AWS / IdP) failure with full detail and return `unavailable`.
    pub fn unavailable(err: impl Display) -> Self {
        tracing::error!(error = %err, "upstream unavailable");
        Self::Unavailable
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Csrf => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Cooldown { .. } | Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Csrf => "csrf",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed | Self::PayloadTooLarge | Self::BadRequest(_) => "bad_request",
            Self::Cooldown { .. } => "cooldown",
            Self::RateLimited { .. } => "rate_limited",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Unauthorized => "authentication required",
            Self::Forbidden => "your account lacks the required role",
            Self::Csrf => "missing or invalid CSRF token or origin",
            Self::NotFound => "not found",
            Self::MethodNotAllowed => "method not allowed",
            Self::PayloadTooLarge => "request body too large",
            Self::BadRequest(msg) => msg,
            Self::Cooldown { .. } => "IP rotation is cooling down",
            Self::RateLimited { .. } => "too many requests",
            Self::Conflict => "another operation is in progress",
            Self::Unavailable => "upstream service unavailable",
            Self::Internal => "internal error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut body = json!({ "error": self.code(), "message": self.message() });
        let retry_after = match &self {
            Self::Cooldown { retry_after_s } => {
                body["retry_after_s"] = json!(retry_after_s);
                Some(*retry_after_s)
            }
            Self::RateLimited { retry_after_s } => Some(*retry_after_s),
            _ => None,
        };
        let mut resp = (status, Json(body)).into_response();
        if let Some(secs) = retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// Generic plain-text 404, identical for every non-API unknown path and for wrong path tokens.
pub fn plain_not_found() -> Response {
    plain_status(StatusCode::NOT_FOUND, "Not Found")
}

pub fn plain_status(status: StatusCode, text: &'static str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        text,
    )
        .into_response()
}
