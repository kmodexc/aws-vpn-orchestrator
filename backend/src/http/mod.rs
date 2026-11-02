//! HTTP layer: router and middleware stack.

pub mod api;
pub mod auth_routes;
pub mod rate_limit;
pub mod request_context;
pub mod security_headers;
pub mod static_files;
pub mod token_routes;

use std::any::Any;

use axum::Router;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Response, header};
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;

use crate::app::AppState;
use crate::error::ApiError;

pub const BODY_LIMIT_BYTES: usize = 16 * 1024;

async fn healthz() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        "ok",
    )
}

/// Reject bodies whose declared length exceeds the limit before any handler runs (JSON for
/// `/api`). Streaming bodies without `Content-Length` are capped by `RequestBodyLimitLayer` and
/// `DefaultBodyLimit`, which surface as a body-read error in the handler.
async fn body_limit(req: axum::extract::Request, next: axum::middleware::Next) -> Response<Body> {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > BODY_LIMIT_BYTES as u64) {
        let path = req.uri().path();
        return if path == "/api" || path.starts_with("/api/") {
            ApiError::PayloadTooLarge.into_response()
        } else {
            crate::error::plain_status(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
            )
        };
    }
    next.run(req).await
}

fn panic_response(_err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    // The panic payload may contain internal details: never send it to the client.
    tracing::error!("handler panicked");
    ApiError::Internal.into_response()
}

/// Build the complete application router with all middleware.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/me", get(api::me))
        .route("/status", get(api::status))
        .route("/ingress/targets", get(api::targets))
        .route("/ingress/switch", post(api::switch))
        .route("/ingress/start", post(api::start))
        .route("/ingress/stop", post(api::stop))
        .route("/ingress/rotate", post(api::rotate))
        .route("/events", get(api::events))
        .route("/subscription", get(api::subscription))
        .route("/wireguard", get(api::wireguard))
        .route(
            "/settings",
            get(api::get_settings)
                .put(api::put_settings)
                .delete(api::reset_settings),
        )
        .route(
            "/settings/debug-log",
            put(api::put_debug_log).delete(api::clear_debug_log),
        )
        .route("/ingress/telemetry", get(api::telemetry))
        .route("/ingress/logs", get(api::logs).delete(api::clear_logs))
        .fallback(api::not_found)
        .method_not_allowed_fallback(api::method_not_allowed);

    let auth = Router::new()
        .route("/login", get(auth_routes::login))
        .route("/callback", get(auth_routes::callback))
        .route("/logout", post(auth_routes::logout))
        .fallback(token_routes::not_found);

    let subscription = Router::new()
        .route("/{token}", get(token_routes::subscription))
        .fallback(token_routes::not_found);

    let ingress = Router::new()
        .route("/{token}/config.json", get(token_routes::ingress_config))
        .route("/{token}/report", post(token_routes::report))
        .fallback(token_routes::not_found);

    // Outermost first.
    let middleware = ServiceBuilder::new()
        .layer(from_fn_with_state(
            state.clone(),
            request_context::request_context,
        ))
        .layer(from_fn(security_headers::security_headers))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(from_fn_with_state(state.clone(), rate_limit::rate_limit))
        .layer(from_fn(request_context::timeout))
        .layer(from_fn(body_limit))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES));

    Router::new()
        .route("/healthz", get(healthz))
        .nest("/api", api)
        .nest("/auth", auth)
        .nest("/s", subscription)
        .nest("/i", ingress)
        .fallback(static_files::serve)
        .layer(middleware)
        .with_state(state)
}

#[cfg(test)]
mod tests;
