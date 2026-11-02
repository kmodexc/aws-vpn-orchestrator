//! Integration tests: the full router (all middleware) with PROVIDER=fake, driven through
//! `tower::ServiceExt::oneshot`. No network access is needed: the OIDC issuer points at a closed
//! local port, so IdP calls fail fast.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use vpn_control::AppState;
use vpn_control::auth::session::SessionData;
use vpn_control::cli::gen_env;
use vpn_control::config::Config;
use vpn_control::providers::IngressProvider;
use vpn_control::providers::fake::FakeProvider;

const BASE: &str = "https://vpn.example.com";
const INDEX_HTML: &str = "<!doctype html><title>spa</title>";

struct TestApp {
    state: AppState,
    router: Router,
    sub_token: String,
    ingress_token: String,
    _state_dir: TempDir,
    _static_dir: TempDir,
}

fn app_with(extra: &[(&str, &str)]) -> TestApp {
    let state_dir = tempfile::tempdir().unwrap();
    let static_dir = tempfile::tempdir().unwrap();
    std::fs::write(static_dir.path().join("index.html"), INDEX_HTML).unwrap();
    std::fs::create_dir(static_dir.path().join("assets")).unwrap();
    std::fs::write(
        static_dir.path().join("assets/app-abc123.js"),
        "console.log(1)",
    )
    .unwrap();

    let mut pairs: Vec<(String, String)> = gen_env::generate_secrets()
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    let dirs = [
        ("STATE_DIR", state_dir.path().to_string_lossy().into_owned()),
        (
            "STATIC_DIR",
            static_dir.path().to_string_lossy().into_owned(),
        ),
    ];
    for (k, v) in dirs {
        pairs.push((k.to_string(), v));
    }
    for (k, v) in [
        ("DOMAIN", "vpn.example.com"),
        ("PUBLIC_BASE_URL", BASE),
        // closed local port: IdP calls fail immediately, tests never touch the network
        ("OIDC_ISSUER_URL", "https://127.0.0.1:9/realms/test"),
        ("OIDC_CLIENT_ID", "vpn-control"),
        ("OIDC_CLIENT_SECRET", "test-client-secret"),
        ("PROVIDER", "fake"),
        ("ROTATE_COOLDOWN_S", "120"),
    ]
    .iter()
    .chain(extra.iter())
    {
        pairs.push(((*k).to_string(), (*v).to_string()));
    }
    let config = Config::from_pairs(pairs).unwrap();
    let sub_token = config.sub_token.expose().clone();
    let ingress_token = config.ingress_token.expose().clone();
    let state = if config.targets.len() == 1 {
        AppState::new(config, Arc::new(FakeProvider::new())).unwrap()
    } else {
        let mut providers = std::collections::HashMap::new();
        for target in &config.targets {
            providers.insert(
                target.id.clone(),
                Arc::new(FakeProvider::new()) as Arc<dyn IngressProvider>,
            );
        }
        AppState::new_with_providers(config, providers).unwrap()
    };
    let router = vpn_control::http::router(state.clone());
    TestApp {
        state,
        router,
        sub_token,
        ingress_token,
        _state_dir: state_dir,
        _static_dir: static_dir,
    }
}

fn app() -> TestApp {
    app_with(&[])
}

impl TestApp {
    /// Create a session the same way the OIDC callback does. Returns (cookie, csrf token).
    fn login(&self, roles: &[&str]) -> (String, String) {
        let cookie = self
            .state
            .sessions
            .create(SessionData {
                sub: "user-1".into(),
                username: "alice".into(),
                email: Some("alice@example.com".into()),
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
                id_token: None,
            })
            .unwrap();
        let csrf = self
            .state
            .sessions
            .get(&cookie)
            .unwrap()
            .csrf_token
            .expose()
            .clone();
        (cookie, csrf)
    }

    async fn send(&self, req: Request<Body>) -> Response {
        self.router.clone().oneshot(req).await.unwrap()
    }

    async fn get(&self, uri: &str) -> Response {
        self.send(request(Method::GET, uri).body(Body::empty()).unwrap())
            .await
    }

    async fn get_with_session(&self, uri: &str, cookie: &str) -> Response {
        self.send(
            request(Method::GET, uri)
                .header(header::COOKIE, session_cookie(cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

fn request(method: Method, uri: &str) -> axum::http::request::Builder {
    let peer: SocketAddr = "192.0.2.10:40000".parse().unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(peer))
}

fn session_cookie(cookie: &str) -> String {
    format!("__Host-sid={cookie}")
}

async fn body_string(resp: Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_json(resp: Response) -> serde_json::Value {
    serde_json::from_str(&body_string(resp).await).unwrap()
}

fn assert_security_headers(resp: &Response, what: &str) {
    let h = resp.headers();
    let expect = [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    ];
    for (name, value) in expect {
        assert_eq!(
            h.get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "{what}: header {name}"
        );
    }
    assert!(h.get(header::SERVER).is_none(), "{what}: Server header");
    assert!(h.get("x-request-id").is_some(), "{what}: X-Request-Id");
    assert!(
        h.get("access-control-allow-origin").is_none(),
        "{what}: no CORS"
    );
}

#[tokio::test]
async fn security_headers_on_every_kind_of_response() {
    let app = app();
    let cases = [
        ("/", StatusCode::OK),
        ("/?login_error=denied", StatusCode::OK),
        ("/healthz", StatusCode::OK),
        ("/assets/app-abc123.js", StatusCode::NOT_FOUND),
        ("/missing.js", StatusCode::NOT_FOUND),
        ("/s/a/b", StatusCode::NOT_FOUND),
        ("/api/status", StatusCode::UNAUTHORIZED),
        ("/api/nonexistent", StatusCode::UNAUTHORIZED),
        ("/auth/whatever", StatusCode::NOT_FOUND),
    ];
    for (uri, status) in cases {
        let resp = app.get(uri).await;
        assert_eq!(resp.status(), status, "{uri}");
        assert_security_headers(&resp, uri);
    }
}

#[tokio::test]
async fn healthz_is_plain_ok() {
    let app = app();
    let resp = app.get("/healthz").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert_eq!(body_string(resp).await, "ok");
}

#[tokio::test]
async fn api_requires_auth_and_is_not_cached() {
    let app = app();
    for uri in [
        "/api/ingress/lifecycle",
        "/api/status",
        "/api/me",
        "/api/events",
        "/api/subscription",
        "/api/wireguard",
    ] {
        let resp = app.get(uri).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        let body = body_json(resp).await;
        assert_eq!(body["error"], "unauthorized");
        assert!(body["message"].is_string());
    }
    // unknown / garbage session cookie
    let resp = app
        .send(
            request(Method::GET, "/api/status")
                .header(header::COOKIE, "__Host-sid=bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // non-bearer Authorization header
    let resp = app
        .send(
            request(Method::GET, "/api/status")
                .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_role_sees_only_the_subscription() {
    // Off unless configured: the role grants nothing by default.
    let plain = app();
    let (c, _) = plain.login(&["vpn-user"]);
    assert_eq!(
        plain.get_with_session("/api/me", &c).await.status(),
        StatusCode::FORBIDDEN
    );

    let app = app_with(&[("OIDC_USER_ROLE", "vpn-user")]);
    let (cookie, csrf) = app.login(&["vpn-user"]);
    let me = body_json(app.get_with_session("/api/me", &cookie).await).await;
    assert_eq!(me["is_admin"], false);
    let (admin, _) = app.login(&["vpn-admin", "vpn-user"]);
    let me = body_json(app.get_with_session("/api/me", &admin).await).await;
    assert_eq!(me["is_admin"], true);

    // the SPA and the subscription are served
    let resp = app.get_with_session("/", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app.get_with_session("/api/subscription", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        body_json(resp).await["url"]
            .as_str()
            .unwrap()
            .contains("/s/")
    );

    // everything else is forbidden, reads and writes alike
    for uri in [
        "/api/ingress/lifecycle",
        "/api/status",
        "/api/events",
        "/api/wireguard",
        "/api/settings",
        "/api/ingress/telemetry",
        "/api/ingress/logs",
    ] {
        let resp = app.get_with_session(uri, &cookie).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body_json(resp).await["error"], "forbidden", "{uri}");
    }
    for uri in [
        "/api/ingress/start",
        "/api/ingress/stop",
        "/api/ingress/rotate",
    ] {
        let resp = app
            .send(
                request(Method::POST, uri)
                    .header(header::COOKIE, session_cookie(&cookie))
                    .header("x-csrf-token", &csrf)
                    .header(header::ORIGIN, BASE)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    let resp = app
        .put_settings(
            &cookie,
            &csrf,
            &settings_body("a.example.com", true, false, true),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        app.state
            .orchestrator
            .store()
            .snapshot()
            .await
            .events
            .is_empty()
    );
}

#[tokio::test]
async fn session_without_role_is_forbidden() {
    let app = app();
    let (cookie, _) = app.login(&["something-else"]);
    let resp = app
        .send(
            request(Method::GET, "/api/status")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "forbidden");
}

#[tokio::test]
async fn me_and_status_with_session() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let resp = app
        .send(
            request(Method::GET, "/api/me")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let me = body_json(resp).await;
    assert_eq!(me["sub"], "user-1");
    assert_eq!(me["username"], "alice");
    assert_eq!(me["email"], "alice@example.com");
    assert_eq!(me["roles"][0], "vpn-admin");
    assert_eq!(me["csrf_token"], csrf.as_str());

    let resp = app
        .send(
            request(Method::GET, "/api/status")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let s = body_json(resp).await;
    assert_eq!(s["provider"], "fake");
    assert_eq!(s["state"], "running");
    assert_eq!(s["public_ip"], "203.0.113.10");
    assert_eq!(s["cooldown_remaining_s"], 0);
    assert!(s["last_rotation_at"].is_null());

    let resp = app
        .send(
            request(Method::GET, "/api/subscription")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let sub = body_json(resp).await;
    assert_eq!(sub["url"], format!("{BASE}/s/{}", app.sub_token));
    assert_eq!(sub["links"].as_array().unwrap().len(), 3);

    let resp = app
        .send(
            request(Method::GET, "/api/wireguard")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let wg = body_json(resp).await;
    assert_eq!(wg["enabled"], false);
    assert!(wg["ingress_public_key"].is_null());
    assert_eq!(wg["ingress_address"], "10.66.0.2/32");
}

#[tokio::test]
async fn configured_targets_can_be_listed_and_switched() {
    let app = app_with(&[(
        "INGRESS_TARGETS",
        "tokyo|fake|ap-northeast-1|tokyo;hongkong|fake|ap-east-1|hongkong",
    )]);
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    let resp = app.get_with_session("/api/ingress/targets", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let targets = body_json(resp).await;
    assert_eq!(targets.as_array().unwrap().len(), 2);
    assert_eq!(targets[0]["id"], "tokyo");
    assert_eq!(targets[0]["active"], true);
    assert_eq!(targets[1]["active"], false);

    let resp = app
        .send(
            request(Method::POST, "/api/ingress/switch")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"target_id":"hongkong","reason":"test"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let status = body_json(resp).await;
    assert_eq!(status["region"], "ap-east-1");
    assert_eq!(status["instance"], "hongkong");

    let status = body_json(app.get_with_session("/api/status", &cookie).await).await;
    assert_eq!(status["region"], "ap-east-1");
    let events = body_json(app.get_with_session("/api/events", &cookie).await).await;
    assert_eq!(events[0]["action"], "switch");
    assert_eq!(events[0]["actor"], "alice");
}

#[tokio::test]
async fn target_switch_requires_valid_json_admin_and_csrf() {
    let app = app_with(&[(
        "INGRESS_TARGETS",
        "tokyo|fake|ap-northeast-1|tokyo;hongkong|fake|ap-east-1|hongkong",
    )]);
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    for (content_type, body) in [
        (None, r#"{"target_id":"hongkong"}"#),
        (Some("text/plain"), r#"{"target_id":"hongkong"}"#),
        (
            Some("application/json"),
            r#"{"target_id":"hongkong","extra":true}"#,
        ),
        (Some("application/json"), "[]"),
    ] {
        let mut builder = request(Method::POST, "/api/ingress/switch")
            .header(header::COOKIE, session_cookie(&cookie))
            .header("x-csrf-token", &csrf)
            .header(header::ORIGIN, BASE);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let resp = app.send(builder.body(Body::from(body)).unwrap()).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{content_type:?} {body}"
        );
    }

    let resp = app
        .send(
            request(Method::POST, "/api/ingress/switch")
                .header(header::COOKIE, session_cookie(&cookie))
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"target_id":"hongkong"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let (user_cookie, user_csrf) = app.login(&["vpn-user"]);
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/switch")
                .header(header::COOKIE, session_cookie(&user_cookie))
                .header("x-csrf-token", &user_csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"target_id":"hongkong"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cookie_mutation_requires_csrf_token_and_origin() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    // no CSRF header at all
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/start")
                .header(header::COOKIE, session_cookie(&cookie))
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "csrf");

    // right token, foreign origin
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/start")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, "https://evil.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(resp).await["error"], "csrf");

    // right token and origin
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/start")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(resp).await, serde_json::json!({"ok": true}));

    // stop with Referer instead of Origin
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/stop")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::REFERER, format!("{BASE}/dashboard"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // the event log shows both operations, newest first
    let resp = app
        .send(
            request(Method::GET, "/api/events?limit=10")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let events = body_json(resp).await;
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["action"], "stop");
    assert_eq!(events[1]["action"], "start");
    assert_eq!(events[0]["actor"], "alice");
}

#[tokio::test]
async fn wrong_subscription_token_is_a_plain_404() {
    let app = app();
    let unknown = app.get("/definitely/not/here.txt").await;
    let unknown_status = unknown.status();
    let unknown_type = unknown.headers()[header::CONTENT_TYPE].clone();
    let unknown_body = body_string(unknown).await;

    let wrong = format!("/s/{}", "x".repeat(43));
    let resp = app.get(&wrong).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.status(), unknown_status);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], unknown_type);
    assert_eq!(body_string(resp).await, unknown_body);

    let resp = app.get("/i/wrong-token/config.json").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(resp).await, unknown_body);

    // the ingress token is not a subscription token and vice versa
    let resp = app.get(&format!("/s/{}", app.ingress_token)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app.get(&format!("/i/{}/config.json", app.sub_token)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn subscription_returns_base64_with_three_links() {
    let app = app();
    let resp = app.get(&format!("/s/{}", app.sub_token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert!(
        h[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert_eq!(h["profile-update-interval"], "1");
    assert_eq!(h["profile-title"], "base64:dHJhdmVs");
    assert_security_headers(&resp, "/s/<token>");
    let body = body_string(resp).await;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .unwrap();
    let text = String::from_utf8(decoded).unwrap();
    let links: Vec<&str> = text.split('\n').collect();
    assert_eq!(links.len(), 3);
    assert!(links[0].starts_with("vless://"));
    assert!(links[1].starts_with("hysteria2://"));
    assert!(links[2].starts_with("ss://"));
    for l in &links {
        assert!(l.contains("@203.0.113.10:"), "{l}");
    }
}

#[tokio::test]
async fn subscription_is_503_without_public_ip() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/stop")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let resp = app.get(&format!("/s/{}", app.sub_token)).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let resp = app
        .send(
            request(Method::GET, "/api/subscription")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(body_json(resp).await["links"].is_null());
}

#[tokio::test]
async fn ingress_config_with_right_token() {
    let app = app();
    let resp = app
        .get(&format!("/i/{}/config.json", app.ingress_token))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    let cfg = body_json(resp).await;
    assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 3);
    assert_eq!(cfg["route"]["final"], "direct");
}

#[tokio::test]
async fn repeated_wrong_tokens_trigger_the_failure_limiter() {
    let app = app();
    for _ in 0..10 {
        let resp = app.get("/s/wrong-token-wrong-token-wrong-token-xx").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    // now even the right token is refused from this IP
    let resp = app.get(&format!("/s/{}", app.sub_token)).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 500);
}

#[tokio::test]
async fn malformed_bearer_is_401_and_a_failure_even_when_idp_is_down() {
    // The IdP (closed local port) is unreachable, but structurally invalid tokens are rejected
    // offline: 401, never 503, and each one counts for the failure limiter.
    let app = app();
    for _ in 0..10 {
        let resp = app
            .send(
                request(Method::GET, "/api/me")
                    .header(header::AUTHORIZATION, "Bearer abc.def.ghi")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let resp = app.get("/api/me").await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn token_endpoints_are_rate_limited() {
    let app = app();
    let mut limited = false;
    for _ in 0..40 {
        let resp = app.get(&format!("/s/{}", app.sub_token)).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            assert!(resp.headers().get(header::RETRY_AFTER).is_some());
            limited = true;
            break;
        }
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert!(limited, "30/min limit not enforced");
}

async fn rotate(app: &TestApp, cookie: &str, csrf: &str, body: &str) -> Response {
    app.send(
        request(Method::POST, "/api/ingress/rotate")
            .header(header::COOKIE, session_cookie(cookie))
            .header("x-csrf-token", csrf)
            .header(header::ORIGIN, BASE)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn rotate_then_cooldown() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    let resp = rotate(
        &app,
        &cookie,
        &csrf,
        r#"{"reason":"blocked in hotel wifi"}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ip = body_json(resp).await["public_ip"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(ip, "203.0.113.10");
    assert!(ip.starts_with("203.0.113."));

    let resp = rotate(&app, &cookie, &csrf, "{}").await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_header: u64 = resp.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["error"], "cooldown");
    let retry_body = body["retry_after_s"].as_u64().unwrap();
    assert!(retry_body > 0 && retry_body <= 120);
    assert_eq!(retry_header, retry_body);

    // the status reflects the rotation
    let resp = app
        .send(
            request(Method::GET, "/api/status")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let s = body_json(resp).await;
    assert_eq!(s["public_ip"], ip.as_str());
    assert!(s["cooldown_remaining_s"].as_u64().unwrap() > 0);
    assert!(s["last_rotation_at"].as_i64().is_some());

    let resp = app
        .send(
            request(Method::GET, "/api/events")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let events = body_json(resp).await;
    assert_eq!(events[0]["action"], "rotate");
    assert_eq!(events[0]["detail"], "blocked in hotel wifi");
    assert_eq!(events[0]["ip"], ip.as_str());
}

#[tokio::test]
async fn rotate_validates_the_body() {
    let app = app_with(&[("ROTATE_COOLDOWN_S", "0")]);
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    for bad in [
        r#"{"reason":"x","extra":1}"#,
        r#"{"reason":5}"#,
        "not json",
        &format!(r#"{{"reason":"{}"}}"#, "a".repeat(201)),
    ] {
        let resp = rotate(&app, &cookie, &csrf, bad).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(body_json(resp).await["error"], "bad_request");
    }
    // empty body is fine
    let resp = rotate(&app, &cookie, &csrf, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let big = format!(r#"{{"reason":"{}"}}"#, "a".repeat(20 * 1024));
    let resp = rotate(&app, &cookie, &csrf, &big).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_security_headers(&resp, "413");
    assert_eq!(body_json(resp).await["error"], "bad_request");

    // declared Content-Length over the limit is rejected before authentication even runs
    let resp = app
        .send(
            request(Method::POST, "/api/ingress/start")
                .header(header::CONTENT_LENGTH, big.len())
                .body(Body::from(big.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(resp).await["error"], "bad_request");
}

#[tokio::test]
async fn api_paths_never_fall_back_to_index_html() {
    let app = app();
    let (cookie, _) = app.login(&["vpn-admin"]);
    for uri in [
        "/api/nonexistent",
        "/api",
        "/api/",
        "/api/ingress",
        "/auth",
        "/auth/",
        "/s",
        "/s/",
        "/i",
        "/i/x",
        "/i/x/other.json",
    ] {
        let resp = app.get_with_session(uri, &cookie).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        let body = body_string(resp).await;
        assert!(
            !body.contains("<title>spa</title>"),
            "{uri} served index.html"
        );
    }
    let resp = app.get_with_session("/api/nonexistent", &cookie).await;
    assert_eq!(body_json(resp).await["error"], "not_found");
}

#[tokio::test]
async fn anonymous_api_probing_reveals_nothing() {
    let app = app();
    // Known and unknown paths, any method: the same 401 JSON.
    for (method, uri) in [
        (Method::GET, "/api/nonexistent"),
        (Method::GET, "/api"),
        (Method::GET, "/api/ingress/rotate"),
        (Method::DELETE, "/api/status"),
        (Method::POST, "/api/whatever"),
        (Method::PATCH, "/api/settings"),
    ] {
        let resp = app
            .send(request(method.clone(), uri).body(Body::empty()).unwrap())
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(body_json(resp).await["error"], "unauthorized");
    }
}

#[tokio::test]
async fn anonymous_visitors_get_no_app_code() {
    let app = app();
    // Pages: a bare neutral page with a sign-in link that keeps the target. No redirect, so a
    // crawler following links does not create pending logins by itself.
    let resp = app.get("/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    let body = body_string(resp).await;
    assert!(
        body.contains(&format!("href=\"{BASE}/auth/login\"")),
        "{body}"
    );
    // Nothing of the app, and no telling words (BASE itself happens to contain "vpn").
    let text = body.replace(BASE, "").to_lowercase();
    assert!(!text.contains("spa") && !text.contains("vpn"), "{body}");
    assert_eq!(app.state.sessions.pending_len(), 0);
    let resp = app.get("/events?x=1").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains(&format!(
        "href=\"{BASE}/auth/login?return_to=%2Fevents%3Fx%3D1\""
    )));
    // Files: plain 404, never the SPA.
    for uri in ["/assets/app-abc123.js", "/index.html", "/favicon.svg"] {
        let resp = app.get(uri).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        assert!(!body_string(resp).await.contains("spa"), "{uri}");
    }
    // An unknown or expired session is anonymous.
    let resp = app.get_with_session("/assets/app-abc123.js", "bogus").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // A failed login adds a message; "try again" starts from the home page.
    let resp = app.get("/?login_error=forbidden").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("This account has no access."));
    assert!(body.contains(&format!("href=\"{BASE}/auth/login\"")));
    assert!(!body.contains("spa"));
}

#[tokio::test]
async fn spa_routes_fall_back_to_index_html() {
    let app = app();
    let (cookie, _) = app.login(&["vpn-admin"]);
    for uri in ["/", "/dashboard", "/settings/profile?x=1"] {
        let resp = app.get_with_session(uri, &cookie).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        assert!(
            resp.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(body_string(resp).await, INDEX_HTML);
    }
    let resp = app.get_with_session("/assets/app-abc123.js", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::CACHE_CONTROL],
        "private, max-age=31536000, immutable"
    );
    // path traversal is not possible
    let resp = app.get_with_session("/../Cargo.toml", &cookie).await;
    assert!(!body_string(resp).await.contains("[package]"));
    let resp = app
        .get_with_session("/assets/..%2f..%2fCargo.toml", &cookie)
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // non-GET to the SPA is a plain 404
    let resp = app
        .send(
            request(Method::POST, "/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn login_redirects_with_error_when_idp_is_unreachable() {
    let app = app();
    let resp = app.get("/auth/login?return_to=/dashboard").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers()[header::LOCATION],
        format!("{BASE}/?login_error=unavailable").as_str()
    );
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn callback_without_pending_login_is_invalid() {
    let app = app();
    let resp = app.get("/auth/callback?code=abc&state=def").await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers()[header::LOCATION],
        format!("{BASE}/?login_error=invalid").as_str()
    );
}

#[tokio::test]
async fn logout_requires_csrf_and_destroys_the_session() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let resp = app
        .send(
            request(Method::POST, "/auth/logout")
                .header(header::COOKIE, session_cookie(&cookie))
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(app.state.sessions.get(&cookie).is_some());

    let resp = app
        .send(
            request(Method::POST, "/auth/logout")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("__Host-sid=;"));
    assert!(set_cookie.contains("Max-Age=0"));
    // IdP unreachable → falls back to the app's home page
    assert_eq!(
        body_json(resp).await["logout_url"],
        format!("{BASE}/").as_str()
    );
    assert!(app.state.sessions.get(&cookie).is_none());

    let resp = app
        .send(
            request(Method::GET, "/api/me")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn trusted_proxy_header_selects_the_client_ip() {
    let app = app_with(&[("TRUST_PROXY_HEADERS", "true")]);
    // Ten failures from one forwarded client block that client only.
    for _ in 0..10 {
        let resp = app
            .send(
                request(Method::GET, "/s/wrong-token-wrong-token-wrong-token-yy")
                    .header("x-forwarded-for", "198.51.100.1, 203.0.113.99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    let blocked = app
        .send(
            request(Method::GET, &format!("/s/{}", app.sub_token))
                .header("x-forwarded-for", "203.0.113.99")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    let other = app
        .send(
            request(Method::GET, &format!("/s/{}", app.sub_token))
                .header("x-forwarded-for", "203.0.113.100")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(other.status(), StatusCode::OK);
}

#[tokio::test]
async fn method_not_allowed_on_api_is_json() {
    let app = app();
    let (cookie, _) = app.login(&["vpn-admin"]);
    let resp = app
        .send(
            request(Method::DELETE, "/api/status")
                .header(header::COOKIE, session_cookie(&cookie))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_security_headers(&resp, "405");
    assert_eq!(body_json(resp).await["error"], "bad_request");
}

fn settings_body(reality: &str, hy2: bool, obfs: bool, ss: bool) -> String {
    serde_json::json!({
        "reality_sni": reality,
        "hy2_sni": "www.bing.com",
        "hysteria2": hy2,
        "hy2_obfs": obfs,
        "shadowsocks": ss,
    })
    .to_string()
}

impl TestApp {
    async fn put_settings(&self, cookie: &str, csrf: &str, body: &str) -> Response {
        self.send(
            request(Method::PUT, "/api/settings")
                .header(header::COOKIE, session_cookie(cookie))
                .header("x-csrf-token", csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn ingress_config(&self) -> serde_json::Value {
        body_json(
            self.get(&format!("/i/{}/config.json", self.ingress_token))
                .await,
        )
        .await
    }
}

#[tokio::test]
async fn settings_change_the_ingress_config_and_subscription() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    let resp = app.get_with_session("/api/settings", &cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["overridden"], false);
    assert_eq!(v["settings"]["reality_sni"], "www.microsoft.com");
    assert_eq!(v["settings"]["shadowsocks"], true);
    assert_eq!(v["ports"]["ss"], 8443);
    assert_eq!(
        app.ingress_config().await["inbounds"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // REALITY only, other camouflage target
    let resp = app
        .put_settings(
            &cookie,
            &csrf,
            &settings_body("WWW.Example.com", false, false, false),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp).await;
    assert_eq!(v["overridden"], true);
    assert_eq!(v["settings"]["reality_sni"], "www.example.com");
    assert_eq!(v["defaults"]["reality_sni"], "www.microsoft.com");

    let cfg = app.ingress_config().await;
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0]["tls"]["server_name"], "www.example.com");

    app.state.orchestrator.start("t".into()).await.unwrap();
    let resp = app.get(&format!("/s/{}", app.sub_token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(body_string(resp).await)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("vless://") && text.contains("sni=www.example.com"));

    // Hysteria2 with Salamander
    let resp = app
        .put_settings(
            &cookie,
            &csrf,
            &settings_body("www.example.com", true, true, false),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg = app.ingress_config().await;
    assert_eq!(cfg["inbounds"][1]["obfs"]["type"], "salamander");

    // the change is in the event log, with the actor
    let resp = app.get_with_session("/api/events", &cookie).await;
    let events = body_json(resp).await;
    assert_eq!(events[0]["action"], "settings");
    assert_eq!(events[0]["actor"], "alice");
    assert!(
        events[0]["detail"]
            .as_str()
            .unwrap()
            .contains("hy2_obfs=on")
    );

    // saving the same settings again changes nothing and logs nothing
    let before = app.state.orchestrator.store().snapshot().await;
    let resp = app
        .put_settings(
            &cookie,
            &csrf,
            &settings_body("www.example.com", true, true, false),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(app.state.orchestrator.store().snapshot().await, before);

    // reset to .env
    let resp = app
        .send(
            request(Method::DELETE, "/api/settings")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["overridden"], false);
    assert_eq!(
        app.ingress_config().await["inbounds"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let events = body_json(app.get_with_session("/api/events", &cookie).await).await;
    assert!(
        events[0]["detail"]
            .as_str()
            .unwrap()
            .starts_with("reset to .env defaults: ")
    );

    // an override equal to the .env defaults is still an override, and a reset clears it
    let defaults =
        body_json(app.get_with_session("/api/settings", &cookie).await).await["defaults"].clone();
    let resp = app
        .put_settings(&cookie, &csrf, &defaults.to_string())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["overridden"], true);
    let resp = app
        .send(
            request(Method::DELETE, "/api/settings")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["overridden"], false);

    // a reset without an override is a no-op
    let before = app.state.orchestrator.store().snapshot().await;
    let resp = app
        .send(
            request(Method::DELETE, "/api/settings")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(app.state.orchestrator.store().snapshot().await, before);
}

#[tokio::test]
async fn settings_updates_are_validated_and_protected() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    for bad in [
        settings_body("localhost", true, false, true),
        settings_body("1.2.3.4", true, false, true),
        settings_body("https://x.example.com", true, false, true),
        r#"{"reality_sni":"a.example.com"}"#.to_string(),
        r#"{"reality_sni":"a.example.com","hy2_sni":"b.example.com","hysteria2":true,"hy2_obfs":false,"shadowsocks":true,"extra":1}"#.to_string(),
        String::new(),
    ] {
        let resp = app.put_settings(&cookie, &csrf, &bad).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    // CSRF is required for a cookie session
    let resp = app
        .send(
            request(Method::PUT, "/api/settings")
                .header(header::COOKIE, session_cookie(&cookie))
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(settings_body(
                    "a.example.com",
                    true,
                    false,
                    true,
                )))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // the role is required
    let (other, other_csrf) = app.login(&["something-else"]);
    let resp = app
        .put_settings(
            &other,
            &other_csrf,
            &settings_body("a.example.com", true, false, true),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // nothing was stored
    let v = body_json(app.get_with_session("/api/settings", &cookie).await).await;
    assert_eq!(v["overridden"], false);
}

fn report_body(hash: &str, log: &[&str]) -> String {
    serde_json::json!({
        "version": "1.14.4",
        "uptime_s": 120,
        "connections": 3,
        "upload_total": 1000,
        "download_total": 5000,
        "config_sha256": hash,
        "log": log,
        "log_dropped": 0,
    })
    .to_string()
}

impl TestApp {
    async fn post_report(&self, token: &str, body: &str) -> Response {
        self.send(
            request(Method::POST, &format!("/i/{token}/report"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn config_hash(&self) -> String {
        let resp = self
            .get(&format!("/i/{}/config.json", self.ingress_token))
            .await;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        hex::encode(vpn_control::util::sha256(&bytes))
    }
}

#[tokio::test]
async fn ingress_reports_feed_telemetry_and_logs() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);

    // wrong token: generic 404, no telemetry
    let resp = app
        .post_report(
            "wrong-token-wrong-token-wrong-token-yy",
            &report_body(&"a".repeat(64), &[]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let t = body_json(
        app.get_with_session("/api/ingress/telemetry", &cookie)
            .await,
    )
    .await;
    assert!(t["report"]["last_report_at"].is_null());
    assert_eq!(t["log_level"], "warn");

    // a valid report with the current config hash
    let hash = app.config_hash().await;
    let resp = app
        .post_report(
            &app.ingress_token,
            &report_body(&hash, &["first \u{1b}[31mline\u{1b}[0m", "second"]),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let reply = body_json(resp).await;
    assert_eq!(reply["config_stale"], false);
    assert_eq!(reply["config_sha256"], hash.as_str());

    let t = body_json(
        app.get_with_session("/api/ingress/telemetry", &cookie)
            .await,
    )
    .await;
    assert_eq!(t["report"]["connections"], 3);
    assert_eq!(t["report"]["download_24h"], 5000);
    assert_eq!(t["report"]["version"], "1.14.4");
    assert_eq!(t["report"]["log_lines"], 2);

    let l = body_json(app.get_with_session("/api/ingress/logs", &cookie).await).await;
    assert_eq!(l["lines"][0]["text"], "first line");
    assert_eq!(l["lines"][1]["seq"], 1);
    assert_eq!(l["next"], 2);
    assert!(l["epoch"].is_u64());
    let epoch = l["epoch"].clone();
    let l = body_json(
        app.get_with_session("/api/ingress/logs?after=2", &cookie)
            .await,
    )
    .await;
    assert_eq!(l["lines"].as_array().unwrap().len(), 0);
    assert_eq!(l["next"], 2);
    // a cursor from a previous life of the server does not stall the client
    let l = body_json(
        app.get_with_session("/api/ingress/logs?after=999", &cookie)
            .await,
    )
    .await;
    assert_eq!(l["next"], 2);
    assert_eq!(l["epoch"], epoch);

    // the log level is raised through the UI; the served config changes and the report
    // reply flags the old hash as stale
    let resp = app
        .send(
            request(Method::PUT, "/api/settings/debug-log")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"level":"info","minutes":30}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let t = body_json(resp).await;
    assert_eq!(t["log_level"], "info");
    assert!(t["debug_log"]["until"].as_i64().unwrap() > t["now"].as_i64().unwrap());
    // the lines collected meanwhile are scheduled to be discarded after the level reverts
    assert_eq!(
        t["report"]["log_purge_at"].as_i64().unwrap(),
        t["debug_log"]["until"].as_i64().unwrap() + 3600
    );
    let cfg = body_json(
        app.get(&format!("/i/{}/config.json", app.ingress_token))
            .await,
    )
    .await;
    assert_eq!(cfg["log"]["level"], "info");
    let reply = body_json(
        app.post_report(&app.ingress_token, &report_body(&hash, &[]))
            .await,
    )
    .await;
    assert_eq!(reply["config_stale"], true);
    assert_ne!(reply["config_sha256"], hash.as_str());

    // and back to warn; the change is in the event log
    let resp = app
        .send(
            request(Method::DELETE, "/api/settings/debug-log")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["log_level"], "warn");
    assert_eq!(app.config_hash().await, hash);
    let events = body_json(app.get_with_session("/api/events", &cookie).await).await;
    assert_eq!(events[0]["action"], "settings");
    assert!(
        events[0]["detail"]
            .as_str()
            .unwrap()
            .contains("back to warn")
    );
    assert!(
        events[1]["detail"]
            .as_str()
            .unwrap()
            .contains("info for 30 min")
    );

    // invalid requests
    for bad in [
        r#"{"level":"warn","minutes":10}"#,
        r#"{"level":"info","minutes":0}"#,
        r#"{"level":"info","minutes":100000}"#,
        r#"{"level":"info"}"#,
        r#"{"level":"info","minutes":5,"x":1}"#,
    ] {
        let resp = app
            .send(
                request(Method::PUT, "/api/settings/debug-log")
                    .header(header::COOKIE, session_cookie(&cookie))
                    .header("x-csrf-token", &csrf)
                    .header(header::ORIGIN, BASE)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    for bad in [
        "not json".to_string(),
        r#"{"version":"x"}"#.to_string(),
        report_body("nothex", &[]),
        report_body(&hash, &[]).replace("\"log_dropped\":0", "\"log_dropped\":0,\"extra\":1"),
    ] {
        let resp = app.post_report(&app.ingress_token, &bad).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let big = report_body(&hash, &[&"x".repeat(20_000)]);
    let resp = app.post_report(&app.ingress_token, &big).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // clearing the log buffer
    let resp = app
        .send(
            request(Method::DELETE, "/api/ingress/logs")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_ne!(
        body_json(resp).await["epoch"],
        epoch,
        "clearing starts a new epoch"
    );
    let t = body_json(
        app.get_with_session("/api/ingress/telemetry", &cookie)
            .await,
    )
    .await;
    assert_eq!(t["report"]["log_lines"], 0);
}

#[tokio::test]
async fn lifecycle_requires_admin_and_csrf_and_reports_disabled_mode() {
    let app = app();
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let response = app
        .get_with_session("/api/ingress/lifecycle", &cookie)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["enabled"], false);
    for (token, expected) in [
        (None, StatusCode::FORBIDDEN),
        (Some(csrf.as_str()), StatusCode::BAD_REQUEST),
    ] {
        let mut builder = request(Method::POST, "/api/ingress/lifecycle")
            .header(header::COOKIE, session_cookie(&cookie))
            .header(header::ORIGIN, BASE)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header("x-csrf-token", token);
        }
        let response = app
            .send(builder.body(Body::from(r#"{"action":"delete"}"#)).unwrap())
            .await;
        assert_eq!(response.status(), expected);
    }
}

struct OnDemandEc2;
#[async_trait::async_trait]
impl vpn_control::lifecycle::Provisioner for OnDemandEc2 {
    fn provider(&self) -> &'static str {
        "ec2"
    }
    fn plan(&self, region: &str, id: &str) -> anyhow::Result<vpn_control::lifecycle::Deployment> {
        use vpn_control::lifecycle::{Deployment, DeploymentResources};
        Ok(Deployment {
            id: id.into(),
            region: region.into(),
            managed: true,
            public_ip: None,
            resources: DeploymentResources::Ec2 {
                instance_id: None,
                volume_ids: vec![],
                allocation_id: None,
                association_id: None,
                launch: None,
            },
        })
    }
    async fn ensure(
        &self,
        d: &vpn_control::lifecycle::Deployment,
    ) -> anyhow::Result<vpn_control::lifecycle::Deployment> {
        let mut result = d.clone();
        result.public_ip = Some("203.0.113.44".parse()?);
        if let vpn_control::lifecycle::DeploymentResources::Ec2 { instance_id, .. } =
            &mut result.resources
        {
            *instance_id = Some("i-12345678901234567".into());
        }
        Ok(result)
    }
    async fn discover(
        &self,
        d: &vpn_control::lifecycle::Deployment,
    ) -> anyhow::Result<vpn_control::lifecycle::Deployment> {
        Ok(d.clone())
    }
    async fn destroy(&self, _: &vpn_control::lifecycle::Deployment) -> anyhow::Result<()> {
        Ok(())
    }
    async fn status(
        &self,
        d: &vpn_control::lifecycle::Deployment,
    ) -> anyhow::Result<vpn_control::providers::IngressStatus> {
        Ok(vpn_control::providers::IngressStatus {
            state: "running".into(),
            public_ip: d.public_ip,
        })
    }
    async fn reachable(&self, _: &vpn_control::lifecycle::Deployment) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[tokio::test]
async fn ec2_on_demand_api_creates_and_deletes_without_preexisting_instance() {
    let mut app = app_with(&[
        ("PROVIDER", "ec2"),
        ("AWS_REGION", "ap-east-1"),
        ("AWS_ACCESS_KEY_ID", "test"),
        ("AWS_SECRET_ACCESS_KEY", "test"),
        ("INGRESS_ON_DEMAND", "true"),
        ("INGRESS_REGIONS", "ap-east-1"),
        ("INGRESS_RECONNECT_GRACE_S", "0"),
        (
            "EC2_REGION_CONFIG",
            r#"{"ap-east-1":{"ami_id":"ami-12345678901234567","subnet_id":"subnet-12345678901234567","security_group_ids":["sg-12345678901234567"]}}"#,
        ),
    ]);
    app.router = Router::new(); // Release router clones before installing the provider.
    app.state = app
        .state
        .with_provisioner(Arc::new(OnDemandEc2))
        .await
        .unwrap();
    app.router = vpn_control::http::router(app.state.clone());
    let (cookie, csrf) = app.login(&["vpn-admin"]);
    let status = body_json(app.get_with_session("/api/status", &cookie).await).await;
    assert_eq!(status["state"], "absent");
    assert_eq!(status["provider"], "ec2");
    let response = app
        .send(
            request(Method::POST, "/api/ingress/lifecycle")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"action":"switch","region":"ap-east-1"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let job = body_json(response).await;
    app.state
        .lifecycle
        .as_ref()
        .unwrap()
        .report_ready(job["id"].as_str().unwrap())
        .await
        .unwrap();
    for _ in 0..1000 {
        if app
            .state
            .lifecycle
            .as_ref()
            .unwrap()
            .view()
            .await
            .job
            .as_ref()
            .is_some_and(|j| j.stage == vpn_control::lifecycle::Stage::Complete)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        app.state
            .lifecycle
            .as_ref()
            .unwrap()
            .view()
            .await
            .job
            .unwrap()
            .stage,
        vpn_control::lifecycle::Stage::Complete
    );
    let status = body_json(app.get_with_session("/api/status", &cookie).await).await;
    assert_eq!(status["state"], "running");
    assert_eq!(status["instance"], "i-12345678901234567");
    let response = app
        .send(
            request(Method::POST, "/api/ingress/lifecycle")
                .header(header::COOKIE, session_cookie(&cookie))
                .header("x-csrf-token", &csrf)
                .header(header::ORIGIN, BASE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"action":"delete"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    for _ in 0..1000 {
        if app
            .state
            .lifecycle
            .as_ref()
            .unwrap()
            .view()
            .await
            .job
            .as_ref()
            .is_some_and(|j| j.stage == vpn_control::lifecycle::Stage::Complete)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        app.state
            .lifecycle
            .as_ref()
            .unwrap()
            .view()
            .await
            .job
            .unwrap()
            .stage,
        vpn_control::lifecycle::Stage::Complete
    );
    let status = body_json(app.get_with_session("/api/status", &cookie).await).await;
    assert_eq!(status["state"], "absent");
    assert!(status["public_ip"].is_null());
    assert_eq!(
        app.get(&format!("/s/{}", app.sub_token)).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
