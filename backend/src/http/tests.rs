//! Router-level tests for Bearer (JWT) authentication. The JWKS is injected into the OIDC
//! cache through a `#[cfg(test)]`-only hook, so no network is needed.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::Response;
use http_body_util::BodyExt;
use jsonwebtoken::Algorithm;
use tower::ServiceExt;

use crate::app::AppState;
use crate::auth::jwt::test_keys::{self, CLIENT, ISSUER};
use crate::config::Config;
use crate::config::tests::valid_pairs;
use crate::providers::fake::FakeProvider;

struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut pairs = valid_pairs();
    pairs.push((
        "STATE_DIR".into(),
        dir.path().to_string_lossy().into_owned(),
    ));
    pairs.push((
        "STATIC_DIR".into(),
        dir.path().to_string_lossy().into_owned(),
    ));
    pairs.push(("OIDC_ISSUER_URL".into(), ISSUER.into()));
    pairs.push(("OIDC_CLIENT_ID".into(), CLIENT.into()));
    pairs.push((
        "OIDC_ALLOWED_CLIENTS".into(),
        format!("{CLIENT},android-app"),
    ));
    let config = Config::from_pairs(pairs).unwrap();
    let state = AppState::new(config, Arc::new(FakeProvider::new())).unwrap();
    state.oidc.inject_jwks_for_tests(test_keys::jwks()).await;
    Harness { state, _dir: dir }
}

impl Harness {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        auth: Option<&str>,
        cookie: Option<&str>,
    ) -> Response {
        self.call_with_body(method, uri, auth, cookie, None, "")
            .await
    }

    async fn call_with_body(
        &self,
        method: Method,
        uri: &str,
        auth: Option<&str>,
        cookie: Option<&str>,
        content_type: Option<&str>,
        body: &str,
    ) -> Response {
        let peer: SocketAddr = "192.0.2.50:5000".parse().unwrap();
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(peer));
        if let Some(a) = auth {
            req = req.header(header::AUTHORIZATION, a);
        }
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, format!("__Host-vpncp_session={c}"));
        }
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        super::router(self.state.clone())
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
}

async fn json(resp: Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn bearer(claims: &serde_json::Value) -> String {
    format!("Bearer {}", test_keys::sign(claims))
}

#[tokio::test]
async fn valid_bearer_token_is_accepted_without_csrf() {
    let h = harness().await;
    let token = bearer(&test_keys::access_claims());

    let resp = h.call(Method::GET, "/api/me", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let me = json(resp).await;
    assert_eq!(me["sub"], "user-1");
    assert_eq!(me["username"], "alice");
    assert!(me["csrf_token"].is_null());

    // Bearer requests are exempt from CSRF.
    let resp = h
        .call(Method::POST, "/api/ingress/start", Some(&token), None)
        .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn other_allowed_client_is_accepted() {
    let h = harness().await;
    let mut claims = test_keys::access_claims();
    claims["azp"] = "android-app".into();
    let resp = h
        .call(Method::GET, "/api/status", Some(&bearer(&claims)), None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn bearer_without_role_is_forbidden() {
    let h = harness().await;
    let mut claims = test_keys::access_claims();
    claims["realm_access"] = serde_json::json!({"roles": ["user"]});
    let resp = h
        .call(Method::GET, "/api/status", Some(&bearer(&claims)), None)
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(resp).await["error"], "forbidden");
}

#[tokio::test]
async fn invalid_bearer_tokens_are_unauthorized() {
    let h = harness().await;
    let mut expired = test_keys::access_claims();
    expired["exp"] = (test_keys::now() - 3600).into();
    let mut wrong_azp = test_keys::access_claims();
    wrong_azp["azp"] = "evil-client".into();
    let mut wrong_iss = test_keys::access_claims();
    wrong_iss["iss"] = "https://evil.example.com/realms/test".into();
    let hs256 = test_keys::sign_with(
        &test_keys::access_claims(),
        Algorithm::HS256,
        Some(test_keys::KID),
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    );
    let unknown_kid = test_keys::sign_with(
        &test_keys::access_claims(),
        Algorithm::RS256,
        Some("rotated-away"),
        &test_keys::rsa().encoding,
    );
    for auth in [
        bearer(&expired),
        bearer(&wrong_azp),
        bearer(&wrong_iss),
        format!("Bearer {hs256}"),
        format!("Bearer {unknown_kid}"),
        "Bearer not-a-jwt".to_string(),
        "Bearer ".to_string(),
    ] {
        let resp = h.call(Method::GET, "/api/me", Some(&auth), None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{auth}");
    }
}

#[tokio::test]
async fn bearer_ignores_cookies() {
    let h = harness().await;
    let cookie = h
        .state
        .sessions
        .create(crate::auth::session::SessionData {
            sub: "cookie-user".into(),
            username: "cookie-user".into(),
            email: None,
            roles: vec!["vpn-admin".into()],
            id_token: None,
        })
        .unwrap();
    // An invalid bearer token is not rescued by a valid session cookie.
    let resp = h
        .call(
            Method::GET,
            "/api/me",
            Some("Bearer garbage"),
            Some(&cookie),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // The session alone works.
    let resp = h.call(Method::GET, "/api/me", None, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json(resp).await["sub"], "cookie-user");
}

#[tokio::test]
async fn bad_bearer_tokens_count_as_failures() {
    let h = harness().await;
    for _ in 0..10 {
        let resp = h
            .call(Method::GET, "/api/me", Some("Bearer garbage"), None)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let resp = h
        .call(
            Method::GET,
            "/api/me",
            Some(&bearer(&test_keys::access_claims())),
            None,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(resp).await["error"], "rate_limited");
}

async fn with_discovery(h: &Harness) {
    h.state
        .oidc
        .inject_discovery_for_tests(crate::auth::oidc::Discovery {
            issuer: ISSUER.into(),
            authorization_endpoint: format!("{ISSUER}/protocol/openid-connect/auth"),
            // closed local port: the code exchange fails fast with "unavailable"
            token_endpoint: "https://127.0.0.1:9/token".into(),
            jwks_uri: "https://127.0.0.1:9/certs".into(),
            end_session_endpoint: Some(format!("{ISSUER}/protocol/openid-connect/logout")),
        })
        .await;
}

fn location(resp: &Response) -> String {
    resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

async fn start_login(h: &Harness) -> (String, url::Url) {
    let resp = h
        .call(Method::GET, "/auth/login?return_to=/events", None, None)
        .await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let set_cookie = resp.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    for attr in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(set_cookie.contains(attr), "{attr}");
    }
    let login_cookie = set_cookie
        .strip_prefix("__Host-vpncp_login=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    (login_cookie, url::Url::parse(&location(&resp)).unwrap())
}

async fn callback(h: &Harness, login_cookie: &str, query: &str) -> Response {
    let peer: SocketAddr = "192.0.2.50:5000".parse().unwrap();
    let req = Request::builder()
        .uri(format!("/auth/callback?{query}"))
        .extension(ConnectInfo(peer))
        .header(header::COOKIE, format!("__Host-vpncp_login={login_cookie}"))
        .body(Body::empty())
        .unwrap();
    super::router(h.state.clone()).oneshot(req).await.unwrap()
}

#[tokio::test]
async fn login_redirects_to_idp_with_pkce_state_and_nonce() {
    let h = harness().await;
    with_discovery(&h).await;
    let (_cookie, url) = start_login(&h).await;
    assert!(
        url.as_str()
            .starts_with(&format!("{ISSUER}/protocol/openid-connect/auth?"))
    );
    let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT);
    assert_eq!(q["redirect_uri"], "https://vpn.example.com/auth/callback");
    assert_eq!(q["scope"], "openid profile email");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"].len(), 43);
    assert_eq!(q["state"].len(), 43);
    assert_eq!(q["nonce"].len(), 43);
    assert_ne!(q["state"], q["nonce"]);
}

#[tokio::test]
async fn callback_rejects_wrong_state_and_is_single_use() {
    let h = harness().await;
    with_discovery(&h).await;
    let (cookie, url) = start_login(&h).await;
    let state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();

    let resp = callback(&h, &cookie, "code=abc&state=wrong").await;
    assert_eq!(
        location(&resp),
        "https://vpn.example.com/?login_error=invalid"
    );
    // the pending login was consumed by the failed attempt
    let resp = callback(&h, &cookie, &format!("code=abc&state={state}")).await;
    assert_eq!(
        location(&resp),
        "https://vpn.example.com/?login_error=invalid"
    );
}

#[tokio::test]
async fn callback_maps_idp_errors_and_unreachable_token_endpoint() {
    let h = harness().await;
    with_discovery(&h).await;

    let (cookie, _) = start_login(&h).await;
    let resp = callback(&h, &cookie, "error=access_denied&state=x").await;
    assert_eq!(
        location(&resp),
        "https://vpn.example.com/?login_error=denied"
    );
    let clear = resp.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(clear.starts_with("__Host-vpncp_login=;") && clear.contains("Max-Age=0"));

    let (cookie, url) = start_login(&h).await;
    let state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    // mix-up defence: a foreign `iss` is rejected before the code is redeemed
    let resp = callback(
        &h,
        &cookie,
        &format!("code=abc&state={state}&iss=https%3A%2F%2Fevil.example.com"),
    )
    .await;
    assert_eq!(
        location(&resp),
        "https://vpn.example.com/?login_error=invalid"
    );

    let (cookie, url) = start_login(&h).await;
    let state: String = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let resp = callback(&h, &cookie, &format!("code=abc&state={state}")).await;
    assert_eq!(
        location(&resp),
        "https://vpn.example.com/?login_error=unavailable"
    );
}

#[tokio::test]
async fn logout_returns_end_session_url() {
    let h = harness().await;
    with_discovery(&h).await;
    let cookie = h
        .state
        .sessions
        .create(crate::auth::session::SessionData {
            sub: "u".into(),
            username: "u".into(),
            email: None,
            roles: vec!["vpn-admin".into()],
            id_token: Some(crate::secret::Secret::new("id.token.value".into())),
        })
        .unwrap();
    let csrf = h
        .state
        .sessions
        .get(&cookie)
        .unwrap()
        .csrf_token
        .expose()
        .clone();
    let peer: SocketAddr = "192.0.2.50:5000".parse().unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/auth/logout")
        .extension(ConnectInfo(peer))
        .header(header::COOKIE, format!("__Host-vpncp_session={cookie}"))
        .header("x-csrf-token", csrf)
        .header(header::ORIGIN, "https://vpn.example.com")
        .body(Body::empty())
        .unwrap();
    let resp = super::router(h.state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json(resp).await;
    let url = url::Url::parse(body["logout_url"].as_str().unwrap()).unwrap();
    assert!(
        url.as_str()
            .starts_with(&format!("{ISSUER}/protocol/openid-connect/logout?"))
    );
    let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(q["id_token_hint"], "id.token.value");
    assert_eq!(q["post_logout_redirect_uri"], "https://vpn.example.com/");
    assert_eq!(q["client_id"], CLIENT);
}

#[tokio::test]
async fn start_and_stop_validate_the_request_body() {
    let h = harness().await;
    let token = bearer(&test_keys::access_claims());
    for uri in ["/api/ingress/start", "/api/ingress/stop"] {
        // Rejected: a non-JSON content type, an unknown field, malformed JSON, a non-object.
        for (ct, body) in [
            (Some("text/plain"), "hello"),
            (None, "{}"),
            (Some("application/json"), r#"{"foo":1}"#),
            (Some("application/json"), "{"),
            (Some("application/json"), "[]"),
        ] {
            let resp = h
                .call_with_body(Method::POST, uri, Some(&token), None, ct, body)
                .await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{uri} {ct:?} {body}"
            );
            assert_eq!(json(resp).await["error"], "bad_request");
        }
        // Accepted: an empty body (with any content type) and an empty JSON object.
        for (ct, body) in [
            (None, ""),
            (Some("text/plain"), ""),
            (Some("application/json"), "{}"),
            (Some("application/json; charset=utf-8"), " { } "),
        ] {
            let resp = h
                .call_with_body(Method::POST, uri, Some(&token), None, ct, body)
                .await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED, "{uri} {ct:?} {body}");
        }
    }
}

#[tokio::test]
async fn start_checks_authentication_before_the_body() {
    let h = harness().await;
    let resp = h
        .call_with_body(
            Method::POST,
            "/api/ingress/start",
            None,
            None,
            Some("text/plain"),
            "hello",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rotate_rejects_a_non_object_body() {
    let h = harness().await;
    let token = bearer(&test_keys::access_claims());
    let resp = h
        .call_with_body(
            Method::POST,
            "/api/ingress/rotate",
            Some(&token),
            None,
            Some("application/json"),
            r#"["sequence form"]"#,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(resp).await["error"], "bad_request");
}
