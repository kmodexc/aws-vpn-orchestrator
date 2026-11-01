//! OIDC client for Keycloak: lazy discovery + JWKS caching, authorization URL, code exchange
//! and token validation.
//!
//! Nothing here runs at startup: if the IdP is unreachable, requests fail with `unavailable`
//! and the next request retries. JWKS is re-fetched on an unknown `kid`, at most once per 60 s.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use super::jwt::{self, AccessClaims, IdClaims, JwtError};
use crate::config::Config;
use crate::secret::Secret;

const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Minimum time between two fetch attempts (unknown-kid refreshes and retries after failure).
const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// The IdP could not be reached or answered with a server error.
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
    /// A token or IdP response was invalid.
    #[error("rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Tokens returned by the token endpoint.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: Secret<String>,
    pub id_token: Secret<String>,
}

#[derive(Debug)]
struct Cached<T> {
    value: Option<Arc<T>>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

impl<T> Default for Cached<T> {
    fn default() -> Self {
        Self {
            value: None,
            fetched_at: None,
            last_attempt: None,
        }
    }
}

impl<T> Cached<T> {
    fn fresh(&self, ttl: Duration) -> Option<Arc<T>> {
        match (&self.value, self.fetched_at) {
            (Some(v), Some(at)) if at.elapsed() < ttl => Some(Arc::clone(v)),
            _ => None,
        }
    }

    fn attempted_recently(&self) -> bool {
        self.last_attempt
            .is_some_and(|t| t.elapsed() < MIN_REFETCH_INTERVAL)
    }
}

pub struct OidcClient {
    http: reqwest::Client,
    issuer: String,
    client_id: String,
    client_secret: Secret<String>,
    scopes: String,
    redirect_uri: String,
    allowed_clients: Vec<String>,
    discovery: RwLock<Cached<Discovery>>,
    discovery_fetch: Mutex<()>,
    jwks: RwLock<Cached<JwkSet>>,
    jwks_fetch: Mutex<()>,
}

impl OidcClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("console/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            issuer: cfg.oidc.issuer_url.clone(),
            client_id: cfg.oidc.client_id.clone(),
            client_secret: cfg.oidc.client_secret.clone(),
            scopes: cfg.oidc.scopes.clone(),
            redirect_uri: cfg.redirect_uri(),
            allowed_clients: cfg.oidc.allowed_clients.clone(),
            discovery: RwLock::new(Cached::default()),
            discovery_fetch: Mutex::new(()),
            jwks: RwLock::new(Cached::default()),
            jwks_fetch: Mutex::new(()),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    async fn read_limited(mut resp: reqwest::Response) -> Result<Vec<u8>, OidcError> {
        if resp
            .content_length()
            .is_some_and(|l| l > MAX_RESPONSE_BYTES as u64)
        {
            return Err(OidcError::Rejected("response too large".into()));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| OidcError::Unavailable(format!("reading response: {e}")))?
        {
            if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(OidcError::Rejected("response too large".into()));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }

    async fn get_json_bytes(&self, url: &str) -> Result<Vec<u8>, OidcError> {
        let resp = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("GET {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(OidcError::Unavailable(format!("GET {url}: HTTP {status}")));
        }
        Self::read_limited(resp).await
    }

    async fn fetch_discovery(&self) -> Result<Discovery, OidcError> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let bytes = self.get_json_bytes(&url).await?;
        let d: Discovery = serde_json::from_slice(&bytes)
            .map_err(|e| OidcError::Unavailable(format!("discovery document: {e}")))?;
        if d.issuer != self.issuer {
            return Err(OidcError::Unavailable(
                "discovery issuer does not match OIDC_ISSUER_URL".into(),
            ));
        }
        for (name, endpoint) in [
            ("authorization_endpoint", Some(&d.authorization_endpoint)),
            ("token_endpoint", Some(&d.token_endpoint)),
            ("jwks_uri", Some(&d.jwks_uri)),
            ("end_session_endpoint", d.end_session_endpoint.as_ref()),
        ] {
            if let Some(ep) = endpoint {
                let ok = url::Url::parse(ep).is_ok_and(|u| u.scheme() == "https");
                if !ok {
                    return Err(OidcError::Unavailable(format!(
                        "discovery {name} is not an https URL"
                    )));
                }
            }
        }
        Ok(d)
    }

    /// The discovery document (cached for an hour; a stale copy is served while the IdP is down).
    pub async fn discovery(&self) -> Result<Arc<Discovery>, OidcError> {
        if let Some(d) = self.discovery.read().await.fresh(DISCOVERY_TTL) {
            return Ok(d);
        }
        let _fetching = self.discovery_fetch.lock().await;
        {
            let cache = self.discovery.read().await;
            if let Some(d) = cache.fresh(DISCOVERY_TTL) {
                return Ok(d);
            }
            if cache.attempted_recently() {
                if let Some(stale) = &cache.value {
                    return Ok(Arc::clone(stale));
                }
            }
        }
        let result = self.fetch_discovery().await;
        let mut cache = self.discovery.write().await;
        cache.last_attempt = Some(Instant::now());
        match result {
            Ok(d) => {
                let d = Arc::new(d);
                cache.value = Some(Arc::clone(&d));
                cache.fetched_at = Some(Instant::now());
                Ok(d)
            }
            Err(e) => match &cache.value {
                Some(stale) => {
                    tracing::warn!(error = %e, "OIDC discovery refresh failed; using cached copy");
                    Ok(Arc::clone(stale))
                }
                None => Err(e),
            },
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, OidcError> {
        let d = self.discovery().await?;
        let bytes = self.get_json_bytes(&d.jwks_uri).await?;
        jwt::parse_jwks(&bytes).map_err(|e| OidcError::Unavailable(format!("JWKS document: {e}")))
    }

    /// The JWKS. With `force_refresh` (unknown `kid`), re-fetch unless a fetch was attempted
    /// in the last 60 s.
    async fn jwks(&self, force_refresh: bool) -> Result<Arc<JwkSet>, OidcError> {
        if !force_refresh {
            if let Some(k) = self.jwks.read().await.fresh(JWKS_TTL) {
                return Ok(k);
            }
        }
        let _fetching = self.jwks_fetch.lock().await;
        {
            let cache = self.jwks.read().await;
            if !force_refresh {
                if let Some(k) = cache.fresh(JWKS_TTL) {
                    return Ok(k);
                }
            }
            if cache.attempted_recently() {
                return cache.value.clone().ok_or_else(|| {
                    OidcError::Unavailable("JWKS unavailable (retrying later)".into())
                });
            }
        }
        let result = self.fetch_jwks().await;
        let mut cache = self.jwks.write().await;
        cache.last_attempt = Some(Instant::now());
        match result {
            Ok(k) => {
                let k = Arc::new(k);
                cache.value = Some(Arc::clone(&k));
                cache.fetched_at = Some(Instant::now());
                Ok(k)
            }
            Err(e) => match &cache.value {
                Some(stale) => {
                    tracing::warn!(error = %e, "JWKS refresh failed; using cached copy");
                    Ok(Arc::clone(stale))
                }
                None => Err(e),
            },
        }
    }

    /// Test-only: preload the JWKS cache so validation needs no network. Compiled out of
    /// non-test builds.
    #[cfg(test)]
    pub(crate) async fn inject_jwks_for_tests(&self, keys: JwkSet) {
        let mut cache = self.jwks.write().await;
        cache.value = Some(Arc::new(keys));
        cache.fetched_at = Some(Instant::now());
        cache.last_attempt = Some(Instant::now());
    }

    /// Test-only: preload the discovery cache. Compiled out of non-test builds.
    #[cfg(test)]
    pub(crate) async fn inject_discovery_for_tests(&self, discovery: Discovery) {
        let mut cache = self.discovery.write().await;
        cache.value = Some(Arc::new(discovery));
        cache.fetched_at = Some(Instant::now());
        cache.last_attempt = Some(Instant::now());
    }

    /// Run a validation against the JWKS, refreshing it once on an unknown `kid`.
    async fn with_jwks<T>(
        &self,
        validate: impl Fn(&JwkSet) -> Result<T, JwtError>,
    ) -> Result<T, OidcError> {
        let keys = self.jwks(false).await?;
        match validate(&keys) {
            Err(JwtError::UnknownKey) => {
                let refreshed = self.jwks(true).await?;
                if Arc::ptr_eq(&keys, &refreshed) {
                    return Err(OidcError::Rejected(JwtError::UnknownKey.to_string()));
                }
                validate(&refreshed).map_err(|e| OidcError::Rejected(e.to_string()))
            }
            other => other.map_err(|e| OidcError::Rejected(e.to_string())),
        }
    }

    /// Validate a Bearer access token from an API client (azp ∈ OIDC_ALLOWED_CLIENTS).
    pub async fn validate_bearer(&self, token: &str) -> Result<AccessClaims, OidcError> {
        jwt::precheck(token).map_err(|e| OidcError::Rejected(e.to_string()))?;
        self.with_jwks(|keys| {
            jwt::validate_access_token(token, keys, &self.issuer, &self.allowed_clients)
        })
        .await
    }

    /// Validate the tokens of our own code exchange (access token azp must be our client).
    pub async fn validate_login_tokens(
        &self,
        tokens: &TokenResponse,
        expected_nonce: &str,
    ) -> Result<(IdClaims, AccessClaims), OidcError> {
        let id = self
            .with_jwks(|keys| {
                jwt::validate_id_token(
                    tokens.id_token.expose(),
                    keys,
                    &self.issuer,
                    &self.client_id,
                    expected_nonce,
                )
            })
            .await?;
        let own_client = [self.client_id.clone()];
        let access = self
            .with_jwks(|keys| {
                jwt::validate_access_token(
                    tokens.access_token.expose(),
                    keys,
                    &self.issuer,
                    &own_client,
                )
            })
            .await?;
        if access.sub.as_deref().is_some_and(|s| s != id.sub) {
            return Err(OidcError::Rejected(
                "access token subject differs from ID token".into(),
            ));
        }
        Ok((id, access))
    }

    /// Build the authorization request URL (code flow, PKCE S256, state, nonce).
    pub async fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        pkce_challenge: &str,
    ) -> Result<String, OidcError> {
        let d = self.discovery().await?;
        let mut url = url::Url::parse(&d.authorization_endpoint)
            .map_err(|e| OidcError::Unavailable(format!("authorization_endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Exchange the authorization code (confidential client, client_secret_post, PKCE verifier).
    /// Redirects are never followed.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<TokenResponse, OidcError> {
        #[derive(Deserialize)]
        struct Raw {
            access_token: String,
            #[serde(default)]
            id_token: Option<String>,
            token_type: String,
        }
        #[derive(Deserialize)]
        struct RawError {
            #[serde(default)]
            error: Option<String>,
        }

        let d = self.discovery().await?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("code_verifier", pkce_verifier)
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", self.client_secret.expose())
            .finish();
        let resp = self
            .http
            .post(&d.token_endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(format!("token endpoint: {e}")))?;
        let status = resp.status();
        let bytes = Self::read_limited(resp).await?;
        if status.is_server_error() {
            return Err(OidcError::Unavailable(format!(
                "token endpoint: HTTP {status}"
            )));
        }
        if !status.is_success() {
            let code = serde_json::from_slice::<RawError>(&bytes)
                .ok()
                .and_then(|e| e.error)
                .map(|e| crate::util::sanitize_text(&e, 64))
                .unwrap_or_default();
            return Err(OidcError::Rejected(format!(
                "token endpoint: HTTP {status} {code}"
            )));
        }
        let raw: Raw = serde_json::from_slice(&bytes)
            .map_err(|_| OidcError::Rejected("token response is not valid JSON".into()))?;
        if !raw.token_type.eq_ignore_ascii_case("bearer") {
            return Err(OidcError::Rejected("unexpected token_type".into()));
        }
        let id_token = raw
            .id_token
            .ok_or_else(|| OidcError::Rejected("token response has no id_token".into()))?;
        Ok(TokenResponse {
            access_token: Secret::new(raw.access_token),
            id_token: Secret::new(id_token),
        })
    }

    /// RP-initiated logout URL, or `None` if the IdP has no end-session endpoint or is down.
    pub async fn logout_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: &str,
    ) -> Option<String> {
        let d = match self.discovery().await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "OIDC discovery failed during logout");
                return None;
            }
        };
        let mut url = url::Url::parse(d.end_session_endpoint.as_deref()?).ok()?;
        {
            let mut q = url.query_pairs_mut();
            if let Some(hint) = id_token_hint {
                q.append_pair("id_token_hint", hint);
            }
            q.append_pair("post_logout_redirect_uri", post_logout_redirect_uri)
                .append_pair("client_id", &self.client_id);
        }
        Some(url.into())
    }
}
