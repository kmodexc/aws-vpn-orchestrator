//! Configuration: everything comes from environment variables (loaded by docker compose from
//! `.env`). Every value is validated at startup. Error messages name the variable but never
//! contain its value.

use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rcgen::PublicKeyData;

use crate::secret::Secret;
use crate::util::{sha256, x25519_public};

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration: {var}: {reason}")]
pub struct ConfigError {
    pub var: &'static str,
    pub reason: String,
}

fn err(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError {
        var,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Lightsail,
    Ec2,
    Fake,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lightsail => "lightsail",
            Self::Ec2 => "ec2",
            Self::Fake => "fake",
        }
    }
}

#[derive(Debug)]
pub struct OidcConfig {
    /// Issuer URL without trailing slash; must equal the `iss` claim exactly.
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Secret<String>,
    /// Role for full access (admin).
    pub required_role: String,
    /// Role that may only sign in and read the subscription.
    pub user_role: String,
    pub allowed_clients: Vec<String>,
    pub scopes: String,
}

#[derive(Debug)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    /// Required for AWS providers.
    pub aws_region: Option<String>,
    /// Lightsail instance name or EC2 instance id. Required for AWS providers.
    pub instance: Option<String>,
}

#[derive(Debug)]
pub struct ProxyConfig {
    pub reality_sni: String,
    pub hy2_sni: String,
    pub vless_port: u16,
    pub hy2_port: u16,
    pub ss_port: u16,
    pub vless_uuid: Secret<String>,
    pub reality_private_key: Secret<String>,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub hy2_password: Secret<String>,
    /// The certificate PEM text (public).
    pub hy2_cert_pem: String,
    /// Lowercase hex SHA-256 of the certificate DER, used for `pinSHA256`.
    pub hy2_cert_sha256_hex: String,
    pub hy2_key_pem: Secret<String>,
    pub ss_password: Secret<String>,
    /// Defaults for the runtime protocol settings (`/api/settings` overrides them).
    pub hy2_enabled: bool,
    pub hy2_obfs: bool,
    pub ss_enabled: bool,
}

#[derive(Debug)]
pub struct WireGuardPeer {
    pub vps_host: String,
    pub vps_port: u16,
    pub vps_public_key: String,
    pub ingress_private_key: Secret<String>,
    pub ingress_public_key: String,
}

#[derive(Debug)]
pub struct WireGuardConfig {
    pub enabled: bool,
    pub ingress_address: String,
    pub mtu: u16,
    /// Present if and only if `enabled`.
    pub peer: Option<WireGuardPeer>,
}

/// The validated configuration. `Debug` is safe to print: every secret is wrapped in [`Secret`].
#[derive(Debug)]
pub struct Config {
    pub domain: String,
    /// `https://<host>[:port]`, no trailing slash, normalized to the browser `Origin` form.
    pub public_base_url: String,
    pub bind_addr: SocketAddr,
    pub log_format: LogFormat,
    pub trust_proxy_headers: bool,
    pub state_dir: PathBuf,
    pub static_dir: PathBuf,
    pub oidc: OidcConfig,
    pub session_idle_timeout: Duration,
    pub session_absolute_timeout: Duration,
    pub provider: ProviderConfig,
    pub rotate_cooldown: Duration,
    pub sub_token: Secret<String>,
    pub ingress_token: Secret<String>,
    pub profile_name: String,
    pub sub_update_hours: u32,
    pub proxy: ProxyConfig,
    pub wireguard: WireGuardConfig,
}

struct Env<F> {
    get: F,
}

impl<F: Fn(&str) -> Option<String>> Env<F> {
    fn opt(&self, var: &'static str) -> Option<String> {
        (self.get)(var)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn req(&self, var: &'static str) -> Result<String, ConfigError> {
        self.opt(var)
            .ok_or_else(|| err(var, "is required but missing or empty"))
    }

    fn or(&self, var: &'static str, default: &str) -> String {
        self.opt(var).unwrap_or_else(|| default.to_string())
    }

    fn num<T>(&self, var: &'static str, default: T, min: T, max: T) -> Result<T, ConfigError>
    where
        T: FromStr + PartialOrd + Display + Copy,
    {
        let Some(raw) = self.opt(var) else {
            return Ok(default);
        };
        let value: T = raw
            .parse()
            .map_err(|_| err(var, format!("must be an integer between {min} and {max}")))?;
        if value < min || value > max {
            return Err(err(var, format!("must be between {min} and {max}")));
        }
        Ok(value)
    }

    fn boolean(&self, var: &'static str, default: bool) -> Result<bool, ConfigError> {
        let Some(raw) = self.opt(var) else {
            return Ok(default);
        };
        match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(err(var, "must be true or false")),
        }
    }
}

impl Config {
    /// Load from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Load from an explicit list of key/value pairs (used by tests and tooling).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Self::from_lookup(|k| map.get(k).cloned())
    }

    pub fn from_lookup<F: Fn(&str) -> Option<String>>(get: F) -> Result<Self, ConfigError> {
        let env = Env { get };

        let domain = env.req("DOMAIN")?.to_ascii_lowercase();
        if !is_hostname(&domain) {
            return Err(err("DOMAIN", "must be a valid DNS host name"));
        }
        let public_base_url = parse_public_base_url(&env.req("PUBLIC_BASE_URL")?, &domain)?;

        let bind_addr: SocketAddr = env
            .or("BIND_ADDR", DEFAULT_BIND_ADDR)
            .parse()
            .map_err(|_| err("BIND_ADDR", "must be an ip:port socket address"))?;
        let log_format = match env.or("LOG_FORMAT", "json").to_ascii_lowercase().as_str() {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            _ => return Err(err("LOG_FORMAT", "must be json or pretty")),
        };
        let trust_proxy_headers = env.boolean("TRUST_PROXY_HEADERS", false)?;
        let state_dir = PathBuf::from(env.or("STATE_DIR", "/data"));
        let static_dir = PathBuf::from(env.or("STATIC_DIR", "/app/static"));

        let oidc = parse_oidc(&env)?;

        let session_idle_timeout =
            Duration::from_secs(env.num("SESSION_IDLE_TIMEOUT_S", 1800u64, 60, 7 * 86_400)?);
        let session_absolute_timeout = Duration::from_secs(env.num(
            "SESSION_ABSOLUTE_TIMEOUT_S",
            43_200u64,
            60,
            30 * 86_400,
        )?);
        if session_absolute_timeout < session_idle_timeout {
            return Err(err(
                "SESSION_ABSOLUTE_TIMEOUT_S",
                "must be greater than or equal to SESSION_IDLE_TIMEOUT_S",
            ));
        }

        let provider = parse_provider(&env)?;
        let rotate_cooldown =
            Duration::from_secs(env.num("ROTATE_COOLDOWN_S", 120u64, 0, 86_400)?);

        let sub_token = parse_path_token(&env, "SUB_TOKEN")?;
        let ingress_token = parse_path_token(&env, "INGRESS_TOKEN")?;
        if sub_token == ingress_token {
            return Err(err("INGRESS_TOKEN", "must differ from SUB_TOKEN"));
        }

        let profile_name = env.or("PROFILE_NAME", "travel");
        if profile_name.is_empty()
            || profile_name.len() > 32
            || !profile_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(err("PROFILE_NAME", "must match [A-Za-z0-9_-]{1,32}"));
        }
        let sub_update_hours = env.num("SUB_UPDATE_HOURS", 1u32, 1, 168)?;

        let proxy = parse_proxy(&env)?;
        let wireguard = parse_wireguard(&env)?;

        Ok(Self {
            domain,
            public_base_url,
            bind_addr,
            log_format,
            trust_proxy_headers,
            state_dir,
            static_dir,
            oidc,
            session_idle_timeout,
            session_absolute_timeout,
            provider,
            rotate_cooldown,
            sub_token: Secret::new(sub_token),
            ingress_token: Secret::new(ingress_token),
            profile_name,
            sub_update_hours,
            proxy,
            wireguard,
        })
    }

    /// `<PUBLIC_BASE_URL>/auth/callback`
    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/callback", self.public_base_url)
    }
}

fn parse_public_base_url(raw: &str, domain: &str) -> Result<String, ConfigError> {
    const VAR: &str = "PUBLIC_BASE_URL";
    if raw.ends_with('/') {
        return Err(err(VAR, "must not end with a slash"));
    }
    let url = url::Url::parse(raw).map_err(|_| err(VAR, "must be an absolute https URL"))?;
    if url.scheme() != "https" {
        return Err(err(VAR, "must use https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(err(VAR, "must not contain credentials"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(err(
            VAR,
            "must be only scheme and host (no path, query or fragment)",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| err(VAR, "must contain a host"))?;
    if !host.eq_ignore_ascii_case(domain) {
        return Err(err(VAR, "host must equal DOMAIN"));
    }
    // The ASCII serialization of the origin is exactly what browsers send in `Origin`.
    Ok(url.origin().ascii_serialization())
}

fn parse_https_url(var: &'static str, raw: &str) -> Result<url::Url, ConfigError> {
    let url = url::Url::parse(raw).map_err(|_| err(var, "must be an absolute https URL"))?;
    if url.scheme() != "https" {
        return Err(err(var, "must use https"));
    }
    if url.host_str().is_none() {
        return Err(err(var, "must contain a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(err(var, "must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(err(var, "must not contain a query or fragment"));
    }
    Ok(url)
}

fn is_visible_ascii(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_graphic())
}

fn parse_oidc<F: Fn(&str) -> Option<String>>(env: &Env<F>) -> Result<OidcConfig, ConfigError> {
    let raw_issuer = env.req("OIDC_ISSUER_URL")?;
    let issuer_url = raw_issuer.trim_end_matches('/').to_string();
    parse_https_url("OIDC_ISSUER_URL", &issuer_url)?;

    let client_id = env.req("OIDC_CLIENT_ID")?;
    if client_id.len() > 255 || !is_visible_ascii(&client_id) || client_id.contains(',') {
        return Err(err(
            "OIDC_CLIENT_ID",
            "must be visible ASCII without commas, at most 255 characters",
        ));
    }
    let client_secret = env.req("OIDC_CLIENT_SECRET")?;
    if client_secret.len() > 1024 || !is_visible_ascii(&client_secret) {
        return Err(err(
            "OIDC_CLIENT_SECRET",
            "must be visible ASCII, at most 1024 characters",
        ));
    }
    let required_role = env.or("OIDC_REQUIRED_ROLE", "vpn-admin");
    let user_role = env.or("OIDC_USER_ROLE", "vpn-user");
    if user_role.len() > 255 || user_role.chars().any(char::is_control) {
        return Err(err("OIDC_USER_ROLE", "must be a short name"));
    }
    if user_role == required_role {
        return Err(err("OIDC_USER_ROLE", "must differ from OIDC_REQUIRED_ROLE"));
    }
    if required_role.len() > 255 || required_role.chars().any(char::is_control) {
        return Err(err(
            "OIDC_REQUIRED_ROLE",
            "must be at most 255 characters without control characters",
        ));
    }
    let allowed_clients: Vec<String> = match env.opt("OIDC_ALLOWED_CLIENTS") {
        None => vec![client_id.clone()],
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    };
    if allowed_clients.is_empty()
        || allowed_clients
            .iter()
            .any(|c| c.len() > 255 || !is_visible_ascii(c))
    {
        return Err(err(
            "OIDC_ALLOWED_CLIENTS",
            "must be a comma separated list of client ids",
        ));
    }
    let scopes = env.or("OIDC_SCOPES", "openid profile email");
    let scope_list: Vec<&str> = scopes.split_whitespace().collect();
    if !scope_list.contains(&"openid")
        || scope_list
            .iter()
            .any(|s| !is_visible_ascii(s) || s.contains('"') || s.contains('\\'))
    {
        return Err(err(
            "OIDC_SCOPES",
            "must be a space separated scope list that contains openid",
        ));
    }
    Ok(OidcConfig {
        issuer_url,
        client_id,
        client_secret: Secret::new(client_secret),
        required_role,
        user_role,
        allowed_clients,
        scopes: scope_list.join(" "),
    })
}

fn parse_provider<F: Fn(&str) -> Option<String>>(
    env: &Env<F>,
) -> Result<ProviderConfig, ConfigError> {
    let kind = match env
        .or("PROVIDER", "lightsail")
        .to_ascii_lowercase()
        .as_str()
    {
        "lightsail" => ProviderKind::Lightsail,
        "ec2" => ProviderKind::Ec2,
        "fake" => ProviderKind::Fake,
        _ => return Err(err("PROVIDER", "must be lightsail, ec2 or fake")),
    };
    if kind == ProviderKind::Fake {
        return Ok(ProviderConfig {
            kind,
            aws_region: env.opt("AWS_REGION"),
            instance: env.opt("INGRESS_INSTANCE"),
        });
    }
    let region = env.req("AWS_REGION")?;
    if region.len() > 32
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(err("AWS_REGION", "must look like eu-central-1"));
    }
    // The AWS SDK reads these itself (default credential chain); we only check presence.
    env.req("AWS_ACCESS_KEY_ID")?;
    env.req("AWS_SECRET_ACCESS_KEY")?;
    let instance = env.req("INGRESS_INSTANCE")?;
    if instance.len() > 255 || !is_visible_ascii(&instance) {
        return Err(err(
            "INGRESS_INSTANCE",
            "must be visible ASCII, at most 255 characters",
        ));
    }
    if kind == ProviderKind::Ec2
        && !(instance.starts_with("i-")
            && instance[2..].bytes().all(|b| b.is_ascii_hexdigit())
            && instance.len() > 2)
    {
        return Err(err(
            "INGRESS_INSTANCE",
            "must be an EC2 instance id (i-...) for PROVIDER=ec2",
        ));
    }
    Ok(ProviderConfig {
        kind,
        aws_region: Some(region),
        instance: Some(instance),
    })
}

fn parse_path_token<F: Fn(&str) -> Option<String>>(
    env: &Env<F>,
    var: &'static str,
) -> Result<String, ConfigError> {
    let token = env.req(var)?;
    if token.len() < 32 || token.len() > 256 {
        return Err(err(var, "must be between 32 and 256 characters long"));
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(err(var, "must only contain [A-Za-z0-9_-]"));
    }
    Ok(token)
}

fn decode_32(var: &'static str, raw: &str, url_safe: bool) -> Result<[u8; 32], ConfigError> {
    let bytes = if url_safe {
        URL_SAFE_NO_PAD.decode(raw)
    } else {
        STANDARD.decode(raw)
    }
    .map_err(|_| {
        err(
            var,
            if url_safe {
                "must be base64url without padding"
            } else {
                "must be standard base64"
            },
        )
    })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| err(var, "must decode to exactly 32 bytes"))
}

fn parse_proxy<F: Fn(&str) -> Option<String>>(env: &Env<F>) -> Result<ProxyConfig, ConfigError> {
    let reality_sni = env
        .or("REALITY_SNI", "www.microsoft.com")
        .to_ascii_lowercase();
    if !is_hostname(&reality_sni) {
        return Err(err("REALITY_SNI", "must be a valid DNS host name"));
    }
    let hy2_sni = env.or("HY2_SNI", "www.bing.com").to_ascii_lowercase();
    if !is_hostname(&hy2_sni) {
        return Err(err("HY2_SNI", "must be a valid DNS host name"));
    }
    let vless_port = env.num("VLESS_PORT", 443u16, 1, 65_535)?;
    let hy2_port = env.num("HY2_PORT", 443u16, 1, 65_535)?;
    let ss_port = env.num("SS_PORT", 8443u16, 1, 65_535)?;
    if ss_port == vless_port {
        // VLESS and Shadowsocks both listen on TCP; Hysteria2 is UDP and may share a port.
        return Err(err("SS_PORT", "must differ from VLESS_PORT (both use TCP)"));
    }

    let vless_uuid = uuid::Uuid::parse_str(&env.req("VLESS_UUID")?)
        .map_err(|_| err("VLESS_UUID", "must be a UUID"))?
        .hyphenated()
        .to_string();

    let reality_private_key = env.req("REALITY_PRIVATE_KEY")?;
    let private = decode_32("REALITY_PRIVATE_KEY", &reality_private_key, true)?;
    let reality_public_key = env.req("REALITY_PUBLIC_KEY")?;
    let public = decode_32("REALITY_PUBLIC_KEY", &reality_public_key, true)?;
    if x25519_public(private) != public {
        return Err(err(
            "REALITY_PUBLIC_KEY",
            "does not match REALITY_PRIVATE_KEY",
        ));
    }

    let reality_short_id = env.req("REALITY_SHORT_ID")?.to_ascii_lowercase();
    if reality_short_id.len() != 16 || !reality_short_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err("REALITY_SHORT_ID", "must be exactly 16 hex characters"));
    }

    let hy2_password = env.req("HY2_PASSWORD")?;
    if hy2_password.chars().count() < 16
        || hy2_password.len() > 256
        || hy2_password.chars().any(char::is_control)
    {
        return Err(err(
            "HY2_PASSWORD",
            "must be 16 to 256 characters without control characters",
        ));
    }

    let (hy2_cert_pem, cert_der) = parse_cert_pem(&env.req("HY2_CERT_PEM_B64")?)?;
    let hy2_key_pem = parse_key_pem(&env.req("HY2_KEY_PEM_B64")?, &cert_der)?;
    let hy2_cert_sha256_hex = hex::encode(sha256(&cert_der));

    let ss_password = env.req("SS_PASSWORD")?;
    let ss_bytes = STANDARD
        .decode(&ss_password)
        .map_err(|_| err("SS_PASSWORD", "must be standard base64"))?;
    if ss_bytes.len() != 16 {
        return Err(err("SS_PASSWORD", "must decode to exactly 16 bytes"));
    }
    let hy2_enabled = env.boolean("HY2_ENABLED", true)?;
    let hy2_obfs = env.boolean("HY2_OBFS", false)?;
    let ss_enabled = env.boolean("SS_ENABLED", true)?;

    Ok(ProxyConfig {
        reality_sni,
        hy2_sni,
        vless_port,
        hy2_port,
        ss_port,
        vless_uuid: Secret::new(vless_uuid),
        reality_private_key: Secret::new(reality_private_key),
        reality_public_key,
        reality_short_id,
        hy2_password: Secret::new(hy2_password),
        hy2_cert_pem,
        hy2_cert_sha256_hex,
        hy2_key_pem: Secret::new(hy2_key_pem),
        ss_password: Secret::new(ss_password),
        hy2_enabled,
        hy2_obfs,
        ss_enabled,
    })
}

fn decode_pem_b64(var: &'static str, raw: &str) -> Result<String, ConfigError> {
    let bytes = STANDARD
        .decode(raw)
        .map_err(|_| err(var, "must be standard base64 of a PEM file"))?;
    String::from_utf8(bytes).map_err(|_| err(var, "must be standard base64 of a PEM file"))
}

/// Returns the normalized PEM text and the certificate DER.
fn parse_cert_pem(raw: &str) -> Result<(String, Vec<u8>), ConfigError> {
    const VAR: &str = "HY2_CERT_PEM_B64";
    let text = decode_pem_b64(VAR, raw)?;
    let blocks = pem::parse_many(text.as_bytes()).map_err(|_| err(VAR, "is not valid PEM"))?;
    let [block] = blocks.as_slice() else {
        return Err(err(VAR, "must contain exactly one PEM block"));
    };
    if block.tag() != "CERTIFICATE" {
        return Err(err(VAR, "must contain a CERTIFICATE"));
    }
    let der = block.contents().to_vec();
    if spki_public_key_bits(&der).is_none() {
        return Err(err(VAR, "is not a parsable X.509 certificate"));
    }
    Ok((pem::encode(block), der))
}

fn parse_key_pem(raw: &str, cert_der: &[u8]) -> Result<String, ConfigError> {
    const VAR: &str = "HY2_KEY_PEM_B64";
    let text = decode_pem_b64(VAR, raw)?;
    let blocks = pem::parse_many(text.as_bytes()).map_err(|_| err(VAR, "is not valid PEM"))?;
    let [block] = blocks.as_slice() else {
        return Err(err(VAR, "must contain exactly one PEM block"));
    };
    if block.tag() != "PRIVATE KEY" {
        return Err(err(VAR, "must be a PKCS#8 PEM private key (PRIVATE KEY)"));
    }
    let normalized = pem::encode(block);
    let key = rcgen::KeyPair::from_pem(&normalized)
        .map_err(|_| err(VAR, "is not a supported private key (use ECDSA P-256)"))?;
    let cert_key = spki_public_key_bits(cert_der);
    if cert_key != Some(key.der_bytes()) {
        return Err(err(VAR, "does not match HY2_CERT_PEM_B64"));
    }
    Ok(normalized)
}

/// One DER TLV: tag, content and the bytes that follow it.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

/// Read one DER TLV (definite lengths only, at most 4 length bytes).
fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, mut after_len) = after_tag.split_first()?;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || after_len.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &after_len[..n] {
            len = (len << 8) | usize::from(b);
        }
        after_len = &after_len[n..];
        len
    };
    if after_len.len() < len {
        return None;
    }
    let (content, rest) = after_len.split_at(len);
    Some(Tlv { tag, content, rest })
}

/// Extract the subjectPublicKey bit string (without the unused-bits byte) from a certificate.
fn spki_public_key_bits(cert_der: &[u8]) -> Option<&[u8]> {
    const SEQ: u8 = 0x30;
    const BIT_STRING: u8 = 0x03;
    let cert = der_tlv(cert_der)?;
    if cert.tag != SEQ {
        return None;
    }
    let tbs = der_tlv(cert.content)?;
    if tbs.tag != SEQ {
        return None;
    }
    let mut rest = tbs.content;
    // Optional explicit [0] version.
    if rest.first() == Some(&0xa0) {
        rest = der_tlv(rest)?.rest;
    }
    // serial, signature algorithm, issuer, validity, subject
    for _ in 0..5 {
        rest = der_tlv(rest)?.rest;
    }
    let spki = der_tlv(rest)?;
    if spki.tag != SEQ {
        return None;
    }
    let algorithm = der_tlv(spki.content)?;
    let bits = der_tlv(algorithm.rest)?;
    if bits.tag != BIT_STRING {
        return None;
    }
    let (&unused, key) = bits.content.split_first()?;
    if unused != 0 {
        return None;
    }
    Some(key)
}

fn parse_wireguard<F: Fn(&str) -> Option<String>>(
    env: &Env<F>,
) -> Result<WireGuardConfig, ConfigError> {
    let enabled = env.boolean("WG_ENABLED", false)?;
    let raw_ingress_address = env.or("WG_INGRESS_ADDRESS", "10.66.0.2/32");
    let (ingress_ip, ingress_prefix) = parse_cidr(&raw_ingress_address)
        .ok_or_else(|| err("WG_INGRESS_ADDRESS", "must be an address/prefix (CIDR)"))?;
    // Store the canonical form, never the raw input: sing-box (Go netip)
    // is stricter than Rust's parsers, so only re-serialised values are
    // forwarded into its config.
    let ingress_address = format!("{ingress_ip}/{ingress_prefix}");
    let mtu = env.num("WG_MTU", 1380u16, 1280, 9000)?;
    let peer = if enabled {
        let endpoint = env.req("WG_VPS_ENDPOINT")?;
        let (vps_host, vps_port) =
            parse_endpoint(&endpoint).ok_or_else(|| err("WG_VPS_ENDPOINT", "must be host:port"))?;
        let vps_public_key = env.req("WG_VPS_PUBLIC_KEY")?;
        decode_32("WG_VPS_PUBLIC_KEY", &vps_public_key, false)?;
        let ingress_private_key = env.req("WG_INGRESS_PRIVATE_KEY")?;
        let private = decode_32("WG_INGRESS_PRIVATE_KEY", &ingress_private_key, false)?;
        let ingress_public_key = STANDARD.encode(x25519_public(private));
        Some(WireGuardPeer {
            vps_host,
            vps_port,
            vps_public_key,
            ingress_private_key: Secret::new(ingress_private_key),
            ingress_public_key,
        })
    } else {
        None
    };
    Ok(WireGuardConfig {
        enabled,
        ingress_address,
        mtu,
        peer,
    })
}

/// Parse `address/prefix`. The prefix must be plain decimal without sign or
/// leading zeros (`^(0|[1-9][0-9]{0,2})$`), matching Go's `netip.ParsePrefix`
/// which sing-box uses; `u8::from_str` alone would accept `+32` and `032`.
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let canonical_digits = !prefix.is_empty()
        && prefix.len() <= 3
        && prefix.bytes().all(|b| b.is_ascii_digit())
        && (prefix == "0" || !prefix.starts_with('0'));
    if !canonical_digits {
        return None;
    }
    let prefix: u8 = prefix.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((ip, prefix))
}

/// Parse `host:port` or `[ipv6]:port`.
fn parse_endpoint(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        let _: std::net::Ipv6Addr = h.parse().ok()?;
        (h.to_string(), p)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        if h.parse::<std::net::Ipv4Addr>().is_err() && !is_hostname(h) {
            return None;
        }
        (h.to_string(), p)
    };
    let port: u16 = port.parse().ok()?;
    (port != 0).then_some((host, port))
}

/// RFC 1123 host name (letters, digits, hyphens, dots).
pub fn is_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cli::gen_env;

    /// A complete, valid configuration for tests (fresh secrets from `gen-env`).
    pub(crate) fn valid_pairs() -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = gen_env::generate_secrets()
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        for (k, v) in [
            ("DOMAIN", "vpn.example.com"),
            ("PUBLIC_BASE_URL", "https://vpn.example.com"),
            ("OIDC_ISSUER_URL", "https://auth.kmode.dev/realms/test"),
            ("OIDC_CLIENT_ID", "vpn-control"),
            ("OIDC_CLIENT_SECRET", "client-secret-value"),
            ("PROVIDER", "fake"),
        ] {
            pairs.push((k.to_string(), v.to_string()));
        }
        pairs
    }

    fn with(overrides: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let mut map: HashMap<String, String> = valid_pairs().into_iter().collect();
        for (k, v) in overrides {
            if v.is_empty() {
                map.remove(*k);
            } else {
                map.insert((*k).to_string(), (*v).to_string());
            }
        }
        Config::from_pairs(map)
    }

    fn error_var(overrides: &[(&str, &str)]) -> &'static str {
        match with(overrides) {
            Ok(_) => "<ok>",
            Err(e) => e.var,
        }
    }

    #[test]
    fn valid_config_loads_with_defaults() {
        let c = with(&[]).unwrap();
        assert_eq!(c.public_base_url, "https://vpn.example.com");
        assert_eq!(c.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(c.oidc.allowed_clients, vec!["vpn-control".to_string()]);
        assert_eq!(c.oidc.required_role, "vpn-admin");
        assert_eq!(c.oidc.user_role, "vpn-user");
        assert_eq!(c.proxy.ss_port, 8443);
        assert_eq!(c.profile_name, "travel");
        assert!(!c.wireguard.enabled);
        assert!(c.wireguard.peer.is_none());
        assert_eq!(c.proxy.hy2_cert_sha256_hex.len(), 64);
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let pairs = valid_pairs();
        let c = Config::from_pairs(pairs.clone()).unwrap();
        let debug = format!("{c:?}");
        for (k, v) in &pairs {
            let secret_vars = [
                "SUB_TOKEN",
                "INGRESS_TOKEN",
                "VLESS_UUID",
                "REALITY_PRIVATE_KEY",
                "HY2_PASSWORD",
                "HY2_KEY_PEM_B64",
                "SS_PASSWORD",
                "WG_INGRESS_PRIVATE_KEY",
                "OIDC_CLIENT_SECRET",
            ];
            if secret_vars.contains(&k.as_str()) {
                assert!(!debug.contains(v.as_str()), "{k} leaked in Debug output");
            }
        }
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn missing_required_values_are_rejected() {
        for var in [
            "DOMAIN",
            "PUBLIC_BASE_URL",
            "OIDC_ISSUER_URL",
            "OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET",
            "SUB_TOKEN",
            "INGRESS_TOKEN",
            "VLESS_UUID",
            "REALITY_PRIVATE_KEY",
            "REALITY_PUBLIC_KEY",
            "REALITY_SHORT_ID",
            "HY2_PASSWORD",
            "HY2_CERT_PEM_B64",
            "HY2_KEY_PEM_B64",
            "SS_PASSWORD",
        ] {
            assert_eq!(error_var(&[(var, "")]), var, "{var}");
        }
    }

    #[test]
    fn error_message_never_contains_the_value() {
        let secret = "short-but-secret";
        let e = with(&[("SUB_TOKEN", secret)]).unwrap_err();
        assert_eq!(e.var, "SUB_TOKEN");
        assert!(!e.to_string().contains(secret));
    }

    #[test]
    fn tokens_are_validated() {
        assert_eq!(error_var(&[("SUB_TOKEN", "tooshort")]), "SUB_TOKEN");
        assert_eq!(
            error_var(&[("SUB_TOKEN", "abcdefghijklmnopqrstuvwxyz012345/+")]),
            "SUB_TOKEN"
        );
        assert_eq!(
            error_var(&[("INGRESS_TOKEN", "abcdefghijklmnopqrstuvwxyz0123456789")]),
            "<ok>"
        );
        let same = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            error_var(&[("SUB_TOKEN", same), ("INGRESS_TOKEN", same)]),
            "INGRESS_TOKEN"
        );
    }

    #[test]
    fn reality_keypair_must_match() {
        let other = gen_env::generate_secrets().unwrap();
        let other_pub = other
            .iter()
            .find(|(k, _)| *k == "REALITY_PUBLIC_KEY")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(
            error_var(&[("REALITY_PUBLIC_KEY", &other_pub)]),
            "REALITY_PUBLIC_KEY"
        );
        assert_eq!(
            error_var(&[("REALITY_PRIVATE_KEY", "not-base64!")]),
            "REALITY_PRIVATE_KEY"
        );
    }

    #[test]
    fn hy2_key_must_match_cert() {
        let other = gen_env::generate_secrets().unwrap();
        let other_key = other
            .iter()
            .find(|(k, _)| *k == "HY2_KEY_PEM_B64")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(
            error_var(&[("HY2_KEY_PEM_B64", &other_key)]),
            "HY2_KEY_PEM_B64"
        );
        assert_eq!(
            error_var(&[("HY2_CERT_PEM_B64", "bm90IGEgcGVt")]),
            "HY2_CERT_PEM_B64"
        );
    }

    #[test]
    fn public_base_url_is_validated() {
        for bad in [
            "http://vpn.example.com",
            "https://vpn.example.com/",
            "https://vpn.example.com/app",
            "https://other.example.com",
            "https://user:pw@vpn.example.com",
            "https://vpn.example.com?x=1",
            "vpn.example.com",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                error_var(&[("PUBLIC_BASE_URL", bad)]),
                "PUBLIC_BASE_URL",
                "{bad}"
            );
        }
        let c = with(&[("PUBLIC_BASE_URL", "https://VPN.example.com")]).unwrap();
        assert_eq!(c.public_base_url, "https://vpn.example.com");
        let c = with(&[("PUBLIC_BASE_URL", "https://vpn.example.com:8443")]).unwrap();
        assert_eq!(c.public_base_url, "https://vpn.example.com:8443");
    }

    #[test]
    fn issuer_must_be_https() {
        assert_eq!(
            error_var(&[("OIDC_ISSUER_URL", "http://auth.kmode.dev/realms/x")]),
            "OIDC_ISSUER_URL"
        );
        let c = with(&[("OIDC_ISSUER_URL", "https://auth.kmode.dev/realms/x/")]).unwrap();
        assert_eq!(c.oidc.issuer_url, "https://auth.kmode.dev/realms/x");
        assert_eq!(
            error_var(&[("OIDC_SCOPES", "profile email")]),
            "OIDC_SCOPES"
        );
    }

    #[test]
    fn misc_values_are_validated() {
        assert_eq!(error_var(&[("PROFILE_NAME", "bad name")]), "PROFILE_NAME");
        assert_eq!(
            error_var(&[("REALITY_SHORT_ID", "abcd")]),
            "REALITY_SHORT_ID"
        );
        assert_eq!(error_var(&[("SS_PASSWORD", "AAAA")]), "SS_PASSWORD");
        assert_eq!(error_var(&[("VLESS_UUID", "nope")]), "VLESS_UUID");
        assert_eq!(error_var(&[("PROVIDER", "azure")]), "PROVIDER");
        assert_eq!(error_var(&[("VLESS_PORT", "0")]), "VLESS_PORT");
        assert_eq!(error_var(&[("LOG_FORMAT", "xml")]), "LOG_FORMAT");
        assert_eq!(
            error_var(&[("TRUST_PROXY_HEADERS", "maybe")]),
            "TRUST_PROXY_HEADERS"
        );
        assert_eq!(
            error_var(&[
                ("SESSION_IDLE_TIMEOUT_S", "3600"),
                ("SESSION_ABSOLUTE_TIMEOUT_S", "600")
            ]),
            "SESSION_ABSOLUTE_TIMEOUT_S"
        );
    }

    #[test]
    fn aws_providers_require_credentials_and_instance() {
        assert_eq!(error_var(&[("PROVIDER", "lightsail")]), "AWS_REGION");
        assert_eq!(
            error_var(&[("PROVIDER", "lightsail"), ("AWS_REGION", "eu-central-1")]),
            "AWS_ACCESS_KEY_ID"
        );
        let full = [
            ("AWS_REGION", "eu-central-1"),
            ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("INGRESS_INSTANCE", "my-instance"),
        ];
        let mut ls = full.to_vec();
        ls.push(("PROVIDER", "lightsail"));
        assert_eq!(error_var(&ls), "<ok>");
        let mut ec2 = full.to_vec();
        ec2.push(("PROVIDER", "ec2"));
        assert_eq!(error_var(&ec2), "INGRESS_INSTANCE");
    }

    #[test]
    fn wireguard_settings() {
        assert_eq!(error_var(&[("WG_ENABLED", "true")]), "WG_VPS_ENDPOINT");
        let pubkey = STANDARD.encode([7u8; 32]);
        let c = with(&[
            ("WG_ENABLED", "true"),
            ("WG_VPS_ENDPOINT", "vps.example.com:51820"),
            ("WG_VPS_PUBLIC_KEY", &pubkey),
        ])
        .unwrap();
        let peer = c.wireguard.peer.unwrap();
        assert_eq!(peer.vps_host, "vps.example.com");
        assert_eq!(peer.vps_port, 51820);
        assert_eq!(peer.ingress_public_key.len(), 44);
        assert_eq!(
            error_var(&[
                ("WG_ENABLED", "true"),
                ("WG_VPS_ENDPOINT", "vps.example.com"),
                ("WG_VPS_PUBLIC_KEY", &pubkey),
            ]),
            "WG_VPS_ENDPOINT"
        );
        assert_eq!(
            parse_endpoint("[2001:db8::1]:51820"),
            Some(("2001:db8::1".to_string(), 51820))
        );
        assert_eq!(
            error_var(&[("WG_INGRESS_ADDRESS", "10.0.0.2")]),
            "WG_INGRESS_ADDRESS"
        );
    }

    #[test]
    fn wireguard_ingress_address_is_strict_and_canonical() {
        for bad in [
            "10.66.0.2/+32",
            "10.66.0.2/032",
            "10.66.0.2/00",
            "10.66.0.2/-0",
            "10.66.0.2/ 32",
            "10.66.0.2/",
            "10.66.0.2/33",
            "10.66.0.2/1000",
            "fd00::2/129",
            "fd00::2/0128",
            "10.66.0.02/32",
            "fe80::1%eth0/64",
        ] {
            assert_eq!(
                error_var(&[("WG_INGRESS_ADDRESS", bad)]),
                "WG_INGRESS_ADDRESS",
                "{bad}"
            );
        }
        assert_eq!(
            parse_cidr("10.66.0.2/0"),
            Some(("10.66.0.2".parse().unwrap(), 0))
        );
        let c = with(&[]).unwrap();
        assert_eq!(c.wireguard.ingress_address, "10.66.0.2/32");
        let c = with(&[("WG_INGRESS_ADDRESS", "FD00:0:0:0::0002/128")]).unwrap();
        assert_eq!(c.wireguard.ingress_address, "fd00::2/128");
        let c = with(&[("WG_INGRESS_ADDRESS", "10.66.0.9/24")]).unwrap();
        assert_eq!(c.wireguard.ingress_address, "10.66.0.9/24");
    }

    #[test]
    fn hostname_validation() {
        assert!(is_hostname("www.microsoft.com"));
        assert!(!is_hostname("-bad.com"));
        assert!(!is_hostname("a..b"));
        assert!(!is_hostname("a b"));
    }
}
