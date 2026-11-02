//! Ingress providers (SPEC §6). AWS errors are returned with full detail; callers log them and
//! surface `unavailable` to clients.

pub mod ec2;
pub mod fake;
pub mod lightsail;
pub mod provisioning;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::config::{Config, ProviderConfig, ProviderKind};

/// Prefix for resources this application allocates and may therefore release.
pub const MANAGED_PREFIX: &str = "vpn-orchestrator-";
pub const MANAGED_TAG_KEY: &str = "vpn-orchestrator";
pub const MANAGED_TAG_VALUE: &str = "managed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressStatus {
    /// running | stopped | pending | stopping | starting | … (lowercase, provider specific)
    pub state: String,
    /// Public IPv4 only; IPv6 is never published.
    pub public_ip: Option<Ipv4Addr>,
}

#[async_trait]
pub trait IngressProvider: Send + Sync {
    async fn status(&self) -> anyhow::Result<IngressStatus>;
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self) -> anyhow::Result<()>;
    /// Swap the public IPv4 address. Returns the new address.
    async fn rotate_ip(&self) -> anyhow::Result<Ipv4Addr>;
}

/// Normalize a provider state name: lowercase, `[a-z0-9_-]` only, bounded length.
pub fn normalize_state(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

pub fn parse_ipv4(raw: Option<&str>) -> Option<Ipv4Addr> {
    raw.and_then(|s| s.parse::<Ipv4Addr>().ok())
}

/// Shared AWS SDK configuration: explicit region, bounded timeouts, standard retries. The
/// credentials come from the default chain (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).
async fn aws_sdk_config(region: &str) -> aws_config::SdkConfig {
    let timeouts = aws_config::timeout::TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(5))
        .operation_attempt_timeout(Duration::from_secs(20))
        .operation_timeout(Duration::from_secs(45))
        .build();
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .timeout_config(timeouts)
        .load()
        .await
}

/// Build the provider selected by `PROVIDER`.
pub async fn build(cfg: &Config) -> anyhow::Result<Arc<dyn IngressProvider>> {
    build_one(&cfg.provider).await
}

async fn build_one(p: &ProviderConfig) -> anyhow::Result<Arc<dyn IngressProvider>> {
    match p.kind {
        ProviderKind::Fake => {
            tracing::warn!(
                "!!! PROVIDER=fake: no AWS calls are made; this mode is for local development and tests only !!!"
            );
            Ok(Arc::new(fake::FakeProvider::new()))
        }
        ProviderKind::Lightsail | ProviderKind::Ec2 => {
            let (Some(region), Some(instance)) = (p.aws_region.as_deref(), p.instance.as_deref())
            else {
                anyhow::bail!("AWS_REGION and INGRESS_INSTANCE are required");
            };
            let sdk = aws_sdk_config(region).await;
            if p.kind == ProviderKind::Lightsail {
                Ok(Arc::new(lightsail::LightsailProvider::new(&sdk, instance)))
            } else {
                Ok(Arc::new(ec2::Ec2Provider::new(&sdk, instance)))
            }
        }
    }
}

/// Build all configured targets. Each AWS SDK client is pinned to the target's region; this is
/// what lets the control plane switch between already-provisioned regions without restarting.
pub async fn build_all(
    cfg: &Config,
) -> anyhow::Result<HashMap<String, Arc<dyn IngressProvider>>> {
    let mut providers = HashMap::with_capacity(cfg.targets.len());
    for target in &cfg.targets {
        let provider = build_one(&target.provider).await?;
        providers.insert(target.id.clone(), provider);
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_normalization() {
        assert_eq!(normalize_state("Running"), "running");
        assert_eq!(normalize_state("shutting-down"), "shutting-down");
        assert_eq!(normalize_state("<script>"), "script");
        assert_eq!(normalize_state(""), "unknown");
    }

    #[test]
    fn ipv6_is_not_parsed_as_public_ip() {
        assert_eq!(parse_ipv4(Some("2001:db8::1")), None);
        assert_eq!(
            parse_ipv4(Some("203.0.113.1")),
            Some(Ipv4Addr::new(203, 0, 113, 1))
        );
    }
}
