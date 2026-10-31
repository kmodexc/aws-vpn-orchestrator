//! AWS Lightsail provider: rotates the public IPv4 by swapping static IPs.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_lightsail::Client;
use aws_sdk_lightsail::error::DisplayErrorContext;

use super::{IngressProvider, IngressStatus, MANAGED_PREFIX, normalize_state, parse_ipv4};
use crate::util::unix_now_millis;

const MAX_PAGES: usize = 50;
/// Attempts (on top of the SDK's own retries) to read the new address after a successful attach.
const READ_BACK_ATTEMPTS: u32 = 3;
const READ_BACK_DELAY: Duration = Duration::from_secs(2);

/// A static IP attached to the instance.
struct AttachedStaticIp {
    name: String,
    address: Option<Ipv4Addr>,
}

/// The instance's public IPv4 as a fallback for the new static IP's address. An address equal to
/// the old static IP is stale (the attach has not propagated yet) and is not accepted.
fn fresh_instance_ip(instance_ip: Option<Ipv4Addr>, old: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    instance_ip.filter(|ip| Some(*ip) != old)
}

pub struct LightsailProvider {
    client: Client,
    instance: String,
}

impl LightsailProvider {
    pub fn new(sdk: &aws_config::SdkConfig, instance: &str) -> Self {
        Self {
            client: Client::new(sdk),
            instance: instance.to_string(),
        }
    }

    /// The static IP currently attached to the instance, if any.
    async fn attached_static_ip(&self) -> anyhow::Result<Option<AttachedStaticIp>> {
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let out = self
                .client
                .get_static_ips()
                .set_page_token(token.clone())
                .send()
                .await
                .map_err(|e| anyhow!("GetStaticIps failed: {}", DisplayErrorContext(&e)))?;
            if let Some(ip) = out.static_ips().iter().find(|ip| {
                ip.is_attached() == Some(true) && ip.attached_to() == Some(self.instance.as_str())
            }) {
                return Ok(ip.name().map(|name| AttachedStaticIp {
                    name: name.to_string(),
                    address: parse_ipv4(ip.ip_address()),
                }));
            }
            match out.next_page_token() {
                Some(t) if !t.is_empty() => token = Some(t.to_string()),
                _ => return Ok(None),
            }
        }
        Err(anyhow!("GetStaticIps: too many pages"))
    }

    async fn release(&self, name: &str) -> anyhow::Result<()> {
        self.client
            .release_static_ip()
            .static_ip_name(name)
            .send()
            .await
            .map_err(|e| anyhow!("ReleaseStaticIp failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn attach(&self, name: &str) -> anyhow::Result<()> {
        self.client
            .attach_static_ip()
            .static_ip_name(name)
            .instance_name(&self.instance)
            .send()
            .await
            .map_err(|e| anyhow!("AttachStaticIp failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn rollback(&self, new_name: &str, old_name: Option<&str>) {
        if let Err(e) = self.release(new_name).await {
            tracing::error!(error = %e, static_ip = new_name, "rollback: releasing the new static IP failed");
        }
        if let Some(old) = old_name {
            if let Err(e) = self.attach(old).await {
                tracing::error!(error = %e, static_ip = old, "rollback: re-attaching the old static IP failed");
            }
        }
    }

    /// After a successful swap: release the old static IP if this application allocated it,
    /// otherwise leave it. Never fails the rotation; a failure is logged (the IP then stays
    /// allocated, and billed, until it is released by hand).
    async fn release_old(&self, old_name: &str) {
        if !old_name.starts_with(MANAGED_PREFIX) {
            tracing::warn!(static_ip = %old_name, "old static IP is not managed by vpn-orchestrator; leaving it allocated");
            return;
        }
        if let Err(e) = self.release(old_name).await {
            tracing::error!(error = %e, static_ip = %old_name, "releasing the old static IP failed; it stays allocated (and billed) and must be released by hand");
        }
    }

    /// Address of the static IP `name`, if Lightsail reports one.
    async fn static_ip_address(&self, name: &str) -> anyhow::Result<Option<Ipv4Addr>> {
        let out = self
            .client
            .get_static_ip()
            .static_ip_name(name)
            .send()
            .await
            .map_err(|e| anyhow!("GetStaticIp failed: {}", DisplayErrorContext(&e)))?;
        Ok(out.static_ip().and_then(|ip| parse_ipv4(ip.ip_address())))
    }

    /// The instance's current public IPv4, if any.
    async fn instance_public_ip(&self) -> anyhow::Result<Option<Ipv4Addr>> {
        let out = self
            .client
            .get_instance()
            .instance_name(&self.instance)
            .send()
            .await
            .map_err(|e| anyhow!("GetInstance failed: {}", DisplayErrorContext(&e)))?;
        Ok(out
            .instance()
            .and_then(|i| parse_ipv4(i.public_ip_address())))
    }

    /// Determine the new public IPv4 after `new_name` has been attached: the static IP's own
    /// address, else the instance's public IP (unless that is still the old address). Retries a
    /// few times and fails only if no address can be determined at all.
    async fn read_back_new_ip(
        &self,
        new_name: &str,
        old_address: Option<Ipv4Addr>,
    ) -> anyhow::Result<Ipv4Addr> {
        let mut last_error = anyhow!("Lightsail reported no IPv4 address for the new static IP");
        for attempt in 1..=READ_BACK_ATTEMPTS {
            if attempt > 1 {
                tokio::time::sleep(READ_BACK_DELAY).await;
            }
            match self.static_ip_address(new_name).await {
                Ok(Some(ip)) => return Ok(ip),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, attempt, static_ip = %new_name, "reading the new static IP failed; trying the instance");
                    last_error = e;
                }
            }
            match self.instance_public_ip().await {
                Ok(ip) => {
                    if let Some(ip) = fresh_instance_ip(ip, old_address) {
                        return Ok(ip);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, attempt, "reading the instance public IP failed");
                    last_error = e;
                }
            }
        }
        Err(last_error
            .context("the new static IP is attached, but its address could not be determined"))
    }
}

#[async_trait]
impl IngressProvider for LightsailProvider {
    async fn status(&self) -> anyhow::Result<IngressStatus> {
        let out = self
            .client
            .get_instance()
            .instance_name(&self.instance)
            .send()
            .await
            .map_err(|e| anyhow!("GetInstance failed: {}", DisplayErrorContext(&e)))?;
        let instance = out.instance().context("GetInstance returned no instance")?;
        Ok(IngressStatus {
            state: normalize_state(instance.state().and_then(|s| s.name()).unwrap_or("unknown")),
            public_ip: parse_ipv4(instance.public_ip_address()),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        self.client
            .start_instance()
            .instance_name(&self.instance)
            .send()
            .await
            .map_err(|e| anyhow!("StartInstance failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.client
            .stop_instance()
            .instance_name(&self.instance)
            .send()
            .await
            .map_err(|e| anyhow!("StopInstance failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn rotate_ip(&self) -> anyhow::Result<Ipv4Addr> {
        let old = self.attached_static_ip().await?;
        let old_name = old.as_ref().map(|o| o.name.as_str());
        let old_address = old.as_ref().and_then(|o| o.address);
        let new_name = format!("{MANAGED_PREFIX}{}", unix_now_millis());

        self.client
            .allocate_static_ip()
            .static_ip_name(&new_name)
            .send()
            .await
            .map_err(|e| anyhow!("AllocateStaticIp failed: {}", DisplayErrorContext(&e)))?;

        if let Some(old_name) = old_name {
            if let Err(e) = self
                .client
                .detach_static_ip()
                .static_ip_name(old_name)
                .send()
                .await
            {
                let err = anyhow!("DetachStaticIp failed: {}", DisplayErrorContext(&e));
                if let Err(re) = self.release(&new_name).await {
                    tracing::error!(error = %re, static_ip = %new_name, "rollback: releasing the new static IP failed");
                }
                return Err(err);
            }
        }

        if let Err(e) = self.attach(&new_name).await {
            self.rollback(&new_name, old_name).await;
            return Err(e);
        }

        // The swap has happened. Deal with the old static IP before anything else can fail:
        // later rotations only look at the IP attached to the instance, so an old IP left
        // detached here would stay allocated (and billed) forever.
        if let Some(old_name) = old_name {
            self.release_old(old_name).await;
        }

        self.read_back_new_ip(&new_name, old_address).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_instance_ip_is_not_accepted() {
        let old = Some(Ipv4Addr::new(203, 0, 113, 1));
        let new = Some(Ipv4Addr::new(203, 0, 113, 2));
        assert_eq!(fresh_instance_ip(new, old), new);
        assert_eq!(fresh_instance_ip(old, old), None);
        assert_eq!(fresh_instance_ip(None, old), None);
        assert_eq!(fresh_instance_ip(new, None), new);
    }
}
