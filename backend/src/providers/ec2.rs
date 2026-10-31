//! AWS EC2 provider: rotates the public IPv4 by associating a fresh Elastic IP.

use std::net::Ipv4Addr;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_ec2::Client;
use aws_sdk_ec2::error::DisplayErrorContext;
use aws_sdk_ec2::types::{DomainType, Filter, ResourceType, Tag, TagSpecification};

use super::{
    IngressProvider, IngressStatus, MANAGED_TAG_KEY, MANAGED_TAG_VALUE, normalize_state, parse_ipv4,
};

pub struct Ec2Provider {
    client: Client,
    instance_id: String,
}

struct ExistingAddress {
    allocation_id: String,
    managed: bool,
}

impl Ec2Provider {
    pub fn new(sdk: &aws_config::SdkConfig, instance_id: &str) -> Self {
        Self {
            client: Client::new(sdk),
            instance_id: instance_id.to_string(),
        }
    }

    async fn associated_addresses(&self) -> anyhow::Result<Vec<ExistingAddress>> {
        let out = self
            .client
            .describe_addresses()
            .filters(
                Filter::builder()
                    .name("instance-id")
                    .values(&self.instance_id)
                    .build(),
            )
            .send()
            .await
            .map_err(|e| anyhow!("DescribeAddresses failed: {}", DisplayErrorContext(&e)))?;
        Ok(out
            .addresses()
            .iter()
            .filter_map(|a| {
                let allocation_id = a.allocation_id()?.to_string();
                let managed = a.tags().iter().any(|t| {
                    t.key() == Some(MANAGED_TAG_KEY) && t.value() == Some(MANAGED_TAG_VALUE)
                });
                Some(ExistingAddress {
                    allocation_id,
                    managed,
                })
            })
            .collect())
    }

    async fn release(&self, allocation_id: &str) -> anyhow::Result<()> {
        self.client
            .release_address()
            .allocation_id(allocation_id)
            .send()
            .await
            .map_err(|e| anyhow!("ReleaseAddress failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }
}

#[async_trait]
impl IngressProvider for Ec2Provider {
    async fn status(&self) -> anyhow::Result<IngressStatus> {
        let out = self
            .client
            .describe_instances()
            .instance_ids(&self.instance_id)
            .send()
            .await
            .map_err(|e| anyhow!("DescribeInstances failed: {}", DisplayErrorContext(&e)))?;
        let instance = out
            .reservations()
            .iter()
            .flat_map(|r| r.instances())
            .next()
            .context("DescribeInstances returned no instance")?;
        Ok(IngressStatus {
            state: normalize_state(
                instance
                    .state()
                    .and_then(|s| s.name())
                    .map_or("unknown", |n| n.as_str()),
            ),
            public_ip: parse_ipv4(instance.public_ip_address()),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        self.client
            .start_instances()
            .instance_ids(&self.instance_id)
            .send()
            .await
            .map_err(|e| anyhow!("StartInstances failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.client
            .stop_instances()
            .instance_ids(&self.instance_id)
            .send()
            .await
            .map_err(|e| anyhow!("StopInstances failed: {}", DisplayErrorContext(&e)))?;
        Ok(())
    }

    async fn rotate_ip(&self) -> anyhow::Result<Ipv4Addr> {
        let previous = self.associated_addresses().await?;

        let alloc = self
            .client
            .allocate_address()
            .domain(DomainType::Vpc)
            .tag_specifications(
                TagSpecification::builder()
                    .resource_type(ResourceType::ElasticIp)
                    .tags(
                        Tag::builder()
                            .key(MANAGED_TAG_KEY)
                            .value(MANAGED_TAG_VALUE)
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
            .map_err(|e| anyhow!("AllocateAddress failed: {}", DisplayErrorContext(&e)))?;
        let allocation_id = alloc
            .allocation_id()
            .context("AllocateAddress returned no allocation id")?
            .to_string();
        let Some(new_ip) = parse_ipv4(alloc.public_ip()) else {
            if let Err(e) = self.release(&allocation_id).await {
                tracing::error!(error = %e, %allocation_id, "rollback: releasing the new address failed");
            }
            return Err(anyhow!("AllocateAddress returned no IPv4 address"));
        };

        if let Err(e) = self
            .client
            .associate_address()
            .instance_id(&self.instance_id)
            .allocation_id(&allocation_id)
            .allow_reassociation(true)
            .send()
            .await
        {
            let err = anyhow!("AssociateAddress failed: {}", DisplayErrorContext(&e));
            if let Err(re) = self.release(&allocation_id).await {
                tracing::error!(error = %re, %allocation_id, "rollback: releasing the new address failed");
            }
            return Err(err);
        }

        for old in previous {
            if old.allocation_id == allocation_id {
                continue;
            }
            if old.managed {
                if let Err(e) = self.release(&old.allocation_id).await {
                    tracing::error!(error = %e, allocation_id = %old.allocation_id, "releasing the old address failed");
                }
            } else {
                tracing::warn!(allocation_id = %old.allocation_id, "old address is not tagged vpn-orchestrator=managed; leaving it allocated");
            }
        }
        Ok(new_ip)
    }
}
