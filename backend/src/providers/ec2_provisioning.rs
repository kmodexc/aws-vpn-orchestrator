//! EC2 on-demand reconciliation. Only tagged deployment resources are mutated.
use super::bootstrap::user_data;
use crate::{
    config::Config,
    lifecycle::{Deployment, DeploymentResources, Ec2LaunchSpec, Provisioner},
    providers::{IngressStatus, parse_ipv4},
    util::sha256,
};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_ec2::{
    Client,
    types::{self, Filter, ResourceType, Tag, TagSpecification},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{collections::HashMap, sync::Arc, time::Duration};
const OWNER: &str = "vpn-orchestrator";
const DEPLOYMENT: &str = "vpn-deployment";

#[derive(Clone, Debug)]
struct Instance {
    id: String,
    state: String,
    ip: Option<std::net::Ipv4Addr>,
    volumes: Vec<String>,
    managed: bool,
    deployment: Option<String>,
}
#[derive(Clone, Debug)]
struct Volume {
    id: String,
    state: String,
    attached: bool,
    managed: bool,
    deployment: Option<String>,
}
#[derive(Clone, Debug)]
struct Address {
    id: String,
    association: Option<String>,
    managed: bool,
    deployment: Option<String>,
}
#[async_trait]
trait Ec2Api: Send + Sync {
    async fn instances(
        &self,
        region: &str,
        deployment: &str,
        known: Option<&str>,
    ) -> anyhow::Result<Vec<Instance>>;
    async fn launch(
        &self,
        region: &str,
        deployment: &str,
        spec: &Ec2LaunchSpec,
        data: &str,
        ports: &[(i32, &'static str)],
    ) -> anyhow::Result<()>;
    async fn terminate(&self, region: &str, ids: Vec<String>) -> anyhow::Result<()>;
    async fn volumes(
        &self,
        region: &str,
        deployment: &str,
        known: &[String],
    ) -> anyhow::Result<Vec<Volume>>;
    async fn delete_volume(&self, region: &str, id: &str) -> anyhow::Result<()>;
    async fn addresses(
        &self,
        region: &str,
        deployment: &str,
        known: Option<&str>,
        instance_id: Option<&str>,
    ) -> anyhow::Result<Vec<Address>>;
    async fn release_address(&self, region: &str, address: &Address) -> anyhow::Result<()>;
}
struct AwsEc2 {
    clients: HashMap<String, Client>,
}
impl AwsEc2 {
    fn client(&self, region: &str) -> anyhow::Result<&Client> {
        self.clients.get(region).context("region is not allowed")
    }
    async fn preflight(
        &self,
        region: &str,
        spec: &Ec2LaunchSpec,
        ports: &[(i32, &'static str)],
    ) -> anyhow::Result<String> {
        let client = self.client(region)?;
        let images = client
            .describe_images()
            .image_ids(&spec.ami_id)
            .send()
            .await?;
        let image = images.images().first().context("AMI not found")?;
        anyhow::ensure!(
            image.owner_id() == Some("099720109477")
                && image.state().is_some_and(|s| s.as_str() == "available")
                && image
                    .root_device_type()
                    .is_some_and(|t| t.as_str() == "ebs"),
            "use an available Canonical Ubuntu EBS AMI"
        );
        anyhow::ensure!(
            image
                .name()
                .is_some_and(|n| n.contains("ubuntu-noble-24.04-")),
            "use an Ubuntu 24.04 server AMI"
        );
        anyhow::ensure!(
            image
                .block_device_mappings()
                .iter()
                .filter(|b| b.ebs().is_some())
                .count()
                == 1,
            "AMI must have exactly one EBS root disk"
        );
        anyhow::ensure!(
            image
                .block_device_mappings()
                .iter()
                .filter_map(|b| b.ebs())
                .all(|b| b
                    .volume_size()
                    .is_none_or(|size| size <= spec.root_volume_gib)),
            "root disk is smaller than the AMI minimum"
        );
        let instance_types = client
            .describe_instance_types()
            .instance_types(types::InstanceType::from(spec.instance_type.as_str()))
            .send()
            .await?;
        let info = instance_types
            .instance_types()
            .first()
            .context("instance type not available")?;
        let architecture = image.architecture().context("AMI has no architecture")?;
        anyhow::ensure!(
            info.processor_info().is_some_and(|p| p
                .supported_architectures()
                .iter()
                .any(|a| a.as_str() == architecture.as_str())),
            "AMI and instance type architectures differ"
        );
        let subnet_out = client
            .describe_subnets()
            .subnet_ids(&spec.subnet_id)
            .send()
            .await?;
        let subnet = subnet_out.subnets().first().context("subnet not found")?;
        let vpc = subnet.vpc_id().context("subnet has no VPC")?;
        let groups = client
            .describe_security_groups()
            .set_group_ids(Some(spec.security_group_ids.clone()))
            .send()
            .await?;
        let mut allowed = std::collections::HashSet::new();
        for group in groups.security_groups() {
            anyhow::ensure!(
                group.vpc_id() == Some(vpc),
                "security group and subnet VPCs differ"
            );
            for permission in group.ip_permissions() {
                let protocol = permission.ip_protocol().unwrap_or("");
                let protocol = match protocol {
                    "6" => "tcp",
                    "17" => "udp",
                    other => other,
                };
                let port = permission
                    .from_port()
                    .context("security group allows unbounded ingress")?;
                anyhow::ensure!(
                    permission.to_port() == Some(port)
                        && ports.contains(&(port, protocol))
                        && permission.user_id_group_pairs().is_empty()
                        && permission.prefix_list_ids().is_empty(),
                    "security groups must allow only the configured VPN ports"
                );
                if permission
                    .ip_ranges()
                    .iter()
                    .any(|r| r.cidr_ip() == Some("0.0.0.0/0"))
                {
                    allowed.insert((port, protocol.to_string()));
                }
            }
        }
        anyhow::ensure!(
            ports
                .iter()
                .all(|(p, proto)| allowed.contains(&(*p, proto.to_string()))),
            "security groups do not expose every configured VPN port"
        );
        let specific = client
            .describe_route_tables()
            .filters(
                Filter::builder()
                    .name("association.subnet-id")
                    .values(&spec.subnet_id)
                    .build(),
            )
            .send()
            .await?;
        let routes = if specific.route_tables().is_empty() {
            client
                .describe_route_tables()
                .filters(Filter::builder().name("vpc-id").values(vpc).build())
                .filters(
                    Filter::builder()
                        .name("association.main")
                        .values("true")
                        .build(),
                )
                .send()
                .await?
        } else {
            specific
        };
        anyhow::ensure!(
            routes
                .route_tables()
                .iter()
                .flat_map(|t| t.routes())
                .any(|r| r.destination_cidr_block() == Some("0.0.0.0/0")
                    && r.gateway_id().is_some_and(|id| id.starts_with("igw-"))
                    && r.state().is_some_and(|s| s.as_str() == "active")),
            "subnet needs a direct internet-gateway default route (no NAT gateway)"
        );
        Ok(image
            .root_device_name()
            .context("AMI has no root device name")?
            .into())
    }
}
fn tagged(tags: &[Tag], key: &str) -> Option<String> {
    tags.iter()
        .find(|t| t.key() == Some(key))
        .and_then(|t| t.value())
        .map(str::to_string)
}
fn instance(i: &types::Instance) -> anyhow::Result<Instance> {
    Ok(Instance {
        id: i.instance_id().context("instance has no ID")?.into(),
        state: i
            .state()
            .and_then(|s| s.name())
            .map(|s| s.as_str())
            .unwrap_or("unknown")
            .into(),
        ip: parse_ipv4(i.public_ip_address()),
        volumes: i
            .block_device_mappings()
            .iter()
            .filter_map(|b| b.ebs().and_then(|e| e.volume_id()).map(str::to_string))
            .collect(),
        managed: tagged(i.tags(), OWNER).as_deref() == Some("managed"),
        deployment: tagged(i.tags(), DEPLOYMENT),
    })
}
fn volume(v: &types::Volume) -> anyhow::Result<Volume> {
    Ok(Volume {
        id: v.volume_id().context("volume has no ID")?.into(),
        state: v.state().map(|s| s.as_str()).unwrap_or("unknown").into(),
        attached: !v.attachments().is_empty(),
        managed: tagged(v.tags(), OWNER).as_deref() == Some("managed"),
        deployment: tagged(v.tags(), DEPLOYMENT),
    })
}
fn address(a: &types::Address) -> anyhow::Result<Address> {
    Ok(Address {
        id: a
            .allocation_id()
            .context("address has no allocation ID")?
            .into(),
        association: a.association_id().map(str::to_string),
        managed: tagged(a.tags(), OWNER).as_deref() == Some("managed"),
        deployment: tagged(a.tags(), DEPLOYMENT),
    })
}
#[async_trait]
impl Ec2Api for AwsEc2 {
    async fn instances(
        &self,
        region: &str,
        deployment: &str,
        known: Option<&str>,
    ) -> anyhow::Result<Vec<Instance>> {
        let client = self.client(region)?;
        let mut result = Vec::new();
        let mut token = None;
        loop {
            let out = client
                .describe_instances()
                .filters(
                    Filter::builder()
                        .name(format!("tag:{DEPLOYMENT}"))
                        .values(deployment)
                        .build(),
                )
                .set_next_token(token)
                .send()
                .await?;
            for i in out.reservations().iter().flat_map(|r| r.instances()) {
                result.push(instance(i)?);
            }
            token = out.next_token().map(str::to_string);
            if token.is_none() {
                break;
            }
        }
        if let Some(id) = known.filter(|id| !result.iter().any(|i| i.id == *id)) {
            // A filter returns an empty list for a no-longer-visible terminated instance.
            let out = client
                .describe_instances()
                .filters(Filter::builder().name("instance-id").values(id).build())
                .send()
                .await?;
            for i in out.reservations().iter().flat_map(|r| r.instances()) {
                result.push(instance(i)?);
            }
        }
        Ok(result)
    }
    async fn launch(
        &self,
        region: &str,
        deployment: &str,
        spec: &Ec2LaunchSpec,
        data: &str,
        ports: &[(i32, &'static str)],
    ) -> anyhow::Result<()> {
        let root = self.preflight(region, spec, ports).await?;
        launch_request(self.client(region)?, deployment, spec, data, &root)
            .send()
            .await?;
        Ok(())
    }
    async fn terminate(&self, region: &str, ids: Vec<String>) -> anyhow::Result<()> {
        self.client(region)?
            .terminate_instances()
            .set_instance_ids(Some(ids))
            .send()
            .await?;
        Ok(())
    }
    async fn volumes(
        &self,
        region: &str,
        deployment: &str,
        known: &[String],
    ) -> anyhow::Result<Vec<Volume>> {
        let client = self.client(region)?;
        let mut result = Vec::new();
        let mut token = None;
        loop {
            let out = client
                .describe_volumes()
                .filters(
                    Filter::builder()
                        .name(format!("tag:{DEPLOYMENT}"))
                        .values(deployment)
                        .build(),
                )
                .set_next_token(token)
                .send()
                .await?;
            for v in out.volumes() {
                result.push(volume(v)?);
            }
            token = out.next_token().map(str::to_string);
            if token.is_none() {
                break;
            }
        }
        for id in known
            .iter()
            .filter(|id| !result.iter().any(|v| &v.id == *id))
            .collect::<Vec<_>>()
        {
            let out = client
                .describe_volumes()
                .filters(Filter::builder().name("volume-id").values(id).build())
                .send()
                .await?;
            for v in out.volumes() {
                result.push(volume(v)?);
            }
        }
        Ok(result)
    }
    async fn delete_volume(&self, region: &str, id: &str) -> anyhow::Result<()> {
        self.client(region)?
            .delete_volume()
            .volume_id(id)
            .send()
            .await?;
        Ok(())
    }
    async fn addresses(
        &self,
        region: &str,
        deployment: &str,
        known: Option<&str>,
        instance_id: Option<&str>,
    ) -> anyhow::Result<Vec<Address>> {
        let client = self.client(region)?;
        let out = client
            .describe_addresses()
            .filters(
                Filter::builder()
                    .name(format!("tag:{DEPLOYMENT}"))
                    .values(deployment)
                    .build(),
            )
            .send()
            .await?;
        let mut result = out
            .addresses()
            .iter()
            .map(address)
            .collect::<anyhow::Result<Vec<_>>>()?;
        if let Some(id) = instance_id {
            let out = client
                .describe_addresses()
                .filters(Filter::builder().name("instance-id").values(id).build())
                .send()
                .await?;
            for item in out.addresses() {
                let item = address(item)?;
                if !result.iter().any(|a| a.id == item.id) {
                    result.push(item);
                }
            }
        }
        if let Some(id) = known.filter(|id| !result.iter().any(|a| a.id == *id)) {
            let out = client
                .describe_addresses()
                .filters(Filter::builder().name("allocation-id").values(id).build())
                .send()
                .await?;
            result.extend(
                out.addresses()
                    .iter()
                    .map(address)
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
        }
        Ok(result)
    }
    async fn release_address(&self, region: &str, address: &Address) -> anyhow::Result<()> {
        let client = self.client(region)?;
        // Wait for instance termination to detach it. Never detach an address from a different instance.
        anyhow::ensure!(
            address.association.is_none(),
            "address is still associated; retry after AWS detaches it"
        );
        client
            .release_address()
            .allocation_id(&address.id)
            .send()
            .await?;
        Ok(())
    }
}

fn launch_request(
    client: &Client,
    deployment: &str,
    spec: &Ec2LaunchSpec,
    data: &str,
    root: &str,
) -> aws_sdk_ec2::operation::run_instances::builders::RunInstancesFluentBuilder {
    let tags = vec![
        Tag::builder().key(OWNER).value("managed").build(),
        Tag::builder().key(DEPLOYMENT).value(deployment).build(),
        Tag::builder()
            .key("Name")
            .value(format!("vpn-ondemand-{deployment}"))
            .build(),
    ];
    client
        .run_instances()
        .client_token(format!("vpn-{deployment}"))
        .min_count(1)
        .max_count(1)
        .image_id(&spec.ami_id)
        .instance_type(types::InstanceType::from(spec.instance_type.as_str()))
        .network_interfaces(
            types::InstanceNetworkInterfaceSpecification::builder()
                .device_index(0)
                .subnet_id(&spec.subnet_id)
                .set_groups(Some(spec.security_group_ids.clone()))
                .associate_public_ip_address(true)
                .delete_on_termination(true)
                .build(),
        )
        .block_device_mappings(
            types::BlockDeviceMapping::builder()
                .device_name(root)
                .ebs(
                    types::EbsBlockDevice::builder()
                        .encrypted(true)
                        .delete_on_termination(true)
                        .volume_type(types::VolumeType::Gp3)
                        .volume_size(spec.root_volume_gib)
                        .build(),
                )
                .build(),
        )
        .metadata_options(
            types::InstanceMetadataOptionsRequest::builder()
                .http_tokens(types::HttpTokensState::Required)
                .http_put_response_hop_limit(1)
                .build(),
        )
        .credit_specification(
            types::CreditSpecificationRequest::builder()
                .cpu_credits("standard")
                .build(),
        )
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Instance)
                .set_tags(Some(tags.clone()))
                .build(),
        )
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Volume)
                .set_tags(Some(tags))
                .build(),
        )
        .user_data(STANDARD.encode(data))
}

pub struct Ec2Provisioner {
    api: Arc<dyn Ec2Api>,
    config: Arc<Config>,
}
impl Ec2Provisioner {
    pub async fn new(config: Arc<Config>) -> Self {
        let mut clients = HashMap::new();
        for region in &config.lifecycle.regions {
            let sdk = super::aws_sdk_config(region).await;
            clients.insert(region.clone(), Client::new(&sdk));
        }
        Self {
            api: Arc::new(AwsEc2 { clients }),
            config,
        }
    }
    fn check(d: &Deployment, managed: bool, deployment: Option<&str>) -> anyhow::Result<()> {
        anyhow::ensure!(
            d.managed && managed && deployment == Some(d.id.as_str()),
            "resource ownership does not match deployment"
        );
        Ok(())
    }
    fn inventory(d: &Deployment) -> anyhow::Result<(Option<&str>, &[String], Option<&str>)> {
        match &d.resources {
            DeploymentResources::Ec2 {
                instance_id,
                volume_ids,
                allocation_id,
                ..
            } => Ok((instance_id.as_deref(), volume_ids, allocation_id.as_deref())),
            _ => anyhow::bail!("EC2 provisioner cannot manage Lightsail resources"),
        }
    }
    async fn instances(&self, d: &Deployment) -> anyhow::Result<Vec<Instance>> {
        let (known, _, _) = Self::inventory(d)?;
        let instances = self.api.instances(&d.region, &d.id, known).await?;
        for i in &instances {
            Self::check(d, i.managed, i.deployment.as_deref())?;
        }
        Ok(instances)
    }
    fn ports(&self) -> Vec<(i32, &'static str)> {
        vec![
            (self.config.proxy.vless_port.into(), "tcp"),
            (self.config.proxy.hy2_port.into(), "udp"),
            (self.config.proxy.ss_port.into(), "tcp"),
            (self.config.proxy.ss_port.into(), "udp"),
        ]
    }
}
#[async_trait]
impl Provisioner for Ec2Provisioner {
    fn provider(&self) -> &'static str {
        "ec2"
    }
    fn plan(&self, region: &str, id: &str) -> anyhow::Result<Deployment> {
        let region_cfg = self
            .config
            .lifecycle
            .ec2
            .regions
            .get(region)
            .context("missing EC2 region settings")?;
        let mut d = Deployment {
            id: id.into(),
            region: region.into(),
            public_ip: None,
            managed: true,
            resources: DeploymentResources::Ec2 {
                instance_id: None,
                volume_ids: vec![],
                allocation_id: None,
                association_id: None,
                launch: None,
            },
        };
        let hash = hex::encode(sha256(user_data(&self.config, &d)?.as_bytes()));
        if let DeploymentResources::Ec2 { launch, .. } = &mut d.resources {
            *launch = Some(Ec2LaunchSpec {
                ami_id: region_cfg.ami_id.clone(),
                subnet_id: region_cfg.subnet_id.clone(),
                security_group_ids: region_cfg.security_group_ids.clone(),
                instance_type: self.config.lifecycle.ec2.instance_type.clone(),
                root_volume_gib: self.config.lifecycle.ec2.root_volume_gib,
                user_data_sha256: hash,
            });
        }
        Ok(d)
    }
    async fn ensure(&self, d: &Deployment) -> anyhow::Result<Deployment> {
        let spec = match &d.resources {
            DeploymentResources::Ec2 {
                launch: Some(spec), ..
            } => spec,
            _ => anyhow::bail!("EC2 launch parameters missing"),
        };
        let data = user_data(&self.config, d)?;
        anyhow::ensure!(
            hex::encode(sha256(data.as_bytes())) == spec.user_data_sha256,
            "bootstrap settings changed during provisioning; candidate must be cleaned before retrying"
        );
        let instances = self.instances(d).await?;
        // A terminated deployment is never relaunched with the same token.
        anyhow::ensure!(
            instances.len() <= 1,
            "multiple instances match this deployment; cleanup required"
        );
        let Some(i) = instances.first() else {
            self.api
                .launch(&d.region, &d.id, spec, &data, &self.ports())
                .await?;
            return Err(anyhow!("EC2 launch requested; waiting for visibility"));
        };
        anyhow::ensure!(i.state == "running", "EC2 instance is not running");
        let mut result = d.clone();
        result.public_ip = Some(i.ip.context("EC2 public IP not assigned yet")?);
        if let DeploymentResources::Ec2 {
            instance_id,
            volume_ids,
            ..
        } = &mut result.resources
        {
            *instance_id = Some(i.id.clone());
            *volume_ids = i.volumes.clone();
        }
        Ok(result)
    }
    async fn discover(&self, d: &Deployment) -> anyhow::Result<Deployment> {
        // Adoption is limited to explicitly managed instances with a deployment tag.
        let (known, _, _) = Self::inventory(d)?;
        let items = self.api.instances(&d.region, &d.id, known).await?;
        let i = items.first().context("existing EC2 instance not found")?;
        anyhow::ensure!(
            items.len() == 1 && i.managed && known == Some(i.id.as_str()),
            "existing instance is not uniquely managed"
        );
        let id = i
            .deployment
            .as_ref()
            .context("EC2 adoption requires a vpn-deployment tag")?;
        anyhow::ensure!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid existing deployment ID"
        );
        let mut result = d.clone();
        result.id = id.clone();
        result.public_ip = i.ip;
        let addresses = self.api.addresses(&d.region, id, None, Some(&i.id)).await?;
        anyhow::ensure!(
            addresses.len() <= 1,
            "multiple reserved IPs require explicit cleanup"
        );
        for a in &addresses {
            Self::check(&result, a.managed, a.deployment.as_deref())?;
        }
        if let DeploymentResources::Ec2 {
            allocation_id,
            association_id,
            ..
        } = &mut result.resources
        {
            if let Some(a) = addresses.first() {
                *allocation_id = Some(a.id.clone());
                *association_id = a.association.clone();
            }
        }
        if let DeploymentResources::Ec2 {
            instance_id,
            volume_ids,
            ..
        } = &mut result.resources
        {
            *instance_id = Some(i.id.clone());
            *volume_ids = i.volumes.clone();
        }
        Ok(result)
    }
    async fn destroy(&self, d: &Deployment) -> anyhow::Result<()> {
        let (_, known_volumes, known_address) = Self::inventory(d)?;
        let instances = self.instances(d).await?;
        let mut ids = Vec::new();
        let mut volumes = known_volumes.to_vec();
        for i in &instances {
            for a in self
                .api
                .addresses(&d.region, &d.id, known_address, Some(&i.id))
                .await?
            {
                Self::check(d, a.managed, a.deployment.as_deref())?;
            }
            volumes.extend(i.volumes.clone());
            if !matches!(i.state.as_str(), "terminated" | "shutting-down") {
                ids.push(i.id.clone());
            }
        }
        if !ids.is_empty() {
            self.api.terminate(&d.region, ids).await?;
        }
        for _ in 0..60 {
            if self
                .instances(d)
                .await?
                .iter()
                .all(|i| i.state == "terminated")
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        anyhow::ensure!(
            self.instances(d)
                .await?
                .iter()
                .all(|i| i.state == "terminated"),
            "EC2 termination pending; resource inventory retained"
        );
        let remaining = self.api.volumes(&d.region, &d.id, &volumes).await?;
        for v in remaining {
            Self::check(d, v.managed, v.deployment.as_deref())?;
            anyhow::ensure!(
                !v.attached,
                "managed volume is still attached; refusing deletion"
            );
            if v.state != "deleting" {
                self.api.delete_volume(&d.region, &v.id).await?;
            }
        }
        for _ in 0..30 {
            if self
                .api
                .volumes(&d.region, &d.id, &volumes)
                .await?
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        anyhow::ensure!(
            self.api
                .volumes(&d.region, &d.id, &volumes)
                .await?
                .is_empty(),
            "volume deletion pending; resource inventory retained"
        );
        for a in self
            .api
            .addresses(&d.region, &d.id, known_address, None)
            .await?
        {
            Self::check(d, a.managed, a.deployment.as_deref())?;
            self.api.release_address(&d.region, &a).await?;
        }
        anyhow::ensure!(
            self.api
                .addresses(&d.region, &d.id, known_address, None)
                .await?
                .is_empty(),
            "address release pending; resource inventory retained"
        );
        Ok(())
    }
    async fn status(&self, d: &Deployment) -> anyhow::Result<IngressStatus> {
        let items = self.instances(d).await?;
        anyhow::ensure!(items.len() <= 1, "multiple instances match deployment");
        Ok(match items.first().filter(|i| i.state != "terminated") {
            Some(i) => IngressStatus {
                state: i.state.clone(),
                public_ip: if i.state == "running" { i.ip } else { None },
            },
            None => IngressStatus {
                state: "absent".into(),
                public_ip: None,
            },
        })
    }
    async fn reachable(&self, d: &Deployment) -> anyhow::Result<bool> {
        let ip = d.public_ip.context("candidate has no public IP")?;
        Ok(tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect((ip, self.config.proxy.vless_port)),
        )
        .await
        .is_ok_and(|r| r.is_ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct State {
        instances: Vec<Instance>,
        volumes: Vec<Volume>,
        addresses: Vec<Address>,
        launches: Vec<(String, Ec2LaunchSpec, String)>,
        objects_created: usize,
        hide_reads: usize,
        lose_response: bool,
        pending_termination: bool,
        terminated: Vec<String>,
        deleted_volumes: Vec<String>,
        released: Vec<String>,
    }
    #[derive(Default)]
    struct Mock {
        state: Mutex<State>,
    }
    #[async_trait]
    impl Ec2Api for Mock {
        async fn instances(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> anyhow::Result<Vec<Instance>> {
            let mut s = self.state.lock().unwrap();
            if s.hide_reads > 0 {
                s.hide_reads -= 1;
                return Ok(vec![]);
            }
            Ok(s.instances.clone())
        }
        async fn launch(
            &self,
            _: &str,
            id: &str,
            spec: &Ec2LaunchSpec,
            data: &str,
            _: &[(i32, &'static str)],
        ) -> anyhow::Result<()> {
            let mut s = self.state.lock().unwrap();
            if let Some((previous, frozen, bootstrap)) = s.launches.first() {
                anyhow::ensure!(
                    previous == id && frozen == spec && bootstrap == data,
                    "client token parameter mismatch"
                );
            } else {
                s.objects_created += 1;
                s.instances.push(Instance {
                    id: "i-12345678901234567".into(),
                    state: "running".into(),
                    ip: Some("203.0.113.1".parse().unwrap()),
                    volumes: vec!["vol-root".into()],
                    managed: true,
                    deployment: Some(id.into()),
                });
            }
            s.launches.push((id.into(), spec.clone(), data.into()));
            anyhow::ensure!(!s.lose_response, "response lost after AWS accepted launch");
            Ok(())
        }
        async fn terminate(&self, _: &str, ids: Vec<String>) -> anyhow::Result<()> {
            let mut s = self.state.lock().unwrap();
            s.terminated.extend(ids);
            let pending = s.pending_termination;
            for i in &mut s.instances {
                i.state = if pending {
                    "shutting-down"
                } else {
                    "terminated"
                }
                .into();
            }
            Ok(())
        }
        async fn volumes(&self, _: &str, _: &str, _: &[String]) -> anyhow::Result<Vec<Volume>> {
            Ok(self.state.lock().unwrap().volumes.clone())
        }
        async fn delete_volume(&self, _: &str, id: &str) -> anyhow::Result<()> {
            let mut s = self.state.lock().unwrap();
            s.deleted_volumes.push(id.into());
            s.volumes.retain(|v| v.id != id);
            Ok(())
        }
        async fn addresses(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> anyhow::Result<Vec<Address>> {
            Ok(self.state.lock().unwrap().addresses.clone())
        }
        async fn release_address(&self, _: &str, a: &Address) -> anyhow::Result<()> {
            let mut s = self.state.lock().unwrap();
            s.released.push(a.id.clone());
            s.addresses.retain(|v| v.id != a.id);
            Ok(())
        }
    }
    fn setup() -> (Ec2Provisioner, Arc<Mock>, Deployment) {
        let mut cfg = Config::from_pairs(crate::config::tests::valid_pairs()).unwrap();
        cfg.lifecycle.ec2.regions.insert(
            "ap-east-1".into(),
            crate::config::Ec2RegionConfig {
                ami_id: "ami-12345678901234567".into(),
                subnet_id: "subnet-12345678901234567".into(),
                security_group_ids: vec!["sg-12345678901234567".into()],
            },
        );
        let api = Arc::new(Mock::default());
        let provisioner = Ec2Provisioner {
            api: api.clone(),
            config: Arc::new(cfg),
        };
        let d = provisioner
            .plan("ap-east-1", "01234567890123456789012345678901")
            .unwrap();
        (provisioner, api, d)
    }
    #[tokio::test]
    async fn request_contract_limits_cost_and_preserves_cleanup_flags() {
        let (p, _, d) = setup();
        let DeploymentResources::Ec2 {
            launch: Some(spec), ..
        } = &d.resources
        else {
            panic!("missing EC2 plan");
        };
        let config = aws_sdk_ec2::Config::builder()
            .behavior_version_latest()
            .region(aws_sdk_ec2::config::Region::new("ap-east-1"))
            .build();
        let client = Client::from_conf(config);
        let request = launch_request(&client, &d.id, spec, "bootstrap", "/dev/sda1")
            .as_input()
            .clone()
            .build()
            .unwrap();
        assert_eq!(request.min_count(), Some(1));
        assert_eq!(request.max_count(), Some(1));
        assert_eq!(
            request.client_token(),
            Some(format!("vpn-{}", d.id).as_str())
        );
        let network = &request.network_interfaces()[0];
        assert_eq!(network.associate_public_ip_address(), Some(true));
        assert_eq!(network.delete_on_termination(), Some(true));
        let disk = request.block_device_mappings()[0].ebs().unwrap();
        assert_eq!(disk.encrypted(), Some(true));
        assert_eq!(disk.delete_on_termination(), Some(true));
        assert_eq!(disk.volume_size(), Some(8));
        assert_eq!(
            request.credit_specification().unwrap().cpu_credits(),
            Some("standard")
        );
        assert_eq!(
            request
                .metadata_options()
                .unwrap()
                .http_tokens()
                .unwrap()
                .as_str(),
            "required"
        );
        assert_eq!(
            request.user_data(),
            Some(STANDARD.encode("bootstrap").as_str())
        );
        for tag_spec in request.tag_specifications() {
            assert_eq!(
                tagged(tag_spec.tags(), DEPLOYMENT).as_deref(),
                Some(d.id.as_str())
            );
        }
        drop(p);
    }

    #[tokio::test]
    async fn lost_response_and_eventual_visibility_reuse_frozen_launch() {
        let (p, api, d) = setup();
        api.state.lock().unwrap().lose_response = true;
        assert!(p.ensure(&d).await.is_err());
        {
            let mut s = api.state.lock().unwrap();
            s.lose_response = false;
            s.hide_reads = 1;
        }
        // Simulate a process restart by serializing the still-unacknowledged deployment.
        let restored: Deployment =
            serde_json::from_slice(&serde_json::to_vec(&d).unwrap()).unwrap();
        assert!(p.ensure(&restored).await.is_err());
        let result = p.ensure(&restored).await.unwrap();
        assert_eq!(result.instance(), "i-12345678901234567");
        let s = api.state.lock().unwrap();
        assert_eq!(s.objects_created, 1);
        assert_eq!(s.launches.len(), 2);
    }
    #[tokio::test]
    async fn config_change_cannot_replay_same_token_with_new_user_data() {
        let (mut p, api, d) = setup();
        Arc::get_mut(&mut p.config).unwrap().proxy.vless_port = 444;
        assert!(p.ensure(&d).await.is_err());
        assert_eq!(api.state.lock().unwrap().objects_created, 0);
    }
    #[tokio::test]
    async fn launch_parameters_are_frozen_even_if_region_configuration_changes() {
        let (mut p, api, d) = setup();
        Arc::get_mut(&mut p.config)
            .unwrap()
            .lifecycle
            .ec2
            .instance_type = "t3.micro".into();
        assert!(p.ensure(&d).await.is_err());
        assert_eq!(
            api.state.lock().unwrap().launches[0].1.instance_type,
            "t3.nano"
        );
    }
    #[tokio::test]
    async fn cleanup_finds_resources_even_when_launch_was_never_recorded() {
        let (p, api, d) = setup();
        let _ = p.ensure(&d).await;
        {
            let mut s = api.state.lock().unwrap();
            s.volumes.push(Volume {
                id: "vol-orphan".into(),
                state: "available".into(),
                attached: false,
                managed: true,
                deployment: Some(d.id.clone()),
            });
            s.addresses.push(Address {
                id: "eipalloc-old".into(),
                association: None,
                managed: true,
                deployment: Some(d.id.clone()),
            });
        }
        p.destroy(&d).await.unwrap();
        let s = api.state.lock().unwrap();
        assert_eq!(s.terminated.len(), 1);
        assert_eq!(s.deleted_volumes, vec!["vol-orphan"]);
        assert_eq!(s.released, vec!["eipalloc-old"]);
    }
    #[tokio::test]
    async fn cleanup_never_deletes_an_attached_or_foreign_volume() {
        for (managed, attached) in [(false, false), (true, true)] {
            let (p, api, d) = setup();
            api.state.lock().unwrap().volumes.push(Volume {
                id: "vol-keep".into(),
                state: "available".into(),
                attached,
                managed,
                deployment: Some(d.id.clone()),
            });
            assert!(p.destroy(&d).await.is_err());
            assert!(api.state.lock().unwrap().deleted_volumes.is_empty());
        }
    }
    #[tokio::test(start_paused = true)]
    async fn pending_termination_is_not_reported_as_success() {
        let (p, api, d) = setup();
        let _ = p.ensure(&d).await;
        api.state.lock().unwrap().pending_termination = true;
        assert!(p.destroy(&d).await.is_err());
        assert!(api.state.lock().unwrap().deleted_volumes.is_empty());
    }
    #[tokio::test]
    async fn ownership_mismatch_prevents_termination() {
        let (p, api, d) = setup();
        let _ = p.ensure(&d).await;
        api.state.lock().unwrap().instances[0].deployment = Some("another-job".into());
        assert!(p.destroy(&d).await.is_err());
        assert!(api.state.lock().unwrap().terminated.is_empty());
    }
}
