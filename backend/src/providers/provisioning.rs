//! Lightsail reconciliation for a persisted deployment. Never runs shell commands on the host.
use crate::{
    config::Config,
    lifecycle::{Deployment, Provisioner},
    providers::{IngressStatus, normalize_state, parse_ipv4},
};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use aws_sdk_lightsail::{
    Client,
    types::{IpAddressType, PortInfo, Tag},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{collections::HashMap, io::Read, sync::Arc, time::Duration};

pub struct LightsailProvisioner {
    clients: HashMap<String, Client>,
    config: Arc<Config>,
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
pub fn user_data(config: &Config, deployment: &Deployment) -> anyhow::Result<String> {
    let mut gzip = flate2::read::GzEncoder::new(
        include_bytes!("../../../deploy/ingress/bootstrap.sh").as_slice(),
        flate2::Compression::best(),
    );
    let mut compressed = Vec::new();
    gzip.read_to_end(&mut compressed)?;
    let payload = STANDARD.encode(compressed);
    let script = format!(
        "#!/bin/sh\nset -eu\numask 077\ninstall -d -m 700 /root/vpn-control\nprintf '%s' {} > /etc/vpn-deployment-id\nprintf '%s' '{}' | base64 -d | gunzip > /root/vpn-control/bootstrap.sh\nCONTROL_PLANE_URL={} INGRESS_TOKEN={} VLESS_PORT={} HY2_PORT={} SS_PORT={} SSH_ALLOW_FROM='' bash /root/vpn-control/bootstrap.sh >> /var/log/vpn-control-bootstrap.log 2>&1\n",
        quote(&deployment.id),
        payload,
        quote(&config.public_base_url),
        quote(config.ingress_token.expose()),
        config.proxy.vless_port,
        config.proxy.hy2_port,
        config.proxy.ss_port
    );
    anyhow::ensure!(
        script.len() <= 16000,
        "compressed bootstrap exceeds Lightsail user-data limit"
    );
    Ok(script)
}
impl LightsailProvisioner {
    pub async fn new(config: Arc<Config>) -> Self {
        let mut clients = HashMap::new();
        for region in &config.lifecycle.regions {
            let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(region.clone()))
                .timeout_config(
                    aws_config::timeout::TimeoutConfig::builder()
                        .connect_timeout(Duration::from_secs(5))
                        .operation_timeout(Duration::from_secs(60))
                        .build(),
                )
                .load()
                .await;
            clients.insert(region.clone(), Client::new(&sdk));
        }
        Self { clients, config }
    }
    fn client(&self, region: &str) -> anyhow::Result<&Client> {
        self.clients.get(region).context("region is not allowed")
    }
    async fn instance(
        &self,
        d: &Deployment,
    ) -> anyhow::Result<Option<aws_sdk_lightsail::types::Instance>> {
        match self
            .client(&d.region)?
            .get_instance()
            .instance_name(&d.instance)
            .send()
            .await
        {
            Ok(out) => {
                let instance = out.instance.context("GetInstance returned no instance")?;
                anyhow::ensure!(
                    instance.tags().iter().any(
                        |t| t.key() == Some("vpn-orchestrator") && t.value() == Some("managed")
                    ),
                    "instance is not tagged as managed"
                );
                Ok(Some(instance))
            }
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_not_found_exception()) =>
            {
                Ok(None)
            }
            Err(e) => Err(anyhow!("GetInstance failed: {e}")),
        }
    }
    async fn static_ip(
        &self,
        d: &Deployment,
    ) -> anyhow::Result<Option<aws_sdk_lightsail::types::StaticIp>> {
        let Some(name) = &d.static_ip else {
            return Ok(None);
        };
        anyhow::ensure!(
            name.starts_with("vpn-orchestrator-"),
            "refusing an unmanaged static IP"
        );
        match self
            .client(&d.region)?
            .get_static_ip()
            .static_ip_name(name)
            .send()
            .await
        {
            Ok(out) => Ok(out.static_ip),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_not_found_exception()) =>
            {
                Ok(None)
            }
            Err(e) => Err(anyhow!("GetStaticIp failed: {e}")),
        }
    }
}
#[async_trait]
impl Provisioner for LightsailProvisioner {
    async fn discover(&self, d: &Deployment) -> anyhow::Result<Deployment> {
        let instance = self
            .instance(d)
            .await?
            .context("existing ingress was not found")?;
        let mut result = d.clone();
        result.public_ip = parse_ipv4(instance.public_ip_address());
        let client = self.client(&d.region)?;
        let mut token = None;
        loop {
            let out = client.get_static_ips().set_page_token(token).send().await?;
            if let Some(ip) = out
                .static_ips()
                .iter()
                .find(|ip| ip.attached_to() == Some(d.instance.as_str()))
            {
                let name = ip.name().context("static IP has no name")?;
                anyhow::ensure!(
                    name.starts_with("vpn-orchestrator-"),
                    "cannot adopt an unmanaged static IP"
                );
                result.static_ip = Some(name.into());
                break;
            }
            token = out
                .next_page_token()
                .filter(|t| !t.is_empty())
                .map(str::to_string);
            if token.is_none() {
                break;
            }
        }
        Ok(result)
    }
    async fn ensure(&self, d: &Deployment) -> anyhow::Result<Deployment> {
        anyhow::ensure!(
            d.managed && d.instance == format!("vpn-ondemand-{}", d.id),
            "invalid generated instance name"
        );
        let client = self.client(&d.region)?;
        let instance = match self.instance(d).await? {
            Some(instance) => instance,
            None => {
                let regions = client
                    .get_regions()
                    .include_availability_zones(true)
                    .send()
                    .await?;
                let zone = regions
                    .regions()
                    .iter()
                    .find(|r| r.name().is_some_and(|n| n.as_str() == d.region))
                    .and_then(|r| {
                        r.availability_zones()
                            .iter()
                            .find(|z| z.state() == Some("available"))
                    })
                    .and_then(|z| z.zone_name())
                    .context("no available Lightsail zone")?;
                client
                    .create_instances()
                    .instance_names(&d.instance)
                    .availability_zone(zone)
                    .blueprint_id(&self.config.lifecycle.blueprint)
                    .bundle_id(&self.config.lifecycle.bundle)
                    .ip_address_type(IpAddressType::Ipv4)
                    .user_data(user_data(&self.config, d)?)
                    .tags(
                        Tag::builder()
                            .key("vpn-orchestrator")
                            .value("managed")
                            .build(),
                    )
                    .send()
                    .await?;
                return Err(anyhow!(
                    "instance creation requested; waiting for visibility"
                ));
            }
        };
        anyhow::ensure!(
            instance.state().and_then(|s| s.name()) == Some("running"),
            "instance is not running yet"
        );
        let mut ports = Vec::new();
        for (port, protocol) in [
            (self.config.proxy.vless_port, "tcp"),
            (self.config.proxy.hy2_port, "udp"),
            (self.config.proxy.ss_port, "tcp"),
            (self.config.proxy.ss_port, "udp"),
        ] {
            if !ports.iter().any(|p: &PortInfo| {
                p.from_port() == i32::from(port)
                    && p.protocol().is_some_and(|v| v.as_str() == protocol)
            }) {
                ports.push(
                    PortInfo::builder()
                        .from_port(i32::from(port))
                        .to_port(i32::from(port))
                        .protocol(aws_sdk_lightsail::types::NetworkProtocol::from(protocol))
                        .cidrs("0.0.0.0/0")
                        .build(),
                );
            }
        }
        client
            .put_instance_public_ports()
            .instance_name(&d.instance)
            .set_port_infos(Some(ports))
            .send()
            .await?;
        let name = d
            .static_ip
            .as_ref()
            .context("missing deterministic static-IP name")?;
        if self.static_ip(d).await?.is_none() {
            client
                .allocate_static_ip()
                .static_ip_name(name)
                .send()
                .await?;
        }
        let ip = self
            .static_ip(d)
            .await?
            .context("static IP not visible yet")?;
        if ip.is_attached() == Some(true) {
            anyhow::ensure!(
                ip.attached_to() == Some(d.instance.as_str()),
                "static IP belongs to another instance"
            );
        } else {
            client
                .attach_static_ip()
                .static_ip_name(name)
                .instance_name(&d.instance)
                .send()
                .await?;
        }
        let ip = self.static_ip(d).await?.context("static IP disappeared")?;
        anyhow::ensure!(
            ip.attached_to() == Some(d.instance.as_str()),
            "waiting for IP attachment"
        );
        let mut result = d.clone();
        result.public_ip = Some(parse_ipv4(ip.ip_address()).context("no public IPv4")?);
        Ok(result)
    }
    async fn destroy(&self, d: &Deployment) -> anyhow::Result<()> {
        anyhow::ensure!(d.managed, "refusing an unmanaged deployment");
        let client = self.client(&d.region)?;
        if self.instance(d).await?.is_some() {
            client
                .delete_instance()
                .instance_name(&d.instance)
                .force_delete_add_ons(true)
                .send()
                .await?;
            // AWS deletion is asynchronous. Do not forget the deployment until it is absent.
            for _ in 0..60 {
                if self.instance(d).await?.is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            anyhow::ensure!(
                self.instance(d).await?.is_none(),
                "instance deletion is still pending"
            );
        }
        if let Some(ip) = self.static_ip(d).await? {
            anyhow::ensure!(
                ip.is_attached() != Some(true),
                "static IP is still attached; refusing release"
            );
            client
                .release_static_ip()
                .static_ip_name(d.static_ip.as_ref().context("missing static-IP name")?)
                .send()
                .await?;
            anyhow::ensure!(
                self.static_ip(d).await?.is_none(),
                "static IP release is still pending"
            );
        }
        Ok(())
    }
    async fn status(&self, d: &Deployment) -> anyhow::Result<IngressStatus> {
        match self.instance(d).await? {
            Some(i) => Ok(IngressStatus {
                state: normalize_state(i.state().and_then(|s| s.name()).unwrap_or("unknown")),
                public_ip: parse_ipv4(i.public_ip_address()),
            }),
            None => Ok(IngressStatus {
                state: "absent".into(),
                public_ip: None,
            }),
        }
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
    #[test]
    fn embedded_bootstrap_fits_lightsail_and_passes_deployment_identity() {
        let cfg = Config::from_pairs(crate::config::tests::valid_pairs()).unwrap();
        let d = Deployment {
            id: "test-id".into(),
            region: "ap-east-1".into(),
            instance: "vpn-ondemand-test-id".into(),
            static_ip: None,
            public_ip: None,
            managed: true,
        };
        let script = user_data(&cfg, &d).unwrap();
        assert!(script.len() <= 16000);
        assert!(script.contains("'test-id' > /etc/vpn-deployment-id"));
        assert!(script.starts_with("#!/bin/sh\nset -eu"));
    }
}
