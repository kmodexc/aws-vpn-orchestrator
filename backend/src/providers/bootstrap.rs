use crate::{config::Config, lifecycle::Deployment};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::Read;

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
        "compressed bootstrap exceeds user-data limit"
    );
    Ok(script)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_bootstrap_fits_lightsail_and_passes_deployment_identity() {
        let cfg = Config::from_pairs(crate::config::tests::valid_pairs()).unwrap();
        let d = Deployment::lightsail(
            "test-id".into(),
            "ap-east-1".into(),
            "vpn-ondemand-test-id".into(),
            None,
        );
        let script = user_data(&cfg, &d).unwrap();
        assert!(script.len() <= 16000);
        assert!(script.contains("'test-id' > /etc/vpn-deployment-id"));
        assert!(script.starts_with("#!/bin/sh\nset -eu"));
    }
}
