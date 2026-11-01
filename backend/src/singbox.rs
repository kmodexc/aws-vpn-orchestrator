//! sing-box server configuration (SPEC §7) and client share links / subscription (SPEC §8).

use std::net::Ipv4Addr;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

use crate::config::Config;
use crate::settings::{DEFAULT_LOG_LEVEL, ProtocolSettings, clash_api_secret, salamander_password};
use crate::util::b64std;

/// Everything except RFC 3986 "unreserved" characters is percent-encoded.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

fn pem_lines(pem: &str) -> Vec<String> {
    pem.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// The sing-box (>= 1.12) server configuration pulled by the ingress (on boot and every
/// 10 minutes). Disabled protocols have no inbound, so nothing answers on their ports.
pub fn server_config(cfg: &Config, s: &ProtocolSettings) -> Value {
    server_config_with(cfg, s, DEFAULT_LOG_LEVEL)
}

/// Like [`server_config`], with an explicit sing-box log level (debug logging).
pub fn server_config_with(cfg: &Config, s: &ProtocolSettings, log_level: &str) -> Value {
    let p = &cfg.proxy;
    let mut inbounds = vec![json!({
        "type": "vless",
        "tag": "vless-reality",
        "listen": "::",
        "listen_port": p.vless_port,
        "users": [{"uuid": p.vless_uuid.expose(), "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": true,
            "server_name": s.reality_sni,
            "reality": {
                "enabled": true,
                "handshake": {"server": s.reality_sni, "server_port": 443},
                "private_key": p.reality_private_key.expose(),
                "short_id": [p.reality_short_id],
            }
        }
    })];
    if s.hysteria2 {
        let mut hy2 = json!({
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": p.hy2_port,
            "users": [{"password": p.hy2_password.expose()}],
            "tls": {
                "enabled": true,
                "server_name": s.hy2_sni,
                "alpn": ["h3"],
                "certificate": pem_lines(&p.hy2_cert_pem),
                "key": pem_lines(p.hy2_key_pem.expose()),
            }
        });
        if s.hy2_obfs {
            hy2["obfs"] = json!({"type": "salamander", "password": salamander_password(cfg)});
        }
        inbounds.push(hy2);
    }
    if s.shadowsocks {
        inbounds.push(json!({
            "type": "shadowsocks",
            "tag": "shadowsocks",
            "listen": "::",
            "listen_port": p.ss_port,
            "method": "2022-blake3-aes-128-gcm",
            "password": p.ss_password.expose(),
        }));
    }
    let mut config = json!({
        "log": {"level": log_level, "timestamp": true},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            // Clients must not reach anything on or around the ingress through the proxy:
            // not the loopback stats API below, not the VPC, not link-local (metadata).
            // Domains are resolved first so the IP rule also covers names that point there.
            "rules": [
                {"action": "resolve"},
                {"ip_is_private": true, "action": "reject"}
            ],
            "final": "direct",
            "default_domain_resolver": "local"
        },
        // Local stats API for the reporter on the ingress (connections, traffic). Loopback
        // only (and unreachable through the proxy, see the route rules); the reporter derives
        // the same secret from INGRESS_TOKEN.
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": clash_api_secret(cfg),
            }
        }
    });

    if let Some(peer) = cfg
        .wireguard
        .peer
        .as_ref()
        .filter(|_| cfg.wireguard.enabled)
    {
        config["endpoints"] = json!([{
            "type": "wireguard",
            "tag": "wg-exit",
            "mtu": cfg.wireguard.mtu,
            "address": [cfg.wireguard.ingress_address],
            "private_key": peer.ingress_private_key.expose(),
            "peers": [{
                "address": peer.vps_host,
                "port": peer.vps_port,
                "public_key": peer.vps_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25,
            }]
        }]);
        config["route"]["final"] = json!("wg-exit");
    }
    config
}

/// Client share links for the given ingress IPv4 address, enabled protocols only. IPv6 is
/// never published, which the type enforces.
pub fn share_links(cfg: &Config, s: &ProtocolSettings, ip: Ipv4Addr) -> Vec<String> {
    let p = &cfg.proxy;
    let name = &cfg.profile_name;
    let mut links = vec![format!(
        "vless://{uuid}@{ip}:{port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type=tcp#{frag}",
        uuid = enc(p.vless_uuid.expose()),
        port = p.vless_port,
        sni = enc(&s.reality_sni),
        pbk = enc(&p.reality_public_key),
        sid = enc(&p.reality_short_id),
        frag = enc(&format!("{name}-reality")),
    )];
    if s.hysteria2 {
        let obfs = if s.hy2_obfs {
            format!(
                "&obfs=salamander&obfs-password={}",
                enc(&salamander_password(cfg))
            )
        } else {
            String::new()
        };
        links.push(format!(
            "hysteria2://{pw}@{ip}:{port}?sni={sni}&insecure=1&pinSHA256={pin}{obfs}#{frag}",
            pw = enc(p.hy2_password.expose()),
            port = p.hy2_port,
            sni = enc(&s.hy2_sni),
            pin = enc(&p.hy2_cert_sha256_hex),
            frag = enc(&format!("{name}-hy2")),
        ));
    }
    if s.shadowsocks {
        links.push(format!(
            "ss://{userinfo}@{ip}:{port}#{frag}",
            userinfo = enc(&format!(
                "2022-blake3-aes-128-gcm:{}",
                p.ss_password.expose()
            )),
            port = p.ss_port,
            frag = enc(&format!("{name}-ss")),
        ));
    }
    links
}

/// The subscription body: standard base64 of the links joined by `\n`.
pub fn subscription_body(cfg: &Config, s: &ProtocolSettings, ip: Ipv4Addr) -> String {
    b64std(share_links(cfg, s, ip).join("\n").as_bytes())
}

/// The `profile-title` header value: `base64:<b64(PROFILE_NAME)>`.
pub fn profile_title(cfg: &Config) -> String {
    format!("base64:{}", b64std(cfg.profile_name.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::valid_pairs;
    use base64::Engine;

    fn defaults(cfg: &Config) -> ProtocolSettings {
        ProtocolSettings::defaults(cfg)
    }

    fn config(extra: &[(&str, &str)]) -> Config {
        let mut pairs = valid_pairs();
        for (k, v) in extra {
            pairs.push(((*k).to_string(), (*v).to_string()));
        }
        Config::from_pairs(pairs).unwrap()
    }

    #[test]
    fn share_links_have_expected_shape() {
        let cfg = config(&[("PROFILE_NAME", "my-trip")]);
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let links = share_links(&cfg, &defaults(&cfg), ip);
        assert_eq!(links.len(), 3);
        let p = &cfg.proxy;

        assert!(links[0].starts_with(&format!(
            "vless://{}@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=",
            p.vless_uuid.expose()
        )));
        assert!(links[0].contains(&format!(
            "&sid={}&type=tcp#my-trip-reality",
            p.reality_short_id
        )));
        assert!(links[0].contains(&format!("pbk={}", p.reality_public_key)));

        assert!(links[1].starts_with("hysteria2://"));
        assert!(links[1].contains("@203.0.113.7:443?sni=www.bing.com&insecure=1&pinSHA256="));
        assert!(links[1].contains(&p.hy2_cert_sha256_hex));
        assert!(links[1].ends_with("#my-trip-hy2"));

        let expected_userinfo = enc(&format!(
            "2022-blake3-aes-128-gcm:{}",
            p.ss_password.expose()
        ));
        assert_eq!(
            links[2],
            format!("ss://{expected_userinfo}@203.0.113.7:8443#my-trip-ss")
        );
        // ':' '+' '/' '=' must be percent-encoded in the userinfo
        assert!(expected_userinfo.starts_with("2022-blake3-aes-128-gcm%3A"));
        assert!(!expected_userinfo.contains('='));
    }

    #[test]
    fn percent_encoding_of_special_characters() {
        assert_eq!(
            enc("a b/c+d=e:f@g#h?i&j"),
            "a%20b%2Fc%2Bd%3De%3Af%40g%23h%3Fi%26j"
        );
        assert_eq!(enc("A-z_0.9~"), "A-z_0.9~");
    }

    #[test]
    fn subscription_is_base64_of_newline_joined_links() {
        let cfg = config(&[]);
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        let body = subscription_body(&cfg, &defaults(&cfg), ip);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap();
        let text = String::from_utf8(decoded).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines, share_links(&cfg, &defaults(&cfg), ip));
        assert_eq!(profile_title(&cfg), "base64:dHJhdmVs");
    }

    #[test]
    fn server_config_without_wireguard() {
        let cfg = config(&[]);
        let c = server_config(&cfg, &defaults(&cfg));
        assert_eq!(c["route"]["final"], "direct");
        assert_eq!(c["log"]["level"], "warn");
        let rules = c["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "resolve");
        assert_eq!(rules[1]["ip_is_private"], true);
        assert_eq!(rules[1]["action"], "reject");
        assert_eq!(
            c["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9090"
        );
        assert_eq!(
            c["experimental"]["clash_api"]["secret"],
            clash_api_secret(&cfg).as_str()
        );
        assert_eq!(
            server_config_with(&cfg, &defaults(&cfg), "debug")["log"]["level"],
            "debug"
        );
        assert_eq!(c["route"]["default_domain_resolver"], "local");
        assert!(c.get("endpoints").is_none());
        let inbounds = c["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        assert_eq!(inbounds[0]["type"], "vless");
        assert_eq!(inbounds[0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(
            inbounds[0]["tls"]["reality"]["private_key"],
            cfg.proxy.reality_private_key.expose().as_str()
        );
        assert_eq!(
            inbounds[0]["tls"]["reality"]["short_id"][0],
            cfg.proxy.reality_short_id.as_str()
        );
        assert_eq!(inbounds[1]["type"], "hysteria2");
        assert_eq!(inbounds[1]["tls"]["alpn"][0], "h3");
        assert!(inbounds[1].get("obfs").is_none());
        let cert = inbounds[1]["tls"]["certificate"].as_array().unwrap();
        assert_eq!(cert[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(cert[cert.len() - 1], "-----END CERTIFICATE-----");
        let key = inbounds[1]["tls"]["key"].as_array().unwrap();
        assert_eq!(key[0], "-----BEGIN PRIVATE KEY-----");
        assert_eq!(inbounds[2]["method"], "2022-blake3-aes-128-gcm");
        assert_eq!(inbounds[2]["listen_port"], 8443);
    }

    #[test]
    fn server_config_with_wireguard() {
        let vps_pub = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let cfg = config(&[
            ("WG_ENABLED", "true"),
            ("WG_VPS_ENDPOINT", "198.51.100.1:51820"),
            ("WG_VPS_PUBLIC_KEY", &vps_pub),
            ("WG_MTU", "1400"),
        ]);
        let c = server_config(&cfg, &defaults(&cfg));
        assert_eq!(c["route"]["final"], "wg-exit");
        let ep = &c["endpoints"][0];
        assert_eq!(ep["type"], "wireguard");
        assert_eq!(ep["tag"], "wg-exit");
        assert_eq!(ep["mtu"], 1400);
        assert_eq!(ep["address"][0], "10.66.0.2/32");
        assert_eq!(ep["peers"][0]["address"], "198.51.100.1");
        assert_eq!(ep["peers"][0]["port"], 51820);
        assert_eq!(ep["peers"][0]["public_key"], vps_pub.as_str());
        assert_eq!(ep["peers"][0]["persistent_keepalive_interval"], 25);
        assert_eq!(ep["peers"][0]["allowed_ips"][1], "::/0");
    }

    #[test]
    fn settings_drive_inbounds_and_links() {
        let cfg = config(&[]);
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let s = ProtocolSettings {
            reality_sni: "www.example.com".into(),
            hy2_sni: "cdn.example.net".into(),
            hysteria2: true,
            hy2_obfs: true,
            shadowsocks: false,
        };
        let c = server_config(&cfg, &s);
        let inbounds = c["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[0]["tls"]["server_name"], "www.example.com");
        assert_eq!(
            inbounds[0]["tls"]["reality"]["handshake"]["server"],
            "www.example.com"
        );
        assert_eq!(inbounds[1]["tls"]["server_name"], "cdn.example.net");
        assert_eq!(inbounds[1]["obfs"]["type"], "salamander");
        let pw = salamander_password(&cfg);
        assert_eq!(inbounds[1]["obfs"]["password"], pw.as_str());

        let links = share_links(&cfg, &s, ip);
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("&sni=www.example.com&"));
        assert!(links[1].contains("?sni=cdn.example.net&"));
        assert!(links[1].contains(&format!("&obfs=salamander&obfs-password={}#", enc(&pw))));
        assert!(!links.iter().any(|l| l.starts_with("ss://")));

        let only_reality = ProtocolSettings {
            hysteria2: false,
            ..s
        };
        let c = server_config(&cfg, &only_reality);
        assert_eq!(c["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(share_links(&cfg, &only_reality, ip).len(), 1);
    }
}
