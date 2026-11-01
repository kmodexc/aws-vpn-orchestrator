//! Protocol settings that can be changed at runtime through `/api/settings`, so that a blocked
//! camouflage target or protocol can be switched without editing `.env` and restarting.
//!
//! `.env` provides the defaults; an override is stored in `state.json` (no secrets). The ingress
//! picks the change up on its next config pull (at most 10 minutes), clients on their next
//! subscription refresh. Ports and secrets stay in `.env` only: changing a port also needs the
//! AWS and host firewalls, which the control plane deliberately cannot touch.

use serde::{Deserialize, Serialize};

use crate::config::{Config, is_hostname};
use crate::util::{b64url, sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolSettings {
    /// TLS server name VLESS-REALITY impersonates; its handshake is forwarded there on 443.
    pub reality_sni: String,
    /// Server name sent by Hysteria2 clients (the certificate is pinned, not name-checked).
    pub hy2_sni: String,
    pub hysteria2: bool,
    /// Salamander obfuscation for Hysteria2: the UDP packets no longer look like QUIC.
    pub hy2_obfs: bool,
    pub shadowsocks: bool,
}

/// Body of `PUT /api/settings`: the complete settings, no unknown fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsUpdate {
    pub reality_sni: String,
    pub hy2_sni: String,
    pub hysteria2: bool,
    pub hy2_obfs: bool,
    pub shadowsocks: bool,
}

impl ProtocolSettings {
    /// The settings `.env` describes.
    pub fn defaults(cfg: &Config) -> Self {
        let p = &cfg.proxy;
        Self {
            reality_sni: p.reality_sni.clone(),
            hy2_sni: p.hy2_sni.clone(),
            hysteria2: p.hy2_enabled,
            hy2_obfs: p.hy2_obfs,
            shadowsocks: p.ss_enabled,
        }
    }

    /// The stored override, or the `.env` defaults.
    pub fn effective(cfg: &Config, stored: Option<&Self>) -> Self {
        stored.cloned().unwrap_or_else(|| Self::defaults(cfg))
    }
}

impl SettingsUpdate {
    /// Validate and normalize. Errors are static messages safe to return to the client.
    pub fn validate(self) -> Result<ProtocolSettings, &'static str> {
        let reality_sni = self.reality_sni.trim().to_ascii_lowercase();
        if !is_public_host_name(&reality_sni) {
            return Err("reality_sni must be a public DNS host name, e.g. www.example.com");
        }
        let hy2_sni = self.hy2_sni.trim().to_ascii_lowercase();
        if !is_public_host_name(&hy2_sni) {
            return Err("hy2_sni must be a public DNS host name, e.g. www.example.com");
        }
        Ok(ProtocolSettings {
            reality_sni,
            hy2_sni,
            hysteria2: self.hysteria2,
            hy2_obfs: self.hy2_obfs,
            shadowsocks: self.shadowsocks,
        })
    }
}

/// A host name with at least two labels whose top-level label is not numeric (so not an IP
/// address and not `localhost`).
fn is_public_host_name(s: &str) -> bool {
    is_hostname(s)
        && s.contains('.')
        && s.rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// Salamander password, derived from `HY2_PASSWORD` so that no further secret has to be kept.
pub fn salamander_password(cfg: &Config) -> String {
    let mut input = b"hysteria2-salamander\0".to_vec();
    input.extend_from_slice(cfg.proxy.hy2_password.expose().as_bytes());
    b64url(&sha256(&input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(reality: &str, hy2: &str) -> SettingsUpdate {
        SettingsUpdate {
            reality_sni: reality.into(),
            hy2_sni: hy2.into(),
            hysteria2: true,
            hy2_obfs: false,
            shadowsocks: false,
        }
    }

    #[test]
    fn validation_normalizes_and_rejects_non_public_names() {
        let s = update(" WWW.Example.COM ", "cdn.example.net")
            .validate()
            .unwrap();
        assert_eq!(s.reality_sni, "www.example.com");
        assert_eq!(s.hy2_sni, "cdn.example.net");
        assert!(!s.shadowsocks);
        for bad in [
            "",
            "localhost",
            "1.2.3.4",
            "-a.example.com",
            "a..example.com",
            "exa mple.com",
            "https://example.com",
            "example.com/x",
        ] {
            assert!(update(bad, "a.example.com").validate().is_err(), "{bad}");
            assert!(update("a.example.com", bad).validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn effective_prefers_the_stored_override() {
        let cfg = Config::from_pairs(crate::config::tests::valid_pairs()).unwrap();
        let defaults = ProtocolSettings::defaults(&cfg);
        assert_eq!(defaults.reality_sni, "www.microsoft.com");
        assert!(defaults.hysteria2 && defaults.shadowsocks && !defaults.hy2_obfs);
        assert_eq!(ProtocolSettings::effective(&cfg, None), defaults);
        let stored = update("a.example.com", "b.example.com").validate().unwrap();
        assert_eq!(ProtocolSettings::effective(&cfg, Some(&stored)), stored);
    }

    #[test]
    fn salamander_password_is_stable_and_not_the_hy2_password() {
        let cfg = Config::from_pairs(crate::config::tests::valid_pairs()).unwrap();
        let a = salamander_password(&cfg);
        assert_eq!(a, salamander_password(&cfg));
        assert_eq!(a.len(), 43);
        assert_ne!(&a, cfg.proxy.hy2_password.expose());
    }
}
