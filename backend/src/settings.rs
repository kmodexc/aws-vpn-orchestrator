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

/// Default sing-box log level: errors and warnings only — no connection records on the ingress.
pub const DEFAULT_LOG_LEVEL: &str = "warn";
pub const DEBUG_LOG_LEVELS: [&str; 3] = ["info", "debug", "trace"];
pub const MAX_DEBUG_MINUTES: u32 = 24 * 60;

/// A temporary, more verbose sing-box log level. `info` and above log every connection with
/// client address and destination, so it always expires by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugLog {
    pub level: String,
    /// Unix seconds; the level reverts to [`DEFAULT_LOG_LEVEL`] when this has passed.
    pub until: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugLogRequest {
    pub level: String,
    pub minutes: u32,
}

impl DebugLogRequest {
    pub fn validate(self, now: i64) -> Result<DebugLog, &'static str> {
        let level = self.level.trim().to_ascii_lowercase();
        if !DEBUG_LOG_LEVELS.contains(&level.as_str()) {
            return Err("level must be info, debug or trace");
        }
        if self.minutes == 0 || self.minutes > MAX_DEBUG_MINUTES {
            return Err("minutes must be between 1 and 1440");
        }
        Ok(DebugLog {
            level,
            until: now + i64::from(self.minutes) * 60,
        })
    }
}

/// The log level to serve now: the debug level while it lasts, else the default.
pub fn log_level(debug: Option<&DebugLog>, now: i64) -> &str {
    match debug {
        Some(d) if d.until > now && DEBUG_LOG_LEVELS.contains(&d.level.as_str()) => &d.level,
        _ => DEFAULT_LOG_LEVEL,
    }
}

/// Secret for sing-box's local stats API (bound to 127.0.0.1 on the ingress). Derived from
/// `INGRESS_TOKEN`, so the reporter on the ingress can derive it too and nothing new is stored.
pub fn clash_api_secret(cfg: &Config) -> String {
    let mut input = b"clash-api\0".to_vec();
    input.extend_from_slice(cfg.ingress_token.expose().as_bytes());
    b64url(&sha256(&input))
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

    #[test]
    fn debug_log_validation_and_expiry() {
        let d = DebugLogRequest {
            level: " INFO ".into(),
            minutes: 30,
        }
        .validate(1000)
        .unwrap();
        assert_eq!(d.level, "info");
        assert_eq!(d.until, 1000 + 30 * 60);
        assert_eq!(log_level(Some(&d), 1000), "info");
        assert_eq!(log_level(Some(&d), 1000 + 30 * 60), "warn");
        assert_eq!(log_level(None, 0), "warn");
        for (level, minutes) in [("warn", 10), ("error", 10), ("info", 0), ("info", 1441)] {
            assert!(
                DebugLogRequest {
                    level: level.into(),
                    minutes
                }
                .validate(0)
                .is_err(),
                "{level} {minutes}"
            );
        }
        // a stored level that is no longer allowed never leaks through
        let bogus = DebugLog {
            level: "panic".into(),
            until: i64::MAX,
        };
        assert_eq!(log_level(Some(&bogus), 0), "warn");
    }
}
