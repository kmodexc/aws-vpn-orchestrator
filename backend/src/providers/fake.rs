//! In-memory provider for tests and local development. Hands out TEST-NET-3 addresses
//! (203.0.113.0/24, RFC 5737).

use std::net::Ipv4Addr;
use std::sync::Mutex;

use async_trait::async_trait;

use super::{IngressProvider, IngressStatus};
use crate::util::lock;

#[derive(Debug)]
struct FakeState {
    running: bool,
    last_octet: u8,
}

#[derive(Debug)]
pub struct FakeProvider {
    state: Mutex<FakeState>,
}

impl Default for FakeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeProvider {
    /// Starts "running" with 203.0.113.10.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FakeState {
                running: true,
                last_octet: 10,
            }),
        }
    }
}

#[async_trait]
impl IngressProvider for FakeProvider {
    async fn status(&self) -> anyhow::Result<IngressStatus> {
        let s = lock(&self.state);
        Ok(IngressStatus {
            state: if s.running { "running" } else { "stopped" }.to_string(),
            public_ip: s.running.then(|| Ipv4Addr::new(203, 0, 113, s.last_octet)),
        })
    }

    async fn start(&self) -> anyhow::Result<()> {
        lock(&self.state).running = true;
        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        lock(&self.state).running = false;
        Ok(())
    }

    async fn rotate_ip(&self) -> anyhow::Result<Ipv4Addr> {
        let mut s = lock(&self.state);
        s.last_octet = if s.last_octet >= 254 {
            1
        } else {
            s.last_octet + 1
        };
        Ok(Ipv4Addr::new(203, 0, 113, s.last_octet))
    }
}
