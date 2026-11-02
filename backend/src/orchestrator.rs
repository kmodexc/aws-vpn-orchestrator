//! Orchestrates ingress operations: one operation at a time (409 when busy), rotation cooldown,
//! burned-IP retries, a 15 s status cache and the event log.
//!
//! Operations run in a spawned task that owns the operation lock, so a client disconnect or a
//! request timeout never aborts an AWS operation half-way.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::error::ApiError;
use crate::providers::{IngressProvider, IngressStatus};
use crate::config::TargetConfig;
use crate::state::{Event, EventAction, StateStore};
use crate::util::{sanitize_text, unix_now};

pub const STATUS_CACHE_TTL: Duration = Duration::from_secs(15);
pub const MAX_ROTATE_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusView {
    pub provider: String,
    pub region: String,
    pub instance: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub cooldown_remaining_s: u64,
    pub last_rotation_at: Option<i64>,
}

pub struct Orchestrator {
    provider: Arc<dyn IngressProvider>,
    store: Arc<StateStore>,
    op_lock: Arc<Mutex<()>>,
    cache: Mutex<Option<(Instant, IngressStatus)>>,
    cooldown: Duration,
    provider_name: String,
    region: String,
    instance: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TargetView {
    pub id: String,
    pub provider: String,
    pub region: String,
    pub instance: String,
    pub active: bool,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Start,
    Stop,
}

/// Seconds of cooldown left, given the last rotation time and the current time (unix seconds).
pub fn cooldown_remaining(last_rotation_at: Option<i64>, now: i64, cooldown: Duration) -> u64 {
    let Some(last) = last_rotation_at else {
        return 0;
    };
    let cooldown = i64::try_from(cooldown.as_secs()).unwrap_or(i64::MAX);
    let elapsed = now.saturating_sub(last).max(0);
    u64::try_from(cooldown.saturating_sub(elapsed).max(0)).unwrap_or(0)
}

impl Orchestrator {
    pub fn new(
        provider: Arc<dyn IngressProvider>,
        store: Arc<StateStore>,
        cooldown: Duration,
        provider_name: &str,
        region: &str,
        instance: &str,
    ) -> Self {
        Self {
            provider,
            store,
            op_lock: Arc::new(Mutex::new(())),
            cache: Mutex::new(None),
            cooldown,
            provider_name: provider_name.to_string(),
            region: region.to_string(),
            instance: instance.to_string(),
        }
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }

    /// Current ingress status, cached for [`STATUS_CACHE_TTL`].
    pub async fn status(&self) -> Result<IngressStatus, ApiError> {
        let mut cache = self.cache.lock().await;
        if let Some((at, status)) = cache.as_ref() {
            if at.elapsed() < STATUS_CACHE_TTL {
                return Ok(status.clone());
            }
        }
        let status = self
            .provider
            .status()
            .await
            .map_err(|e| ApiError::unavailable(format!("{e:#}")))?;
        *cache = Some((Instant::now(), status.clone()));
        Ok(status)
    }

    pub async fn invalidate(&self) {
        *self.cache.lock().await = None;
    }

    pub async fn status_view(&self) -> Result<StatusView, ApiError> {
        let status = self.status().await?;
        let last_rotation_at = self.store.snapshot().await.last_rotation_at;
        Ok(StatusView {
            provider: self.provider_name.clone(),
            region: self.region.clone(),
            instance: self.instance.clone(),
            state: status.state,
            public_ip: status.public_ip.map(|ip| ip.to_string()),
            cooldown_remaining_s: cooldown_remaining(last_rotation_at, unix_now(), self.cooldown),
            last_rotation_at,
        })
    }

    fn try_acquire(&self) -> Result<OwnedMutexGuard<()>, ApiError> {
        Arc::clone(&self.op_lock)
            .try_lock_owned()
            .map_err(|_| ApiError::Conflict)
    }

    pub fn busy(&self) -> bool {
        self.op_lock.try_lock().is_err()
    }

    /// Wait until no operation is running (used during graceful shutdown).
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.op_lock.lock())
            .await
            .is_ok()
    }

    pub async fn start(self: &Arc<Self>, actor: String) -> Result<(), ApiError> {
        self.power(Op::Start, actor).await
    }

    pub async fn stop(self: &Arc<Self>, actor: String) -> Result<(), ApiError> {
        self.power(Op::Stop, actor).await
    }

    async fn power(self: &Arc<Self>, op: Op, actor: String) -> Result<(), ApiError> {
        let guard = self.try_acquire()?;
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = guard;
            let (result, action, name) = match op {
                Op::Start => (this.provider.start().await, EventAction::Start, "start"),
                Op::Stop => (this.provider.stop().await, EventAction::Stop, "stop"),
            };
            this.invalidate().await;
            match result {
                Ok(()) => {
                    this.record(action, None, format!("{name} requested"), actor)
                        .await;
                    Ok(())
                }
                Err(e) => {
                    this.record(EventAction::Error, None, format!("{name} failed"), actor)
                        .await;
                    Err(ApiError::unavailable(format!("{e:#}")))
                }
            }
        })
        .await
        .map_err(ApiError::internal)?
    }

    /// Rotate the public IPv4. Returns the new address.
    pub async fn rotate(
        self: &Arc<Self>,
        actor: String,
        reason: Option<String>,
    ) -> Result<Ipv4Addr, ApiError> {
        let guard = self.try_acquire()?;
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = guard;
            this.rotate_locked(actor, reason).await
        })
        .await
        .map_err(ApiError::internal)?
    }

    async fn rotate_locked(
        &self,
        actor: String,
        reason: Option<String>,
    ) -> Result<Ipv4Addr, ApiError> {
        let snap = self.store.snapshot().await;
        let remaining = cooldown_remaining(snap.last_rotation_at, unix_now(), self.cooldown);
        if remaining > 0 {
            return Err(ApiError::Cooldown {
                retry_after_s: remaining,
            });
        }

        let old_ip = match self.provider.status().await {
            Ok(s) => s.public_ip,
            Err(e) => {
                self.record(EventAction::Error, None, "rotate failed".into(), actor)
                    .await;
                return Err(ApiError::unavailable(format!("{e:#}")));
            }
        };
        if let Some(old) = old_ip {
            self.persist(|s| s.burn_ip(&old.to_string())).await;
        }

        let mut attempt = 0;
        let new_ip = loop {
            attempt += 1;
            let ip = match self.provider.rotate_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    self.invalidate().await;
                    self.record(EventAction::Error, None, "rotate failed".into(), actor)
                        .await;
                    return Err(ApiError::unavailable(format!("{e:#}")));
                }
            };
            let burned =
                Some(ip) == old_ip || self.store.snapshot().await.is_burned(&ip.to_string());
            if !burned {
                break ip;
            }
            if attempt >= MAX_ROTATE_ATTEMPTS {
                tracing::warn!(%ip, attempt, "rotation keeps returning previously used addresses; accepting the last one");
                break ip;
            }
            tracing::warn!(%ip, attempt, "rotation returned a previously used address; rotating again");
            self.persist(|s| s.burn_ip(&ip.to_string())).await;
        };

        let detail = match reason {
            Some(r) if !r.is_empty() => r,
            _ => "manual rotation".to_string(),
        };
        let now = unix_now();
        let ip_text = new_ip.to_string();
        self.persist(move |s| {
            s.last_rotation_at = Some(now);
            s.push_event(crate::state::Event {
                at: now,
                action: EventAction::Rotate,
                ip: Some(ip_text),
                detail,
                actor,
            });
        })
        .await;
        self.invalidate().await;
        tracing::info!(new_ip = %new_ip, "ingress IP rotated");
        Ok(new_ip)
    }

    async fn record(&self, action: EventAction, ip: Option<String>, detail: String, actor: String) {
        if let Err(e) = self.store.record(action, ip, detail, actor).await {
            tracing::error!(error = %e, "failed to persist event");
        }
    }

    async fn persist(&self, f: impl FnOnce(&mut crate::state::PersistedState)) {
        if let Err(e) = self.store.update(f).await {
            tracing::error!(error = %e, "failed to persist state");
        }
    }
}

/// Coordinates several pre-provisioned ingress targets. Region changes are deliberately an
/// explicit promotion of a configured target; provisioning and IAM changes remain outside the
/// public control process.
pub struct IngressManager {
    targets: HashMap<String, Arc<Orchestrator>>,
    views: Vec<TargetView>,
    default_id: String,
    store: Arc<StateStore>,
    op_lock: Arc<Mutex<()>>,
}

impl IngressManager {
    pub fn new(
        configs: &[TargetConfig],
        providers: HashMap<String, Arc<dyn IngressProvider>>,
        store: Arc<StateStore>,
        cooldown: Duration,
    ) -> anyhow::Result<Self> {
        let mut targets = HashMap::with_capacity(configs.len());
        let mut views = Vec::with_capacity(configs.len());
        for config in configs {
            let provider = providers
                .get(&config.id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing provider for target {}", config.id))?;
            let (region, instance) = match config.provider.kind {
                crate::config::ProviderKind::Fake => (
                    config
                        .provider
                        .aws_region
                        .clone()
                        .unwrap_or_else(|| "local".into()),
                    config
                        .provider
                        .instance
                        .clone()
                        .unwrap_or_else(|| "fake-ingress".into()),
                ),
                _ => (
                    config.provider.aws_region.clone().unwrap_or_default(),
                    config.provider.instance.clone().unwrap_or_default(),
                ),
            };
            let orchestrator = Arc::new(Orchestrator::new(
                provider,
                Arc::clone(&store),
                cooldown,
                config.provider.kind.as_str(),
                &region,
                &instance,
            ));
            views.push(TargetView {
                id: config.id.clone(),
                provider: config.provider.kind.as_str().to_string(),
                region,
                instance,
                active: false,
            });
            targets.insert(config.id.clone(), orchestrator);
        }
        let default_id = configs
            .first()
            .map(|c| c.id.clone())
            .ok_or_else(|| anyhow::anyhow!("at least one ingress target is required"))?;
        Ok(Self {
            targets,
            views,
            default_id,
            store,
            op_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }

    async fn active_id(&self) -> String {
        let id = self.store.snapshot().await.active_target_id;
        match id {
            Some(id) if self.targets.contains_key(&id) => id,
            _ => self.default_id.clone(),
        }
    }

    fn target(&self, id: &str) -> Result<Arc<Orchestrator>, ApiError> {
        self.targets.get(id).cloned().ok_or(ApiError::NotFound)
    }

    fn try_acquire(&self) -> Result<OwnedMutexGuard<()>, ApiError> {
        Arc::clone(&self.op_lock)
            .try_lock_owned()
            .map_err(|_| ApiError::Conflict)
    }

    pub async fn status(&self) -> Result<IngressStatus, ApiError> {
        let id = self.active_id().await;
        self.target(&id)?.status().await
    }

    pub async fn status_view(&self) -> Result<StatusView, ApiError> {
        let id = self.active_id().await;
        self.target(&id)?.status_view().await
    }

    pub async fn start(&self, actor: String) -> Result<(), ApiError> {
        let _guard = self.try_acquire()?;
        let id = self.active_id().await;
        self.target(&id)?.start(actor).await
    }

    pub async fn stop(&self, actor: String) -> Result<(), ApiError> {
        let _guard = self.try_acquire()?;
        let id = self.active_id().await;
        self.target(&id)?.stop(actor).await
    }

    pub async fn rotate(
        &self,
        actor: String,
        reason: Option<String>,
    ) -> Result<Ipv4Addr, ApiError> {
        let _guard = self.try_acquire()?;
        let id = self.active_id().await;
        self.target(&id)?.rotate(actor, reason).await
    }

    pub async fn targets(&self) -> Vec<TargetView> {
        let active = self.active_id().await;
        self.views
            .iter()
            .cloned()
            .map(|mut view| {
                view.active = view.id == active;
                view
            })
            .collect()
    }

    /// Promote a configured target after proving its AWS API is reachable. The target may be
    /// stopped; this is intentional because the phone UI can then start it separately.
    pub async fn switch(
        &self,
        target_id: String,
        actor: String,
        reason: Option<String>,
    ) -> Result<StatusView, ApiError> {
        let _guard = self.try_acquire()?;
        let target = self.target(&target_id)?;
        let current = self.active_id().await;
        if current == target_id {
            return target.status_view().await;
        }
        target
            .status()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let detail = reason
            .filter(|r| !r.trim().is_empty())
            .map(|r| format!("{current} -> {target_id}: {}", sanitize_text(&r, 200)))
            .unwrap_or_else(|| format!("{current} -> {target_id}"));
        self.store
            .update(|s| {
                s.active_target_id = Some(target_id.clone());
                s.push_event(Event {
                    at: unix_now(),
                    action: EventAction::Switch,
                    ip: None,
                    detail,
                    actor,
                });
            })
            .await
            .map_err(ApiError::internal)?;
        target.status_view().await
    }

    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.op_lock.lock())
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    /// Returns scripted IPs from `rotate_ip`.
    struct Scripted {
        current: StdMutex<Ipv4Addr>,
        next: StdMutex<Vec<Ipv4Addr>>,
        delay: Duration,
    }

    #[async_trait]
    impl IngressProvider for Scripted {
        async fn status(&self) -> anyhow::Result<IngressStatus> {
            Ok(IngressStatus {
                state: "running".into(),
                public_ip: Some(*self.current.lock().unwrap()),
            })
        }
        async fn start(&self) -> anyhow::Result<()> {
            tokio::time::sleep(self.delay).await;
            Ok(())
        }
        async fn stop(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn rotate_ip(&self) -> anyhow::Result<Ipv4Addr> {
            let ip = self.next.lock().unwrap().remove(0);
            *self.current.lock().unwrap() = ip;
            Ok(ip)
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    fn fake_target(id: &str, region: &str) -> TargetConfig {
        TargetConfig {
            id: id.to_string(),
            provider: crate::config::ProviderConfig {
                kind: crate::config::ProviderKind::Fake,
                aws_region: Some(region.to_string()),
                instance: Some(format!("{id}-instance")),
            },
        }
    }

    fn orchestrator(
        provider: Arc<dyn IngressProvider>,
        cooldown: u64,
    ) -> (Arc<Orchestrator>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        (
            Arc::new(Orchestrator::new(
                provider,
                store,
                Duration::from_secs(cooldown),
                "fake",
                "local",
                "test",
            )),
            dir,
        )
    }

    #[test]
    fn cooldown_math() {
        let c = Duration::from_secs(120);
        assert_eq!(cooldown_remaining(None, 1000, c), 0);
        assert_eq!(cooldown_remaining(Some(1000), 1000, c), 120);
        assert_eq!(cooldown_remaining(Some(1000), 1100, c), 20);
        assert_eq!(cooldown_remaining(Some(1000), 2000, c), 0);
        // clock went backwards: never more than the cooldown
        assert_eq!(cooldown_remaining(Some(2000), 1000, c), 120);
    }

    #[tokio::test]
    async fn burned_ips_are_retried() {
        let provider = Arc::new(Scripted {
            current: StdMutex::new(ip(1)),
            // 1 is the old IP, 2 was burned earlier, 3 is fresh
            next: StdMutex::new(vec![ip(1), ip(2), ip(3)]),
            delay: Duration::ZERO,
        });
        let (o, _dir) = orchestrator(provider, 120);
        o.store()
            .update(|s| s.burn_ip("203.0.113.2"))
            .await
            .unwrap();
        let new_ip = o.rotate("alice".into(), Some("test".into())).await.unwrap();
        assert_eq!(new_ip, ip(3));
        let snap = o.store().snapshot().await;
        assert!(snap.is_burned("203.0.113.1"));
        assert!(snap.last_rotation_at.is_some());
        let ev = snap.events.last().unwrap();
        assert_eq!(ev.action, EventAction::Rotate);
        assert_eq!(ev.actor, "alice");
        assert_eq!(ev.detail, "test");
        assert_eq!(ev.ip.as_deref(), Some("203.0.113.3"));

        // second rotation is refused by the cooldown
        let err = o.rotate("alice".into(), None).await.unwrap_err();
        assert!(matches!(err, ApiError::Cooldown { retry_after_s } if retry_after_s > 0));
    }

    #[tokio::test]
    async fn gives_up_after_three_attempts() {
        let provider = Arc::new(Scripted {
            current: StdMutex::new(ip(1)),
            next: StdMutex::new(vec![ip(1), ip(1), ip(1), ip(9)]),
            delay: Duration::ZERO,
        });
        let (o, _dir) = orchestrator(provider, 0);
        assert_eq!(o.rotate("bob".into(), None).await.unwrap(), ip(1));
    }

    #[tokio::test]
    async fn concurrent_operations_conflict() {
        let provider = Arc::new(Scripted {
            current: StdMutex::new(ip(1)),
            next: StdMutex::new(vec![]),
            delay: Duration::from_millis(300),
        });
        let (o, _dir) = orchestrator(provider, 0);
        let o2 = Arc::clone(&o);
        let first = tokio::spawn(async move { o2.start("a".into()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(o.stop("b".into()).await.unwrap_err(), ApiError::Conflict);
        first.await.unwrap().unwrap();
        o.stop("b".into()).await.unwrap();
    }

    #[tokio::test]
    async fn manager_switch_persists_target_and_records_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let configs = vec![
            fake_target("tokyo", "ap-northeast-1"),
            fake_target("hongkong", "ap-east-1"),
        ];
        let mut providers: HashMap<String, Arc<dyn IngressProvider>> = HashMap::new();
        providers.insert(
            "tokyo".into(),
            Arc::new(crate::providers::fake::FakeProvider::new()),
        );
        providers.insert(
            "hongkong".into(),
            Arc::new(crate::providers::fake::FakeProvider::new()),
        );
        let manager = IngressManager::new(
            &configs,
            providers,
            Arc::clone(&store),
            Duration::ZERO,
        )
        .unwrap();

        let initial = manager.targets().await;
        assert_eq!(initial.iter().filter(|target| target.active).count(), 1);
        assert!(initial
            .iter()
            .any(|target| target.id == "tokyo" && target.active));

        let status = manager
            .switch(
                "hongkong".into(),
                "alice".into(),
                Some("reachability test".into()),
            )
            .await
            .unwrap();
        assert_eq!(status.region, "ap-east-1");
        assert_eq!(status.instance, "hongkong-instance");

        let snapshot = store.snapshot().await;
        assert_eq!(snapshot.active_target_id.as_deref(), Some("hongkong"));
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].action, EventAction::Switch);
        assert_eq!(snapshot.events[0].actor, "alice");
        assert!(snapshot.events[0].detail.contains("tokyo -> hongkong"));

        let restored = IngressManager::new(
            &configs,
            {
                let mut providers: HashMap<String, Arc<dyn IngressProvider>> = HashMap::new();
                providers.insert(
                    "tokyo".into(),
                    Arc::new(crate::providers::fake::FakeProvider::new()),
                );
                providers.insert(
                    "hongkong".into(),
                    Arc::new(crate::providers::fake::FakeProvider::new()),
                );
                providers
            },
            store,
            Duration::ZERO,
        )
        .unwrap();
        let restored_targets = restored.targets().await;
        assert!(restored_targets
            .iter()
            .any(|target| target.id == "hongkong" && target.active));
    }

    #[tokio::test]
    async fn manager_rejects_unknown_target_and_conflicts_while_busy() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let configs = vec![fake_target("default", "local")];
        let provider = Arc::new(Scripted {
            current: StdMutex::new(ip(1)),
            next: StdMutex::new(vec![]),
            delay: Duration::from_millis(300),
        });
        let mut providers: HashMap<String, Arc<dyn IngressProvider>> = HashMap::new();
        providers.insert("default".into(), provider as Arc<dyn IngressProvider>);
        let manager = Arc::new(
            IngressManager::new(&configs, providers, store, Duration::ZERO).unwrap(),
        );

        assert_eq!(
            manager
                .switch("missing".into(), "alice".into(), None)
                .await
                .unwrap_err(),
            ApiError::NotFound
        );

        let running = Arc::clone(&manager);
        let task = tokio::spawn(async move { running.start("alice".into()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            manager
                .switch("default".into(), "bob".into(), None)
                .await
                .unwrap_err(),
            ApiError::Conflict
        );
        task.await.unwrap().unwrap();
    }
}
