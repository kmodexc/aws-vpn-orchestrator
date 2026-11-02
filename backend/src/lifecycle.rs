//! Durable, on-demand ingress jobs. The browser never owns an AWS operation.
use crate::{
    config::Config,
    error::ApiError,
    providers::IngressStatus,
    state::{EventAction, StateStore},
    util::unix_now,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deployment {
    pub id: String,
    pub region: String,
    pub instance: String,
    pub static_ip: Option<String>,
    pub public_ip: Option<Ipv4Addr>,
    /// Only generated deployments may be removed automatically. Existing deployments require
    /// an explicit adoption setting and are discovered before their resource names are saved.
    pub managed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Creating,
    WaitingReady,
    Reconnect,
    Cleaning,
    Failed,
    Complete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub stage: Stage,
    pub candidate: Option<Deployment>,
    pub started_at: i64,
    pub ready: bool,
    #[serde(default)]
    pub ready_at: Option<i64>,
    pub cleanup_after: Option<i64>,
    pub error: Option<String>,
    pub actor: String,
}
impl Job {
    pub fn unfinished(&self) -> bool {
        !matches!(self.stage, Stage::Failed | Stage::Complete)
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleState {
    pub active: Option<Deployment>,
    pub cleanup_pending: Vec<Deployment>,
    pub job: Option<Job>,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub enabled: bool,
    pub regions: Vec<String>,
    pub active: Option<Deployment>,
    pub cleanup_pending: Vec<Deployment>,
    pub job: Option<Job>,
}

#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Reconcile deterministic names. A retry must not create another instance or static IP.
    async fn ensure(&self, deployment: &Deployment) -> anyhow::Result<Deployment>;
    async fn discover(&self, deployment: &Deployment) -> anyhow::Result<Deployment>;
    async fn destroy(&self, deployment: &Deployment) -> anyhow::Result<()>;
    async fn status(&self, deployment: &Deployment) -> anyhow::Result<IngressStatus>;
    async fn reachable(&self, deployment: &Deployment) -> anyhow::Result<bool>;
}

pub struct Lifecycle {
    store: Arc<StateStore>,
    cloud: Arc<dyn Provisioner>,
    regions: Vec<String>,
    lock: Arc<Mutex<()>>,
    grace_s: i64,
}
impl Lifecycle {
    pub fn new(
        store: Arc<StateStore>,
        cloud: Arc<dyn Provisioner>,
        regions: Vec<String>,
        grace_s: i64,
    ) -> Self {
        Self {
            store,
            cloud,
            regions,
            lock: Arc::new(Mutex::new(())),
            grace_s,
        }
    }
    pub async fn initialize(&self, cfg: &Config) -> anyhow::Result<()> {
        if self.store.snapshot().await.lifecycle.is_some() {
            return Ok(());
        }
        // Adoption is explicit: never silently treat all configured targets as disposable.
        let active = if cfg.lifecycle.adopt_existing {
            let snapshot = self.store.snapshot().await;
            let target = snapshot
                .active_target_id
                .as_ref()
                .and_then(|id| cfg.targets.iter().find(|t| &t.id == id))
                .or_else(|| cfg.targets.first())
                .ok_or_else(|| anyhow::anyhow!("no existing ingress to adopt"))?;
            let region = target
                .provider
                .aws_region
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing adoption region"))?;
            anyhow::ensure!(
                self.regions.contains(&region),
                "existing region is not allowed for lifecycle"
            );
            let deployment = Deployment {
                id: "adopted".into(),
                region,
                instance: target
                    .provider
                    .instance
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("missing adoption instance"))?,
                static_ip: None,
                public_ip: None,
                managed: true,
            };
            Some(self.cloud.discover(&deployment).await?)
        } else {
            None
        };
        self.store
            .durable_update(|s| {
                s.lifecycle = Some(LifecycleState {
                    active,
                    ..Default::default()
                })
            })
            .await
    }
    pub async fn view(&self) -> View {
        let state = self.store.snapshot().await.lifecycle.unwrap_or_default();
        View {
            enabled: true,
            regions: self.regions.clone(),
            active: state.active,
            cleanup_pending: state.cleanup_pending,
            job: state.job,
        }
    }
    pub async fn status(&self) -> anyhow::Result<IngressStatus> {
        match self.store.snapshot().await.lifecycle.and_then(|s| s.active) {
            Some(d) => self.cloud.status(&d).await,
            None => Ok(IngressStatus {
                state: "absent".into(),
                public_ip: None,
            }),
        }
    }
    pub async fn submit(
        self: &Arc<Self>,
        region: Option<String>,
        actor: String,
    ) -> Result<Job, ApiError> {
        let _guard = self.lock.try_lock().map_err(|_| ApiError::Conflict)?;
        let state = self.store.snapshot().await.lifecycle.unwrap_or_default();
        if state.job.as_ref().is_some_and(Job::unfinished) || !state.cleanup_pending.is_empty() {
            return Err(ApiError::Conflict);
        }
        if let Some(region) = &region {
            if !self.regions.contains(region) {
                return Err(ApiError::BadRequest("region is not allowed"));
            }
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let candidate = region.map(|region| Deployment {
            id: id.clone(),
            region,
            instance: format!("vpn-ondemand-{id}"),
            static_ip: Some(format!("vpn-orchestrator-{id}")),
            public_ip: None,
            managed: true,
        });
        let job = Job {
            id,
            stage: if candidate.is_some() {
                Stage::Creating
            } else {
                Stage::Cleaning
            },
            candidate,
            started_at: unix_now(),
            ready: false,
            ready_at: None,
            cleanup_after: None,
            error: None,
            actor,
        };
        self.store
            .durable_update(|s| {
                let state = s.lifecycle.get_or_insert_with(Default::default);
                if job.candidate.is_none() {
                    if let Some(active) = state.active.take() {
                        state.cleanup_pending.push(active);
                    }
                }
                state.job = Some(job.clone());
            })
            .await
            .map_err(ApiError::internal)?;
        drop(_guard);
        self.wake();
        Ok(job)
    }
    /// Explicit retry never loses the inventory of chargeable resources.
    pub async fn retry(self: &Arc<Self>) -> Result<(), ApiError> {
        let _guard = self.lock.try_lock().map_err(|_| ApiError::Conflict)?;
        self.store
            .durable_update(|s| {
                if let Some(state) = &mut s.lifecycle {
                    if let Some(job) = &mut state.job {
                        if job.stage == Stage::Failed && !state.cleanup_pending.is_empty() {
                            job.stage = Stage::Cleaning;
                            job.error = None;
                        }
                    }
                }
            })
            .await
            .map_err(ApiError::internal)?;
        drop(_guard);
        self.wake();
        Ok(())
    }
    pub fn wake(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let Ok(_guard) = Arc::clone(&this.lock).try_lock_owned() else {
                return;
            };
            if let Err(error) = this.run().await {
                tracing::error!(error = %error, "lifecycle job stopped; resource inventory retained");
            }
        });
    }
    pub async fn report_ready(&self, id: &str) -> anyhow::Result<()> {
        let snap = self.store.snapshot().await;
        if !snap
            .lifecycle
            .as_ref()
            .and_then(|s| s.job.as_ref())
            .is_some_and(|j| {
                (!j.ready || j.ready_at.is_none_or(|at| unix_now() - at >= 30))
                    && j.candidate.as_ref().is_some_and(|d| d.id == id)
                    && matches!(j.stage, Stage::Creating | Stage::WaitingReady)
            })
        {
            return Ok(());
        }
        self.store
            .durable_update(|s| {
                if let Some(job) = s.lifecycle.as_mut().and_then(|s| s.job.as_mut()) {
                    if job.candidate.as_ref().is_some_and(|d| d.id == id) {
                        job.ready = true;
                        job.ready_at = Some(unix_now());
                    }
                }
            })
            .await
    }
    async fn change(&self, f: impl FnOnce(&mut LifecycleState)) -> anyhow::Result<()> {
        self.store
            .durable_update(|s| f(s.lifecycle.get_or_insert_with(Default::default)))
            .await
    }
    async fn fail_candidate(&self, candidate: Deployment, message: &str) -> anyhow::Result<()> {
        self.change(|s| {
            if !s.cleanup_pending.iter().any(|d| d.id == candidate.id) {
                s.cleanup_pending.push(candidate);
            }
            if let Some(j) = &mut s.job {
                j.stage = Stage::Cleaning;
                j.error = Some(message.into());
            }
        })
        .await
    }
    async fn run(&self) -> anyhow::Result<()> {
        loop {
            let state = self.store.snapshot().await.lifecycle.unwrap_or_default();
            let Some(job) = state.job else {
                return Ok(());
            };
            match job.stage {
                Stage::Creating => {
                    let candidate = job
                        .candidate
                        .ok_or_else(|| anyhow::anyhow!("missing candidate"))?;
                    // An uncertain AWS response is retried using the same resource names. After
                    // the deadline, cleanup is attempted even if creation was never acknowledged.
                    match self.cloud.ensure(&candidate).await {
                        Ok(candidate) => {
                            self.change(|s| {
                                if let Some(j) = &mut s.job {
                                    j.candidate = Some(candidate);
                                    j.stage = Stage::WaitingReady;
                                }
                            })
                            .await?
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "provisioning attempt failed");
                            if unix_now() - job.started_at >= 900 {
                                self.fail_candidate(
                                    candidate,
                                    "Provisioning failed; replacement cleanup requested.",
                                )
                                .await?;
                            } else {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            }
                        }
                    }
                }
                Stage::WaitingReady => {
                    let candidate = job
                        .candidate
                        .ok_or_else(|| anyhow::anyhow!("missing candidate"))?;
                    if job.ready
                        && job.ready_at.is_some_and(|at| unix_now() - at < 120)
                        && self.cloud.reachable(&candidate).await.unwrap_or(false)
                    {
                        self.change(|s| {
                            if let Some(old) = s.active.replace(candidate) {
                                s.cleanup_pending.push(old);
                            }
                            if let Some(j) = &mut s.job {
                                j.stage = Stage::Reconnect;
                                j.cleanup_after = Some(unix_now() + self.grace_s);
                            }
                        })
                        .await?;
                    } else if unix_now() - job.started_at >= 1200 {
                        self.fail_candidate(
                            candidate,
                            "Replacement did not become ready; original server retained.",
                        )
                        .await?;
                    } else {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                Stage::Reconnect => {
                    if unix_now() >= job.cleanup_after.unwrap_or(0) {
                        self.change(|s| {
                            if let Some(j) = &mut s.job {
                                j.stage = Stage::Cleaning;
                            }
                        })
                        .await?;
                    } else {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                Stage::Cleaning => {
                    if let Some(deployment) = state.cleanup_pending.first() {
                        if let Err(e) = self.cloud.destroy(deployment).await {
                            tracing::error!(error = %e, "cleanup failed; resources may still be billed");
                            self.change(|s| { if let Some(j) = &mut s.job { j.stage = Stage::Failed; j.error = Some("Cleanup failed. Resources may still be billed. Retry cleanup.".into()); } }).await?;
                            return Ok(());
                        }
                        self.change(|s| s.cleanup_pending.retain(|d| d.id != deployment.id))
                            .await?;
                    } else {
                        self.change(|s| {
                            if let Some(j) = &mut s.job {
                                j.stage = if j.error.is_some() {
                                    Stage::Failed
                                } else {
                                    Stage::Complete
                                };
                            }
                        })
                        .await?;
                        self.store
                            .record(
                                EventAction::Switch,
                                None,
                                "on-demand ingress job finished".into(),
                                job.actor,
                            )
                            .await?;
                    }
                }
                Stage::Failed | Stage::Complete => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    };
    #[derive(Default)]
    struct Cloud {
        destroyed: StdMutex<Vec<String>>,
        fail_destroy: AtomicBool,
        fail_create: AtomicBool,
    }
    #[async_trait]
    impl Provisioner for Cloud {
        async fn ensure(&self, d: &Deployment) -> anyhow::Result<Deployment> {
            anyhow::ensure!(
                !self.fail_create.load(Ordering::Relaxed),
                "creation response lost"
            );
            let mut d = d.clone();
            d.public_ip = Some(Ipv4Addr::new(203, 0, 113, 12));
            Ok(d)
        }
        async fn discover(&self, d: &Deployment) -> anyhow::Result<Deployment> {
            Ok(d.clone())
        }
        async fn destroy(&self, d: &Deployment) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.fail_destroy.load(Ordering::Relaxed),
                "cleanup unavailable"
            );
            self.destroyed.lock().unwrap().push(d.id.clone());
            Ok(())
        }
        async fn status(&self, d: &Deployment) -> anyhow::Result<IngressStatus> {
            Ok(IngressStatus {
                state: "running".into(),
                public_ip: d.public_ip,
            })
        }
        async fn reachable(&self, _: &Deployment) -> anyhow::Result<bool> {
            Ok(true)
        }
    }
    fn deployment(id: &str) -> Deployment {
        Deployment {
            id: id.into(),
            region: "ap-east-1".into(),
            instance: format!("vpn-ondemand-{id}"),
            static_ip: Some(format!("vpn-orchestrator-{id}")),
            public_ip: None,
            managed: true,
        }
    }
    fn job(stage: Stage) -> Job {
        Job {
            id: "job".into(),
            stage,
            candidate: Some(deployment("new")),
            started_at: unix_now(),
            ready: true,
            ready_at: Some(unix_now()),
            cleanup_after: Some(0),
            error: None,
            actor: "test".into(),
        }
    }
    async fn seed(store: &StateStore, stage: Stage) {
        store
            .durable_update(|s| {
                s.lifecycle = Some(LifecycleState {
                    active: Some(deployment("old")),
                    cleanup_pending: vec![],
                    job: Some(job(stage)),
                })
            })
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn absent_ingress_has_no_stale_subscription_ip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let worker = Lifecycle::new(store, Arc::new(Cloud::default()), vec![], 0);
        let status = worker.status().await.unwrap();
        assert_eq!(status.state, "absent");
        assert_eq!(status.public_ip, None);
    }

    #[tokio::test]
    async fn region_allowlist_and_operation_lock_reject_before_provisioning() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        let worker = Arc::new(Lifecycle::new(store, cloud, vec!["ap-east-1".into()], 0));
        assert!(matches!(
            worker
                .submit(Some("us-east-1".into()), "alice".into())
                .await,
            Err(ApiError::BadRequest(_))
        ));
        let _guard = worker.lock.lock().await;
        assert!(matches!(
            worker
                .submit(Some("ap-east-1".into()), "alice".into())
                .await,
            Err(ApiError::Conflict)
        ));
    }

    #[tokio::test]
    async fn readiness_timeout_does_not_activate_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        seed(&store, Stage::WaitingReady).await;
        store
            .durable_update(|s| {
                let job = s.lifecycle.as_mut().unwrap().job.as_mut().unwrap();
                job.ready = false;
                job.started_at -= 1201;
            })
            .await
            .unwrap();
        let worker = Lifecycle::new(store, cloud.clone(), vec![], 0);
        worker.run().await.unwrap();
        assert_eq!(worker.view().await.active.unwrap().id, "old");
        assert_eq!(*cloud.destroyed.lock().unwrap(), vec!["new"]);
    }

    #[tokio::test]
    async fn replacement_is_activated_before_old_server_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        seed(&store, Stage::Creating).await;
        let worker = Lifecycle::new(store.clone(), cloud.clone(), vec!["ap-east-1".into()], 0);
        worker.run().await.unwrap();
        let view = worker.view().await;
        assert_eq!(view.active.unwrap().id, "new");
        assert!(view.cleanup_pending.is_empty());
        assert_eq!(view.job.unwrap().stage, Stage::Complete);
        assert_eq!(*cloud.destroyed.lock().unwrap(), vec!["old"]);
    }
    #[tokio::test]
    async fn failed_creation_cleans_uncertain_candidate_and_retains_original() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        cloud.fail_create.store(true, Ordering::Relaxed);
        seed(&store, Stage::Creating).await;
        store
            .durable_update(|s| {
                s.lifecycle
                    .as_mut()
                    .unwrap()
                    .job
                    .as_mut()
                    .unwrap()
                    .started_at -= 901
            })
            .await
            .unwrap();
        let worker = Lifecycle::new(store, cloud.clone(), vec![], 0);
        worker.run().await.unwrap();
        assert_eq!(worker.view().await.active.unwrap().id, "old");
        assert_eq!(*cloud.destroyed.lock().unwrap(), vec!["new"]);
        assert_eq!(worker.view().await.job.unwrap().stage, Stage::Failed);
    }
    #[tokio::test]
    async fn cleanup_failure_survives_restart_and_can_resume() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        seed(&store, Stage::WaitingReady).await;
        cloud.fail_destroy.store(true, Ordering::Relaxed);
        let worker = Lifecycle::new(store.clone(), cloud.clone(), vec![], 0);
        worker.run().await.unwrap();
        assert_eq!(worker.view().await.job.unwrap().stage, Stage::Failed);
        drop(worker);
        drop(store);
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        assert_eq!(
            store.snapshot().await.lifecycle.unwrap().cleanup_pending[0].id,
            "old"
        );
        cloud.fail_destroy.store(false, Ordering::Relaxed);
        store
            .durable_update(|s| {
                s.lifecycle.as_mut().unwrap().job.as_mut().unwrap().stage = Stage::Cleaning
            })
            .await
            .unwrap();
        let worker = Lifecycle::new(store, cloud.clone(), vec![], 0);
        worker.run().await.unwrap();
        assert!(worker.view().await.cleanup_pending.is_empty());
        assert_eq!(worker.view().await.active.unwrap().id, "new");
    }
    #[tokio::test]
    async fn another_deployments_report_cannot_mark_candidate_ready() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        seed(&store, Stage::WaitingReady).await;
        store
            .durable_update(|s| s.lifecycle.as_mut().unwrap().job.as_mut().unwrap().ready = false)
            .await
            .unwrap();
        let worker = Lifecycle::new(store.clone(), Arc::new(Cloud::default()), vec![], 0);
        worker.report_ready("old").await.unwrap();
        assert!(!worker.view().await.job.unwrap().ready);
        worker.report_ready("new").await.unwrap();
        assert!(worker.view().await.job.unwrap().ready);
    }
    #[tokio::test]
    async fn reconnect_stage_is_resumed_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        seed(&store, Stage::Reconnect).await;
        store
            .durable_update(|s| {
                let state = s.lifecycle.as_mut().unwrap();
                state.active = Some(deployment("new"));
                state.cleanup_pending.push(deployment("old"));
            })
            .await
            .unwrap();
        drop(store);
        let store = Arc::new(StateStore::open(dir.path()).unwrap());
        let cloud = Arc::new(Cloud::default());
        let worker = Lifecycle::new(store, cloud.clone(), vec![], 0);
        worker.run().await.unwrap();
        assert_eq!(*cloud.destroyed.lock().unwrap(), vec!["old"]);
    }
}
