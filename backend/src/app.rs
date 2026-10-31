//! Application state and the server lifecycle.

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::oidc::OidcClient;
use crate::auth::session::SessionStore;
use crate::config::{Config, ProviderKind};
use crate::http::rate_limit::RateLimiter;
use crate::http::static_files::StaticFiles;
use crate::orchestrator::Orchestrator;
use crate::providers::{self, IngressProvider};
use crate::state::StateStore;

pub struct AppInner {
    pub config: Arc<Config>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub orchestrator: Arc<Orchestrator>,
    pub limiter: RateLimiter,
    pub static_files: StaticFiles,
}

/// Cheaply clonable handle to the shared application state.
#[derive(Clone)]
pub struct AppState(Arc<AppInner>);

impl Deref for AppState {
    type Target = AppInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AppState {
    /// Build the state. Performs no network I/O (OIDC discovery is lazy); opens the state store.
    pub fn new(config: Config, provider: Arc<dyn IngressProvider>) -> anyhow::Result<Self> {
        let store = Arc::new(StateStore::open(&config.state_dir)?);
        let p = &config.provider;
        let (region, instance) = match p.kind {
            ProviderKind::Fake => (
                p.aws_region.clone().unwrap_or_else(|| "local".into()),
                p.instance.clone().unwrap_or_else(|| "fake-ingress".into()),
            ),
            _ => (
                p.aws_region.clone().unwrap_or_default(),
                p.instance.clone().unwrap_or_default(),
            ),
        };
        let orchestrator = Arc::new(Orchestrator::new(
            provider,
            store,
            config.rotate_cooldown,
            p.kind.as_str(),
            &region,
            &instance,
        ));
        let sessions =
            SessionStore::new(config.session_idle_timeout, config.session_absolute_timeout);
        let oidc = OidcClient::new(&config)?;
        let static_files = StaticFiles::new(&config.static_dir);
        Ok(Self(Arc::new(AppInner {
            config: Arc::new(config),
            sessions,
            oidc,
            orchestrator,
            limiter: RateLimiter::default(),
            static_files,
        })))
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}

fn log_startup(cfg: &Config) {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        bind_addr = %cfg.bind_addr,
        public_base_url = %cfg.public_base_url,
        oidc_issuer = %cfg.oidc.issuer_url,
        provider = cfg.provider.kind.as_str(),
        wireguard = cfg.wireguard.enabled,
        trust_proxy_headers = cfg.trust_proxy_headers,
        "starting vpn-control"
    );
    if !cfg.trust_proxy_headers {
        tracing::warn!(
            "TRUST_PROXY_HEADERS=false: rate limits key on the TCP peer. Behind the reverse proxy (Apache) set TRUST_PROXY_HEADERS=true."
        );
    }
    if !cfg.static_dir.join("index.html").is_file() {
        tracing::warn!(static_dir = %cfg.static_dir.display(), "STATIC_DIR has no index.html; the web UI will 404");
    }
}

/// Run the server until SIGTERM / Ctrl-C.
pub async fn run(config: Config) -> anyhow::Result<()> {
    log_startup(&config);
    let provider = providers::build(&config).await?;
    let state = AppState::new(config, provider)?;
    let app = crate::http::router(state.clone());

    let listener = tokio::net::TcpListener::bind(state.config.bind_addr).await?;
    tracing::info!(addr = %state.config.bind_addr, "listening");

    let janitor_state = state.clone();
    let janitor = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            janitor_state.sessions.purge_expired();
            janitor_state.limiter.purge(Instant::now());
        }
    });

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    janitor.abort();
    if !state.orchestrator.wait_idle(Duration::from_secs(25)).await {
        tracing::warn!("an ingress operation was still running at shutdown");
    }
    tracing::info!("stopped");
    Ok(())
}
