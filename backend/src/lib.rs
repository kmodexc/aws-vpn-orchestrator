//! `vpn-control`: control plane for a disposable sing-box ingress server on AWS.
//!
//! See `docs/SPEC.md` in the repository root for the binding specification.

#![forbid(unsafe_code)]

pub mod app;
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod http;
pub mod orchestrator;
pub mod providers;
pub mod secret;
pub mod settings;
pub mod singbox;
pub mod state;
pub mod telemetry;
pub mod util;

pub use app::AppState;
pub use config::Config;
