//! Command line interface: `serve` (default), `gen-env`, `healthcheck`.

pub mod gen_env;
pub mod healthcheck;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "vpn-control",
    version,
    about = "Control plane for a disposable sing-box ingress server on AWS"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Command {
    /// Run the HTTP server (default).
    Serve,
    /// Print a complete .env with freshly generated secrets to stdout.
    GenEnv,
    /// Probe http://127.0.0.1:<BIND_ADDR port>/healthz; exit 0 on HTTP 200, else 1.
    Healthcheck,
}
