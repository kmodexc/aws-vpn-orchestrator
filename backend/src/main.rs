#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use vpn_control::cli::{Cli, Command, gen_env, healthcheck};
use vpn_control::config::{Config, LogFormat};

fn init_tracing() {
    // LOG_FORMAT is read directly so that configuration errors are logged in the right format.
    let format = match std::env::var("LOG_FORMAT")
        .map(|v| v.trim().to_ascii_lowercase())
        .as_deref()
    {
        Ok("pretty") => LogFormat::Pretty,
        _ => LogFormat::Json,
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .init(),
        LogFormat::Pretty => builder.init(),
    }
}

fn serve() -> ExitCode {
    init_tracing();
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            // Names the variable, never its value.
            tracing::error!(variable = e.var, reason = %e.reason, "invalid configuration; refusing to start");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(vpn_control::app::run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "server failed");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(),
        Command::GenEnv => match gen_env::render() {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("gen-env failed: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Healthcheck => {
            if healthcheck::run() == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
