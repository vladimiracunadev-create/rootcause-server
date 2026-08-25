mod api;
mod auth;
mod config;
mod error;
mod state;
mod storage;
mod ui;

use anyhow::Context;
use clap::Parser;
use config::{Cli, Command};
use state::AppState;
use storage::Database;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Token => {
            println!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            Ok(())
        }
        Command::Serve(settings) => run(settings).await,
    }
}

async fn run(settings: config::ServeSettings) -> anyhow::Result<()> {
    init_tracing(settings.json_logs);
    settings.validate()?;

    let database = Database::connect(&settings.database_url)
        .await
        .context("failed to initialize RootCause storage")?;
    let state = AppState::new(database, settings.api_token.clone());
    let app = api::router(state);
    let listener = TcpListener::bind(settings.bind)
        .await
        .with_context(|| format!("failed to bind RootCause Server to {}", settings.bind))?;

    if settings.api_token.is_none() {
        warn!("insecure development mode enabled; the API is only available on loopback");
    }
    info!(
        address = %settings.bind,
        database = %settings.database_url,
        "RootCause Server is ready"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("RootCause Server stopped unexpectedly")
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_env("ROOTCAUSE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("rootcause_server=info,tower_http=info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.compact().init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                warn!(%error, "failed to install termination handler");
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
    info!("shutdown signal received");
}
