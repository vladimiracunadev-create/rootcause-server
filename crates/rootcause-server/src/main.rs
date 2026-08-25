//! RootCause Server: the control plane that defends a fleet of servers.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use rootcause_core::{DetectionEngine, RULES, policy::DetectionPolicy};
use rootcause_server::{
    api,
    config::{Cli, Command, PolicyArgs, ServeSettings},
    state::AppState,
    storage::Database,
    watchdog,
};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Token => {
            println!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            Ok(())
        }
        Command::Rules => {
            print_rules();
            Ok(())
        }
        Command::Policy(args) => print_policy(&args),
        Command::Serve(settings) => run(*settings).await,
    }
}

fn print_rules() {
    println!("{:<38} {:<16} PREGUNTA QUE RESPONDE", "REGLA", "CATEGORÍA");
    for rule in RULES {
        println!("{:<38} {:<16} {}", rule.id, rule.category.as_str(), rule.question);
    }
    println!("\n{} reglas publicadas en esta versión.", RULES.len());
}

fn print_policy(args: &PolicyArgs) -> anyhow::Result<()> {
    let policy = match &args.file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("no se pudo leer {}", path.display()))?;
            let policy: DetectionPolicy = serde_json::from_str(&raw)
                .with_context(|| format!("{} no es una política JSON válida", path.display()))?;
            policy.validate().map_err(|error| anyhow::anyhow!("política inválida: {error}"))?;
            policy
        }
        None => DetectionPolicy::default(),
    };
    println!("{}", serde_json::to_string_pretty(&policy)?);
    Ok(())
}

async fn run(settings: ServeSettings) -> anyhow::Result<()> {
    init_tracing(settings.json_logs);
    settings.validate()?;

    let policy = settings.detection_policy()?;
    let engine = DetectionEngine::new(policy)
        .map_err(|error| anyhow::anyhow!("no se pudo construir el motor de detección: {error}"))?;
    let database = Database::connect(&settings.database_url)
        .await
        .context("no se pudo inicializar el almacenamiento de RootCause")?;

    let state = AppState::new(database, engine, &settings);
    let app = api::router(state.clone());
    let listener = TcpListener::bind(settings.bind)
        .await
        .with_context(|| format!("no se pudo enlazar RootCause Server a {}", settings.bind))?;

    announce(&settings);
    tokio::spawn(watchdog::run(state));

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("RootCause Server se detuvo de forma inesperada")
}

/// Say out loud what the running configuration actually protects.
fn announce(settings: &ServeSettings) {
    if settings.api_token.is_none() {
        warn!("modo de desarrollo inseguro: la API no exige token y solo escucha en loopback");
    }
    if !settings.bind.ip().is_loopback() {
        warn!(
            address = %settings.bind,
            "el servidor escucha fuera de loopback: publícalo únicamente detrás de TLS y de una red controlada"
        );
    }
    info!(
        address = %settings.bind,
        database = %settings.database_url,
        detectors = RULES.len(),
        rate_limit_per_minute = settings.rate_limit_per_minute,
        lockout_threshold = settings.lockout_threshold,
        retention_days = settings.retention_days,
        "RootCause Server listo"
    );
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_env("ROOTCAUSE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("rootcause_server=info,tower_http=warn"));
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
            warn!(%error, "no se pudo instalar el manejador de Ctrl+C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                warn!(%error, "no se pudo instalar el manejador de terminación");
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
    info!("señal de apagado recibida");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_rule_catalog_is_not_empty() {
        assert!(RULES.len() >= 15, "the product claims a rule catalog; keep it real");
    }

    #[test]
    fn the_default_policy_is_printable_and_reloadable() {
        let rendered = serde_json::to_string_pretty(&DetectionPolicy::default()).unwrap();
        let parsed: DetectionPolicy = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed, DetectionPolicy::default());
    }
}
