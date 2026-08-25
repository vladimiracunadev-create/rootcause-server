//! Read-only native telemetry and security sensor for RootCause Server.
//!
//! The agent observes and reports. It never blocks an address, never edits a
//! configuration file and never runs a command outside the allowlist in
//! [`probe`]. Everything it can change on the host it runs on is: nothing.

mod authlog;
mod baseline;
mod collector;
mod integrity;
mod net;
mod probe;

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use anyhow::{Context, bail};
use clap::Parser;
use collector::{Collector, CollectorConfig};
use reqwest::{Client, Url};
use rootcause_core::{
    PROTOCOL_VERSION,
    models::{AssetRegistration, Platform, TelemetryEnvelope},
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Longest interval the agent will back off to after repeated failures.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug, Parser)]
#[command(
    name = "rootcause-agent",
    version,
    about = "Sensor nativo de solo lectura para RootCause Server",
    long_about = "Recolecta métricas de recursos y la superficie de seguridad del host \
(puertos en escucha, intentos de autenticación, integridad de archivos críticos y controles \
básicos) y los envía firmados con un token al servidor RootCause. No modifica el host."
)]
struct Cli {
    /// URL of the RootCause server.
    #[arg(long, env = "ROOTCAUSE_SERVER_URL", default_value = "http://127.0.0.1:8080")]
    server_url: Url,

    /// Shared bearer token issued by the server.
    #[arg(long, env = "ROOTCAUSE_API_TOKEN", hide_env_values = true)]
    api_token: String,

    /// Seconds between collection cycles.
    #[arg(
        long,
        env = "ROOTCAUSE_AGENT_INTERVAL_SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(5..=3600)
    )]
    interval_seconds: u64,

    /// Collect and send one cycle, then exit.
    #[arg(long, default_value_t = false)]
    once: bool,

    /// Explicitly allow a token to cross a non-loopback HTTP connection.
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,

    /// Report resource metrics only, without inspecting the security surface.
    #[arg(long, env = "ROOTCAUSE_AGENT_METRICS_ONLY", default_value_t = false)]
    metrics_only: bool,

    /// Minutes of authentication history read on every cycle.
    #[arg(
        long,
        env = "ROOTCAUSE_AGENT_AUTH_WINDOW_MINUTES",
        default_value_t = 15,
        value_parser = clap::value_parser!(u32).range(1..=1440)
    )]
    auth_window_minutes: u32,

    /// File to fingerprint on every cycle. May be supplied more than once.
    #[arg(long = "watch-file")]
    watch_files: Vec<PathBuf>,

    /// Comma-separated watch list; replaces the platform defaults.
    #[arg(long, env = "ROOTCAUSE_WATCH_FILES")]
    watch_list: Option<String>,

    /// Asset label in key=value form. May be supplied more than once.
    #[arg(long = "label", value_parser = parse_label)]
    labels: Vec<(String, String)>,

    /// Print the surface the agent would report and exit, without sending it.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl Cli {
    fn collector_config(&self) -> CollectorConfig {
        let mut watched_files = self.watch_files.clone();
        if let Some(list) = &self.watch_list {
            watched_files.extend(integrity::parse_watch_list(list));
        }
        if watched_files.is_empty() {
            watched_files = integrity::default_paths();
        }
        watched_files.sort();
        watched_files.dedup();

        CollectorConfig {
            security: !self.metrics_only,
            watched_files,
            auth_window_minutes: self.auth_window_minutes,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            EnvFilter::try_from_env("ROOTCAUSE_LOG")
                .unwrap_or_else(|_| EnvFilter::new("rootcause_agent=info")),
        )
        .init();

    let cli = Cli::parse();
    validate_transport(&cli.server_url, cli.allow_insecure_http)?;
    if cli.api_token.len() < 32 {
        bail!("ROOTCAUSE_API_TOKEN debe contener al menos 32 caracteres");
    }

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("rootcause-agent/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let labels = cli.labels.iter().cloned().collect::<BTreeMap<_, _>>();
    let config = cli.collector_config();
    let watched = config.watched_files.len();
    let mut collector = Collector::new(labels, config);
    let registration = collector.registration();

    info!(
        agent_id = %registration.agent_id,
        hostname = %registration.hostname,
        platform = registration.platform.as_str(),
        role = registration.role().as_str(),
        watched_files = watched,
        security = !cli.metrics_only,
        "sensor RootCause iniciado"
    );

    if cli.dry_run {
        return dry_run(&mut collector).await;
    }

    if cli.once {
        return send_once(&client, &cli, &registration, &mut collector).await;
    }

    let normal_interval = Duration::from_secs(cli.interval_seconds);
    let mut retry_interval = normal_interval;
    loop {
        match send_once(&client, &cli, &registration, &mut collector).await {
            Ok(()) => retry_interval = normal_interval,
            Err(error) => {
                warn!(
                    error = ?error,
                    retry_seconds = retry_interval.as_secs(),
                    "no se pudo entregar la telemetría"
                );
                retry_interval = (retry_interval * 2).min(MAX_BACKOFF);
            }
        }

        tokio::select! {
            () = tokio::time::sleep(retry_interval) => {},
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    error!(%error, "no se pudo escuchar Ctrl+C");
                }
                info!("sensor RootCause detenido");
                break;
            }
        }
    }
    Ok(())
}

/// Show exactly what would be sent, so an operator can audit it before enrolling.
async fn dry_run(collector: &mut Collector) -> anyhow::Result<()> {
    let sample = collector.sample()?;
    let security = collector.security().await;
    let envelope = TelemetryEnvelope {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        asset: Some(collector.registration()),
        sample,
        security: Some(security),
    };
    let rendered = serde_json::to_string_pretty(&envelope)
        .context("no se pudo serializar el sobre de telemetría")?;
    info!("modo de prueba: el sobre siguiente es exactamente lo que se enviaría");
    println!("{rendered}");
    Ok(())
}

async fn send_once(
    client: &Client,
    cli: &Cli,
    registration: &AssetRegistration,
    collector: &mut Collector,
) -> anyhow::Result<()> {
    let register_url = endpoint(&cli.server_url, "api/v1/assets/register")?;
    client
        .post(register_url)
        .bearer_auth(&cli.api_token)
        .json(registration)
        .send()
        .await
        .context("falló el registro del activo")?
        .error_for_status()
        .context("el servidor rechazó el registro del activo")?;

    let sample = collector.sample()?;
    let security = if cli.metrics_only { None } else { Some(collector.security().await) };
    let exposed = security
        .as_ref()
        .map(|signals| net::exposed_ports(&signals.listeners).len())
        .unwrap_or_default();

    let telemetry_url = endpoint(&cli.server_url, "api/v1/telemetry")?;
    let response = client
        .post(telemetry_url)
        .bearer_auth(&cli.api_token)
        .json(&TelemetryEnvelope {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            asset: Some(registration.clone()),
            sample,
            security,
        })
        .send()
        .await
        .context("falló el envío de telemetría")?
        .error_for_status()
        .context("el servidor rechazó la telemetría")?;

    let body: rootcause_core::models::IngestResponse =
        response.json().await.context("respuesta de telemetría inválida")?;
    for warning in &body.warnings {
        warn!(%warning, "el servidor aceptó la telemetría con observaciones");
    }
    info!(
        incidents_touched = body.incidents_touched,
        exposed_ports = exposed,
        "telemetría aceptada"
    );
    Ok(())
}

fn endpoint(base: &Url, path: &str) -> anyhow::Result<Url> {
    let mut normalized = base.clone();
    if !normalized.path().ends_with('/') {
        normalized.set_path(&format!("{}/", normalized.path()));
    }
    normalized.join(path).context("URL de servidor inválida")
}

/// Refuse to put a bearer token on the wire in the clear.
fn validate_transport(url: &Url, allow_insecure_http: bool) -> anyhow::Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() != "http" {
        bail!("la URL del servidor debe usar http o https");
    }
    let is_loopback = match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback()),
        None => false,
    };
    if !is_loopback && !allow_insecure_http {
        bail!(
            "no se enviará un token por HTTP remoto; usa HTTPS o pasa --allow-insecure-http de forma deliberada"
        );
    }
    Ok(())
}

fn parse_label(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "las etiquetas usan el formato clave=valor".to_owned())?;
    if key.is_empty() || key.len() > 64 || value.len() > 256 {
        return Err("la etiqueta está vacía o supera los límites admitidos".to_owned());
    }
    Ok((key.to_owned(), value.to_owned()))
}

/// Identifier that stays the same across restarts of the same host.
pub(crate) fn stable_agent_id(hostname: &str) -> Uuid {
    let identity = format!(
        "{}:{}:{}",
        hostname.to_lowercase(),
        Platform::current().as_str(),
        std::env::consts::ARCH
    );
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, identity.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        let token = "x".repeat(32);
        let mut full = vec!["rootcause-agent", "--api-token", token.as_str()];
        full.extend_from_slice(args);
        Cli::parse_from(full)
    }

    #[test]
    fn remote_plain_http_is_rejected() {
        let url = Url::parse("http://192.0.2.10:8080").unwrap();
        assert!(validate_transport(&url, false).is_err());
        assert!(validate_transport(&url, true).is_ok());
    }

    #[test]
    fn localhost_plain_http_is_allowed() {
        assert!(validate_transport(&Url::parse("http://127.0.0.1:8080").unwrap(), false).is_ok());
        assert!(validate_transport(&Url::parse("http://localhost:8080").unwrap(), false).is_ok());
    }

    #[test]
    fn https_is_always_allowed_and_other_schemes_never_are() {
        assert!(
            validate_transport(&Url::parse("https://rootcause.example.cl").unwrap(), false).is_ok()
        );
        assert!(
            validate_transport(&Url::parse("ftp://rootcause.example.cl").unwrap(), true).is_err()
        );
    }

    #[test]
    fn the_stable_identifier_is_repeatable_and_distinct() {
        assert_eq!(stable_agent_id("host-a"), stable_agent_id("host-a"));
        assert_eq!(stable_agent_id("HOST-A"), stable_agent_id("host-a"));
        assert_ne!(stable_agent_id("host-a"), stable_agent_id("host-b"));
    }

    #[test]
    fn labels_require_a_key_and_a_value() {
        assert_eq!(parse_label("role=edge").unwrap(), ("role".to_owned(), "edge".to_owned()));
        assert!(parse_label("role").is_err());
        assert!(parse_label("=edge").is_err());
    }

    #[test]
    fn endpoints_are_joined_below_a_base_path() {
        let base = Url::parse("https://rootcause.example.cl/panel").unwrap();
        let joined = endpoint(&base, "api/v1/telemetry").unwrap();
        assert_eq!(joined.as_str(), "https://rootcause.example.cl/panel/api/v1/telemetry");
    }

    #[test]
    fn the_default_watch_list_is_used_when_the_operator_supplies_none() {
        let config = cli(&[]).collector_config();
        let mut expected = integrity::default_paths();
        expected.sort();
        assert_eq!(config.watched_files, expected);
        assert!(config.security);
    }

    #[test]
    fn an_operator_watch_list_replaces_the_defaults_without_duplicates() {
        let config =
            cli(&["--watch-file", "/etc/hosts", "--watch-list", "/etc/hosts,/srv/app/.env"])
                .collector_config();
        assert_eq!(
            config.watched_files,
            vec![PathBuf::from("/etc/hosts"), PathBuf::from("/srv/app/.env")]
        );
    }

    #[test]
    fn metrics_only_disables_the_security_surface() {
        assert!(!cli(&["--metrics-only"]).collector_config().security);
    }

    #[test]
    fn the_command_line_contract_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
