mod collector;

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, bail};
use clap::Parser;
use collector::Collector;
use reqwest::{Client, Url};
use rootcause_core::{AssetRegistration, PROTOCOL_VERSION, Platform, TelemetryEnvelope};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "rootcause-agent",
    version,
    about = "Read-only native telemetry agent for RootCause Server"
)]
struct Cli {
    #[arg(
        long,
        env = "ROOTCAUSE_SERVER_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    server_url: Url,

    #[arg(long, env = "ROOTCAUSE_API_TOKEN", hide_env_values = true)]
    api_token: String,

    #[arg(
        long,
        env = "ROOTCAUSE_AGENT_INTERVAL_SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(5..=3600)
    )]
    interval_seconds: u64,

    #[arg(long, default_value_t = false)]
    once: bool,

    /// Explicitly allow a token to cross a non-loopback HTTP connection.
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,

    /// Asset label in key=value form. May be supplied more than once.
    #[arg(long = "label", value_parser = parse_label)]
    labels: Vec<(String, String)>,
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
        bail!("ROOTCAUSE_API_TOKEN must contain at least 32 characters");
    }

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("rootcause-agent/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let labels = cli.labels.into_iter().collect::<BTreeMap<_, _>>();
    let mut collector = Collector::new(labels);
    let registration = collector.registration();

    info!(
        agent_id = %registration.agent_id,
        hostname = %registration.hostname,
        platform = %registration.platform.as_str(),
        "RootCause agent started"
    );

    if cli.once {
        send_once(
            &client,
            &cli.server_url,
            &cli.api_token,
            &registration,
            &mut collector,
        )
        .await?;
        return Ok(());
    }

    let normal_interval = Duration::from_secs(cli.interval_seconds);
    let mut retry_interval = normal_interval;
    loop {
        match send_once(
            &client,
            &cli.server_url,
            &cli.api_token,
            &registration,
            &mut collector,
        )
        .await
        {
            Ok(()) => retry_interval = normal_interval,
            Err(error) => {
                warn!(
                    error = ?error,
                    retry_seconds = retry_interval.as_secs(),
                    "telemetry delivery failed"
                );
                retry_interval = (retry_interval * 2).min(Duration::from_secs(300));
            }
        }

        tokio::select! {
            () = tokio::time::sleep(retry_interval) => {},
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    error!(%error, "failed to listen for Ctrl+C");
                }
                info!("RootCause agent stopped");
                break;
            }
        }
    }
    Ok(())
}

async fn send_once(
    client: &Client,
    server_url: &Url,
    token: &str,
    registration: &AssetRegistration,
    collector: &mut Collector,
) -> anyhow::Result<()> {
    let register_url = endpoint(server_url, "api/v1/assets/register")?;
    client
        .post(register_url)
        .bearer_auth(token)
        .json(registration)
        .send()
        .await
        .context("asset registration request failed")?
        .error_for_status()
        .context("server rejected asset registration")?;

    let sample = collector.collect()?;
    let telemetry_url = endpoint(server_url, "api/v1/telemetry")?;
    let response = client
        .post(telemetry_url)
        .bearer_auth(token)
        .json(&TelemetryEnvelope {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            asset: Some(registration.clone()),
            sample,
        })
        .send()
        .await
        .context("telemetry request failed")?
        .error_for_status()
        .context("server rejected telemetry")?;
    let body: rootcause_core::IngestResponse = response
        .json()
        .await
        .context("invalid telemetry response")?;
    info!(incidents_touched = body.incidents_touched, "telemetry accepted");
    Ok(())
}

fn endpoint(base: &Url, path: &str) -> anyhow::Result<Url> {
    let mut normalized = base.clone();
    if !normalized.path().ends_with('/') {
        normalized.set_path(&format!("{}/", normalized.path()));
    }
    normalized.join(path).context("invalid server endpoint")
}

fn validate_transport(url: &Url, allow_insecure_http: bool) -> anyhow::Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() != "http" {
        bail!("server URL must use http or https");
    }
    let is_loopback = match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    };
    if !is_loopback && !allow_insecure_http {
        bail!(
            "refusing to send an API token over remote HTTP; use HTTPS or --allow-insecure-http"
        );
    }
    Ok(())
}

fn parse_label(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "labels must use key=value format".to_owned())?;
    if key.is_empty() || key.len() > 64 || value.len() > 256 {
        return Err("label key/value is empty or exceeds supported limits".to_owned());
    }
    Ok((key.to_owned(), value.to_owned()))
}

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

    #[test]
    fn remote_plain_http_is_rejected() {
        let url = Url::parse("http://192.0.2.10:8080").unwrap();
        assert!(validate_transport(&url, false).is_err());
    }

    #[test]
    fn localhost_plain_http_is_allowed() {
        let url = Url::parse("http://127.0.0.1:8080").unwrap();
        assert!(validate_transport(&url, false).is_ok());
    }

    #[test]
    fn stable_identifier_is_repeatable() {
        assert_eq!(stable_agent_id("host-a"), stable_agent_id("host-a"));
        assert_ne!(stable_agent_id("host-a"), stable_agent_id("host-b"));
    }
}
