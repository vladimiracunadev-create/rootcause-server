use std::net::SocketAddr;

use anyhow::{bail, Context};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rootcause-server",
    version,
    about = "RootCause cross-platform observability and diagnosis control plane",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the API and embedded web console.
    Serve(ServeSettings),
    /// Generate a high-entropy API token.
    Token,
}

#[derive(Debug, Clone, Args)]
pub struct ServeSettings {
    /// Address used by the HTTP listener.
    #[arg(long, env = "ROOTCAUSE_BIND", default_value = "127.0.0.1:8080")]
    pub bind: SocketAddr,

    /// SQLite URL. Example: sqlite://rootcause.db
    #[arg(
        long,
        env = "ROOTCAUSE_DATABASE_URL",
        default_value = "sqlite://rootcause.db"
    )]
    pub database_url: String,

    /// Shared bearer token used by the console and agents.
    #[arg(long, env = "ROOTCAUSE_API_TOKEN", hide_env_values = true)]
    pub api_token: Option<String>,

    /// Allow a tokenless local-only development instance.
    #[arg(long, env = "ROOTCAUSE_INSECURE_DEV_MODE", default_value_t = false)]
    pub insecure_dev_mode: bool,

    /// Emit structured JSON logs.
    #[arg(long, env = "ROOTCAUSE_JSON_LOGS", default_value_t = false)]
    pub json_logs: bool,
}

impl ServeSettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.database_url.starts_with("sqlite:") {
            bail!("the 0.1 storage backend requires a sqlite: database URL");
        }

        match &self.api_token {
            Some(token) if token.len() < 32 => {
                bail!("ROOTCAUSE_API_TOKEN must contain at least 32 characters")
            }
            Some(_) => {}
            None if !self.insecure_dev_mode => {
                bail!(
                    "ROOTCAUSE_API_TOKEN is required; generate one with `rootcause-server token`"
                )
            }
            None if !self.bind.ip().is_loopback() => {
                bail!("insecure development mode may only bind to a loopback address")
            }
            None => {}
        }

        self.database_url
            .parse::<sqlx::sqlite::SqliteConnectOptions>()
            .context("invalid SQLite database URL")?;
        Ok(())
    }
}
