//! Command line and environment contract of the control plane.
//!
//! Every setting that weakens the default posture has to be typed out by an
//! operator: there is no configuration file that can silently open the server
//! to the network, and `validate` refuses the combinations that would.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use rootcause_core::policy::DetectionPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "rootcause-server",
    version,
    about = "Plano de control de RootCause: defensa, correlación y evidencia para servidores",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the API and the embedded console.
    Serve(Box<ServeSettings>),
    /// Generate a high-entropy API token.
    Token,
    /// Print the detection policy in force, ready to be versioned.
    Policy(PolicyArgs),
    /// Print the rule catalog this build implements.
    Rules,
}

#[derive(Debug, Clone, Args)]
pub struct PolicyArgs {
    /// Policy file to validate instead of printing the built-in defaults.
    #[arg(long)]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ServeSettings {
    /// Address used by the HTTP listener.
    #[arg(long, env = "ROOTCAUSE_BIND", default_value = "127.0.0.1:8080")]
    pub bind: SocketAddr,

    /// SQLite URL. Example: sqlite://rootcause.db
    #[arg(long, env = "ROOTCAUSE_DATABASE_URL", default_value = "sqlite://rootcause.db")]
    pub database_url: String,

    /// Shared bearer token used by the console and the agents.
    #[arg(long, env = "ROOTCAUSE_API_TOKEN", hide_env_values = true)]
    pub api_token: Option<String>,

    /// Allow a tokenless, loopback-only development instance.
    #[arg(long, env = "ROOTCAUSE_INSECURE_DEV_MODE", default_value_t = false)]
    pub insecure_dev_mode: bool,

    /// Emit structured JSON logs.
    #[arg(long, env = "ROOTCAUSE_JSON_LOGS", default_value_t = false)]
    pub json_logs: bool,

    /// Requests accepted per client address per minute.
    #[arg(
        long,
        env = "ROOTCAUSE_RATE_LIMIT_PER_MINUTE",
        default_value_t = 600,
        value_parser = clap::value_parser!(u32).range(10..=100_000)
    )]
    pub rate_limit_per_minute: u32,

    /// Failed authentications from one address before it is locked out.
    #[arg(
        long,
        env = "ROOTCAUSE_LOCKOUT_THRESHOLD",
        default_value_t = 10,
        value_parser = clap::value_parser!(u32).range(3..=1_000)
    )]
    pub lockout_threshold: u32,

    /// Seconds an address stays locked out after crossing the threshold.
    #[arg(
        long,
        env = "ROOTCAUSE_LOCKOUT_SECONDS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(30..=86_400)
    )]
    pub lockout_seconds: u64,

    /// Days of telemetry, authentication pressure and defence events kept.
    #[arg(
        long,
        env = "ROOTCAUSE_RETENTION_DAYS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u32).range(1..=3_650)
    )]
    pub retention_days: u32,

    /// Seconds between agent cycles, used to decide when an agent went silent.
    #[arg(
        long,
        env = "ROOTCAUSE_AGENT_INTERVAL_SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(5..=3_600)
    )]
    pub agent_interval_seconds: u64,

    /// Trust `X-Forwarded-For` because a reverse proxy terminates TLS in front.
    ///
    /// Off by default: trusting the header without a proxy lets any client
    /// choose the address that gets rate limited and locked out.
    #[arg(long, env = "ROOTCAUSE_TRUST_FORWARDED_FOR", default_value_t = false)]
    pub trust_forwarded_for: bool,

    /// JSON detection policy replacing the built-in thresholds.
    #[arg(long, env = "ROOTCAUSE_POLICY_FILE")]
    pub policy_file: Option<PathBuf>,

    /// Maximum accepted request body, in kibibytes.
    #[arg(
        long,
        env = "ROOTCAUSE_MAX_BODY_KIB",
        default_value_t = 1024,
        value_parser = clap::value_parser!(u64).range(16..=16_384)
    )]
    pub max_body_kib: u64,
}

impl ServeSettings {
    /// Refuse a configuration that only looks secure.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.database_url.starts_with("sqlite:") {
            bail!("el almacenamiento 0.2 requiere una URL sqlite:");
        }
        self.database_url
            .parse::<sqlx::sqlite::SqliteConnectOptions>()
            .context("URL de base de datos SQLite inválida")?;

        match &self.api_token {
            Some(token) if token.trim().len() < 32 => {
                bail!("ROOTCAUSE_API_TOKEN debe contener al menos 32 caracteres")
            }
            Some(token) if token.trim() != token => {
                bail!("ROOTCAUSE_API_TOKEN no debe empezar ni terminar con espacios")
            }
            Some(_) => {}
            None if !self.insecure_dev_mode => {
                bail!("falta ROOTCAUSE_API_TOKEN; genera uno con `rootcause-server token`")
            }
            None if !self.bind.ip().is_loopback() => bail!(
                "el modo de desarrollo inseguro solo puede escuchar en una dirección de loopback"
            ),
            None => {}
        }

        if self.trust_forwarded_for && self.bind.ip().is_loopback() {
            // Not fatal, but worth refusing the obviously wrong combination:
            // a loopback listener has no proxy in front of it.
            bail!(
                "--trust-forwarded-for solo tiene sentido detrás de un proxy inverso; el enlace actual es loopback"
            );
        }
        Ok(())
    }

    /// Load the detection policy, falling back to the audited defaults.
    pub fn detection_policy(&self) -> anyhow::Result<DetectionPolicy> {
        let Some(path) = &self.policy_file else {
            return Ok(DetectionPolicy::default());
        };
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("no se pudo leer la política {}", path.display()))?;
        let policy: DetectionPolicy = serde_json::from_str(&raw)
            .with_context(|| format!("la política {} no es JSON válido", path.display()))?;
        policy.validate().map_err(|error| anyhow::anyhow!("política inválida: {error}"))?;
        Ok(policy)
    }

    pub fn max_body_bytes(&self) -> usize {
        (self.max_body_kib * 1024) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ServeSettings {
        ServeSettings {
            bind: "127.0.0.1:8080".parse().unwrap(),
            database_url: "sqlite://rootcause.db".to_owned(),
            api_token: Some("a".repeat(32)),
            insecure_dev_mode: false,
            json_logs: false,
            rate_limit_per_minute: 600,
            lockout_threshold: 10,
            lockout_seconds: 300,
            retention_days: 30,
            agent_interval_seconds: 30,
            trust_forwarded_for: false,
            policy_file: None,
            max_body_kib: 1024,
        }
    }

    #[test]
    fn a_sane_configuration_is_accepted() {
        assert!(settings().validate().is_ok());
    }

    #[test]
    fn a_short_token_is_refused() {
        let settings = ServeSettings { api_token: Some("corto".to_owned()), ..settings() };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn a_padded_token_is_refused_before_it_causes_a_mismatch() {
        let settings =
            ServeSettings { api_token: Some(format!(" {} ", "a".repeat(32))), ..settings() };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn no_token_is_only_allowed_on_loopback_and_on_purpose() {
        let missing = ServeSettings { api_token: None, ..settings() };
        assert!(missing.validate().is_err(), "a tokenless instance must be explicit");

        let dev = ServeSettings { api_token: None, insecure_dev_mode: true, ..settings() };
        assert!(dev.validate().is_ok());

        let exposed = ServeSettings {
            api_token: None,
            insecure_dev_mode: true,
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..settings()
        };
        assert!(exposed.validate().is_err(), "dev mode must never listen off loopback");
    }

    #[test]
    fn a_non_sqlite_url_is_refused() {
        let settings =
            ServeSettings { database_url: "postgres://localhost/rc".to_owned(), ..settings() };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn trusting_forwarded_headers_without_a_proxy_is_refused() {
        let on_loopback = ServeSettings { trust_forwarded_for: true, ..settings() };
        assert!(on_loopback.validate().is_err());

        let behind_proxy = ServeSettings {
            trust_forwarded_for: true,
            bind: "0.0.0.0:8080".parse().unwrap(),
            ..settings()
        };
        assert!(behind_proxy.validate().is_ok());
    }

    #[test]
    fn the_default_policy_is_used_when_no_file_is_given() {
        assert_eq!(settings().detection_policy().unwrap(), DetectionPolicy::default());
    }

    #[test]
    fn an_invalid_policy_file_stops_the_server_instead_of_being_ignored() {
        let path = std::env::temp_dir().join("rootcause-policy-invalid.json");
        std::fs::write(&path, r#"{"resource":{"cpu_high":99.0,"cpu_critical":10.0}}"#).unwrap();
        let settings = ServeSettings { policy_file: Some(path.clone()), ..settings() };
        assert!(settings.detection_policy().is_err());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_valid_policy_file_is_loaded() {
        let path = std::env::temp_dir().join("rootcause-policy-valid.json");
        std::fs::write(&path, r#"{"public_allowlist":[8443]}"#).unwrap();
        let settings = ServeSettings { policy_file: Some(path.clone()), ..settings() };
        let policy = settings.detection_policy().unwrap();
        assert_eq!(policy.public_allowlist, vec![8443]);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn the_body_limit_is_expressed_in_bytes() {
        assert_eq!(settings().max_body_bytes(), 1024 * 1024);
    }

    #[test]
    fn the_command_line_contract_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
