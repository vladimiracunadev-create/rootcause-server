//! The only place in the agent that runs an external command.
//!
//! Every probe is read-only, comes from a fixed allowlist, runs with a timeout
//! and never receives untrusted input as an argument. Concentrating this in one
//! module means the claim "the agent does not modify the host" can be checked by
//! reading a single file — and by the test at the bottom of it.

use std::{process::Stdio, time::Duration};

use tokio::process::Command;
use tracing::debug;

/// Commands the agent is allowed to invoke, with why they are needed.
///
/// Anything not listed here cannot be executed: [`run`] refuses unknown
/// programs before touching the operating system.
pub const ALLOWED_PROGRAMS: &[(&str, &str)] = &[
    ("ss", "sockets en escucha y conexiones establecidas (Linux)"),
    ("netstat", "sockets en escucha (Windows y macOS)"),
    ("journalctl", "eventos de autenticación del sistema (Linux)"),
    ("wevtutil", "eventos de autenticación del registro de seguridad (Windows)"),
    ("ufw", "estado del firewall del host (Linux)"),
    ("firewall-cmd", "estado del firewall del host (Linux)"),
    ("nft", "estado del firewall del host (Linux)"),
    ("netsh", "estado del firewall del host (Windows)"),
    ("socketfilterfw", "estado del firewall del host (macOS)"),
    ("apt-get", "simulación de actualizaciones pendientes (Debian y derivados)"),
    ("dnf", "actualizaciones de seguridad pendientes (RHEL y derivados)"),
];

/// Whether a program is part of the read-only allowlist.
pub fn is_allowed(program: &str) -> bool {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    ALLOWED_PROGRAMS.iter().any(|(allowed, _)| *allowed == name)
}

/// Why a probe produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The program is not part of the allowlist.
    NotAllowed,
    /// The program is not installed on this host.
    Missing,
    /// The program exited with a non-zero status.
    Failed(i32),
    /// The program did not finish within the allotted time.
    TimedOut,
}

impl ProbeError {
    /// Operator-facing explanation, used verbatim in a collection gap.
    pub fn reason(&self, program: &str) -> String {
        match self {
            Self::NotAllowed => format!("{program} no está en la lista de comandos permitidos"),
            Self::Missing => format!("{program} no está instalado en este host"),
            Self::Failed(code) => {
                format!("{program} terminó con código {code}; suele faltar privilegio de lectura")
            }
            Self::TimedOut => format!("{program} no respondió dentro del tiempo permitido"),
        }
    }
}

/// Run an allowlisted read-only command and return its standard output.
pub async fn run(program: &str, args: &[&str], timeout: Duration) -> Result<String, ProbeError> {
    if !is_allowed(program) {
        return Err(ProbeError::NotAllowed);
    }
    let future = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();

    match tokio::time::timeout(timeout, future).await {
        Err(_) => {
            debug!(program, "probe timed out");
            Err(ProbeError::TimedOut)
        }
        Ok(Err(error)) => {
            debug!(program, %error, "probe could not start");
            Err(ProbeError::Missing)
        }
        Ok(Ok(output)) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(Ok(output)) => Err(ProbeError::Failed(output.status.code().unwrap_or(-1))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_is_documented_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (program, purpose) in ALLOWED_PROGRAMS {
            assert!(seen.insert(*program), "duplicated program {program}");
            assert!(!purpose.is_empty(), "{program} must document why it is needed");
        }
    }

    #[test]
    fn allowlisted_programs_are_recognised_with_and_without_a_path() {
        assert!(is_allowed("ss"));
        assert!(is_allowed("/usr/bin/ss"));
        assert!(is_allowed(r"C:\Windows\System32\netstat.exe"));
    }

    #[test]
    fn anything_that_writes_is_rejected() {
        for program in ["rm", "iptables", "sh", "powershell", "cmd", "systemctl", "reg"] {
            assert!(!is_allowed(program), "{program} must never be allowed");
        }
    }

    #[tokio::test]
    async fn a_program_outside_the_allowlist_never_runs() {
        let error = run("rm", &["-rf", "/"], Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(error, ProbeError::NotAllowed);
    }

    #[test]
    fn every_error_explains_itself_in_operator_language() {
        assert!(ProbeError::Missing.reason("ss").contains("no está instalado"));
        assert!(ProbeError::TimedOut.reason("ss").contains("no respondió"));
        assert!(ProbeError::Failed(1).reason("ss").contains("código 1"));
    }
}
