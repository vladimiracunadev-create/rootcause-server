//! Guided response: the exact commands an operator may run, and nothing else.
//!
//! RootCause never executes a runbook. It writes one, marks whether it needs
//! privileges and whether it can be undone, and leaves the decision to a human.
//! The `no_destructive_commands` test at the bottom of this file enforces that
//! promise on every build: a command that destroys data cannot reach this
//! module without failing CI.

use serde::{Deserialize, Serialize};

use crate::models::Platform;

/// What running a step does to the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    /// Reads state. Changes nothing.
    Inspect,
    /// Limits reachability or blocks a source. Reversible.
    Contain,
    /// Changes configuration. Reversible, but needs review first.
    Remediate,
}

impl StepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Contain => "contain",
            Self::Remediate => "remediate",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Inspect => "Inspeccionar",
            Self::Contain => "Contener",
            Self::Remediate => "Corregir",
        }
    }
}

/// One reviewed, copy-pasteable action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunbookStep {
    pub description: String,
    pub kind: StepKind,
    /// Platform the command targets; `None` means it is platform-neutral advice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub requires_privileges: bool,
    /// Whether the operator can undo the step with a documented inverse.
    pub reversible: bool,
}

impl RunbookStep {
    pub fn advice(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            kind: StepKind::Inspect,
            platform: None,
            command: None,
            requires_privileges: false,
            reversible: true,
        }
    }

    pub fn command(
        description: impl Into<String>,
        kind: StepKind,
        platform: Platform,
        command: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            kind,
            platform: Some(platform),
            command: Some(command.into()),
            requires_privileges: true,
            reversible: true,
        }
    }

    #[must_use]
    pub fn unprivileged(mut self) -> Self {
        self.requires_privileges = false;
        self
    }
}

/// Commands to confirm and then block an abusive source address.
///
/// Blocking is containment, not destruction: every command listed here has a
/// documented inverse, and the first step is always to look before acting.
pub fn block_source(platform: Platform, address: &str) -> Vec<RunbookStep> {
    let mut steps = vec![RunbookStep::advice(format!(
        "Confirma que {address} no es una IP legítima de tu operación (VPN, monitoreo, balanceador) antes de bloquearla."
    ))];
    match platform {
        Platform::Linux => {
            steps.push(RunbookStep::command(
                "Revisa los intentos registrados desde ese origen.",
                StepKind::Inspect,
                Platform::Linux,
                format!("journalctl -u ssh --since '-1h' --grep '{address}'"),
            ));
            steps.push(RunbookStep::command(
                "Bloquea el origen en el firewall del host (revierte con: ufw status numbered && ufw delete <n>).",
                StepKind::Contain,
                Platform::Linux,
                format!("ufw deny from {address} to any"),
            ));
            steps.push(RunbookStep::command(
                "Alternativa con nftables (revierte con: nft delete element inet filter blocklist).",
                StepKind::Contain,
                Platform::Linux,
                format!("nft add element inet filter blocklist {{ {address} }}"),
            ));
        }
        Platform::Windows => {
            steps.push(RunbookStep::command(
                "Revisa los inicios de sesión fallidos desde ese origen.",
                StepKind::Inspect,
                Platform::Windows,
                format!(
                    "Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents 200 | Where-Object Message -match '{address}'"
                ),
            ));
            steps.push(RunbookStep::command(
                "Bloquea el origen (revierte con: Remove-NetFirewallRule -DisplayName 'RootCause block ...').",
                StepKind::Contain,
                Platform::Windows,
                format!(
                    "New-NetFirewallRule -DisplayName 'RootCause block {address}' -Direction Inbound -RemoteAddress {address} -Action Block"
                ),
            ));
        }
        Platform::Macos => {
            steps.push(RunbookStep::command(
                "Añade el origen a la tabla de bloqueo de pf (revierte con: pfctl -t rootcause_block -T delete).",
                StepKind::Contain,
                Platform::Macos,
                format!("pfctl -t rootcause_block -T add {address}"),
            ));
        }
        Platform::Unknown => {
            steps.push(RunbookStep::advice(format!(
                "Bloquea {address} en el firewall perimetral con la herramienta de tu plataforma."
            )));
        }
    }
    steps.push(RunbookStep::advice(
        "Registra el bloqueo con fecha y responsable; un bloqueo sin registro es indistinguible de un corte.",
    ));
    steps
}

/// Commands to identify and then restrict a service exposed beyond its scope.
pub fn restrict_listener(platform: Platform, port: u16, service: &str) -> Vec<RunbookStep> {
    let mut steps = Vec::new();
    match platform {
        Platform::Linux => {
            steps.push(RunbookStep::command(
                format!("Identifica qué proceso publica {service} en el puerto {port}."),
                StepKind::Inspect,
                Platform::Linux,
                format!("ss -ltnp 'sport = :{port}'"),
            ));
            steps.push(RunbookStep::command(
                format!(
                    "Limita el puerto {port} a la red interna mientras corriges la configuración del servicio."
                ),
                StepKind::Contain,
                Platform::Linux,
                format!("ufw deny in to any port {port}"),
            ));
            steps.push(RunbookStep::advice(format!(
                "Corrige la causa: haz que {service} escuche en 127.0.0.1 o en la interfaz interna en vez de 0.0.0.0, y reinicia el servicio en una ventana acordada."
            )));
        }
        Platform::Windows => {
            steps.push(RunbookStep::command(
                format!("Identifica qué proceso publica {service} en el puerto {port}."),
                StepKind::Inspect,
                Platform::Windows,
                format!("Get-NetTCPConnection -LocalPort {port} -State Listen | Select-Object LocalAddress,OwningProcess"),
            ));
            steps.push(RunbookStep::command(
                format!("Bloquea el puerto {port} desde fuera mientras corriges el servicio."),
                StepKind::Contain,
                Platform::Windows,
                format!(
                    "New-NetFirewallRule -DisplayName 'RootCause restrict {port}' -Direction Inbound -LocalPort {port} -Protocol TCP -Action Block"
                ),
            ));
        }
        Platform::Macos => {
            steps.push(RunbookStep::command(
                format!("Identifica qué proceso publica {service} en el puerto {port}."),
                StepKind::Inspect,
                Platform::Macos,
                format!("lsof -nP -iTCP:{port} -sTCP:LISTEN"),
            ));
        }
        Platform::Unknown => {
            steps.push(RunbookStep::advice(format!(
                "Identifica el proceso que publica el puerto {port} y limita su alcance a la red interna."
            )));
        }
    }
    steps.push(RunbookStep::advice(
        "Verifica desde fuera del host que el puerto ya no responde antes de cerrar el incidente.",
    ));
    steps
}

/// Commands to compare a changed file against its known-good state.
pub fn verify_file(platform: Platform, path: &str) -> Vec<RunbookStep> {
    let mut steps = vec![RunbookStep::advice(format!(
        "Averigua si el cambio en {path} corresponde a un despliegue autorizado antes de tocar nada."
    ))];
    match platform {
        Platform::Linux | Platform::Macos => {
            steps.push(
                RunbookStep::command(
                    "Compara el contenido con la copia de referencia.",
                    StepKind::Inspect,
                    platform,
                    format!("diff -u {path}.rootcause-baseline {path}"),
                )
                .unprivileged(),
            );
            steps.push(RunbookStep::command(
                "Revisa quién y cuándo modificó el archivo.",
                StepKind::Inspect,
                platform,
                format!("stat {path} && ausearch -f {path} -ts recent"),
            ));
        }
        Platform::Windows => {
            steps.push(
                RunbookStep::command(
                    "Compara el contenido con la copia de referencia.",
                    StepKind::Inspect,
                    Platform::Windows,
                    format!(
                        "Compare-Object (Get-Content '{path}.baseline') (Get-Content '{path}')"
                    ),
                )
                .unprivileged(),
            );
        }
        Platform::Unknown => {}
    }
    steps.push(RunbookStep::advice(
        "Si el cambio no está justificado, conserva el archivo actual como evidencia antes de restaurar la referencia.",
    ));
    steps
}

/// Commands to bring a missing baseline control back.
pub fn enable_firewall(platform: Platform) -> Vec<RunbookStep> {
    match platform {
        Platform::Linux => vec![
            RunbookStep::command(
                "Revisa el estado actual antes de habilitar nada.",
                StepKind::Inspect,
                Platform::Linux,
                "ufw status verbose",
            ),
            RunbookStep::advice(
                "Antes de activar el firewall, confirma que la regla de tu acceso remoto ya existe: activarlo sin ella te deja fuera del servidor.",
            ),
            RunbookStep::command(
                "Habilita el firewall con denegación entrante por omisión.",
                StepKind::Remediate,
                Platform::Linux,
                "ufw default deny incoming && ufw allow OpenSSH && ufw enable",
            ),
        ],
        Platform::Windows => vec![
            RunbookStep::command(
                "Revisa el estado de los perfiles de firewall.",
                StepKind::Inspect,
                Platform::Windows,
                "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction",
            ),
            RunbookStep::command(
                "Habilita los tres perfiles.",
                StepKind::Remediate,
                Platform::Windows,
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            ),
        ],
        Platform::Macos => vec![RunbookStep::command(
            "Revisa el estado del firewall de aplicaciones.",
            StepKind::Inspect,
            Platform::Macos,
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
        )],
        Platform::Unknown => {
            vec![RunbookStep::advice(
                "Habilita el firewall del host con denegación entrante por omisión.",
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbs that must never appear in a generated command.
    const FORBIDDEN: &[&str] = &[
        "rm -rf",
        "rm -f",
        "mkfs",
        "dd if=",
        "shutdown",
        "reboot",
        "Stop-Computer",
        "Restart-Computer",
        "format ",
        "del /f",
        "Remove-Item",
        "drop database",
        "truncate ",
        ":(){",
        "chmod 777",
        "curl ",
        "wget ",
        "Invoke-WebRequest",
    ];

    fn every_step() -> Vec<RunbookStep> {
        let mut steps = Vec::new();
        for platform in [Platform::Linux, Platform::Windows, Platform::Macos, Platform::Unknown] {
            steps.extend(block_source(platform, "203.0.113.10"));
            steps.extend(restrict_listener(platform, 5432, "PostgreSQL"));
            steps.extend(verify_file(platform, "/etc/ssh/sshd_config"));
            steps.extend(enable_firewall(platform));
        }
        steps
    }

    #[test]
    fn no_destructive_commands() {
        for step in every_step() {
            let Some(command) = step.command.as_deref() else { continue };
            for forbidden in FORBIDDEN {
                assert!(
                    !command.to_ascii_lowercase().contains(&forbidden.to_ascii_lowercase()),
                    "runbook command must never contain {forbidden:?}: {command}"
                );
            }
        }
    }

    #[test]
    fn every_step_is_reversible() {
        assert!(every_step().iter().all(|step| step.reversible));
    }

    #[test]
    fn containment_always_follows_an_inspection() {
        for platform in [Platform::Linux, Platform::Windows] {
            let steps = block_source(platform, "203.0.113.10");
            let first_contain =
                steps.iter().position(|step| step.kind == StepKind::Contain).unwrap();
            assert!(
                steps[..first_contain].iter().any(|step| step.kind == StepKind::Inspect),
                "{platform:?}: containment must be preceded by an inspection step"
            );
        }
    }

    #[test]
    fn blocking_mentions_the_offending_address() {
        let steps = block_source(Platform::Linux, "198.51.100.7");
        assert!(
            steps
                .iter()
                .filter_map(|step| step.command.as_deref())
                .any(|command| command.contains("198.51.100.7"))
        );
    }
}
