//! Baseline controls: is the host firewall filtering, and is the host patched.
//!
//! Both answers come from the platform's own tooling, read-only, and both are
//! reported as a gap rather than as a zero when the tool is absent. "No pending
//! updates" and "nobody asked" must never look the same in the console.

use std::time::Duration;

use rootcause_core::security::{CollectionGap, FirewallState};

use crate::probe;

const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

/// Baseline controls observed in one cycle.
#[derive(Debug, Default)]
pub struct BaselineSurface {
    pub firewall: Option<FirewallState>,
    pub pending_security_updates: Option<u32>,
    pub gaps: Vec<CollectionGap>,
}

/// Inspect the host firewall and the pending security updates.
pub async fn collect() -> BaselineSurface {
    let mut surface = BaselineSurface::default();
    match firewall().await {
        Ok(state) => surface.firewall = Some(state),
        Err(reason) => surface.gaps.push(CollectionGap::new("firewall", reason)),
    }
    match pending_updates().await {
        Ok(Some(count)) => surface.pending_security_updates = Some(count),
        Ok(None) => {}
        Err(reason) => surface.gaps.push(CollectionGap::new("security-updates", reason)),
    }
    surface
}

async fn firewall() -> Result<FirewallState, String> {
    if cfg!(target_os = "linux") {
        if let Ok(output) = probe::run("ufw", &["status", "verbose"], PROBE_TIMEOUT).await {
            return Ok(parse_ufw_status(&output));
        }
        if let Ok(output) = probe::run("firewall-cmd", &["--state"], PROBE_TIMEOUT).await {
            return Ok(parse_firewalld_state(&output));
        }
        if let Ok(output) = probe::run("nft", &["list", "ruleset"], PROBE_TIMEOUT).await {
            return Ok(parse_nft_ruleset(&output));
        }
        return Err("no se encontró ufw, firewalld ni nftables en este host".to_owned());
    }
    if cfg!(target_os = "windows") {
        return probe::run("netsh", &["advfirewall", "show", "allprofiles"], PROBE_TIMEOUT)
            .await
            .map(|output| parse_netsh_advfirewall(&output))
            .map_err(|error| error.reason("netsh"));
    }
    if cfg!(target_os = "macos") {
        return probe::run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
            PROBE_TIMEOUT,
        )
        .await
        .map(|output| parse_socketfilterfw(&output))
        .map_err(|error| error.reason("socketfilterfw"));
    }
    Err("esta plataforma no tiene un lector de firewall implementado".to_owned())
}

async fn pending_updates() -> Result<Option<u32>, String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "el conteo de actualizaciones de seguridad solo está implementado en Linux".to_owned()
        );
    }
    if let Ok(output) =
        probe::run("apt-get", &["--simulate", "--quiet", "upgrade"], PROBE_TIMEOUT).await
    {
        return Ok(Some(parse_apt_simulation(&output)));
    }
    if let Ok(output) =
        probe::run("dnf", &["--quiet", "check-update", "--security"], PROBE_TIMEOUT).await
    {
        return Ok(Some(parse_dnf_security(&output)));
    }
    Err("no se encontró apt-get ni dnf para consultar actualizaciones".to_owned())
}

/// Parse `ufw status verbose`.
pub fn parse_ufw_status(output: &str) -> FirewallState {
    let lowered = output.to_ascii_lowercase();
    let enabled = lowered.contains("status: active") || lowered.contains("estado: activo");
    let default_inbound_deny =
        lowered.contains("deny (incoming)") || lowered.contains("reject (incoming)");
    let rule_count = output
        .lines()
        .filter(|line| {
            let upper = line.to_ascii_uppercase();
            upper.contains("ALLOW") || upper.contains("DENY") || upper.contains("REJECT")
        })
        .filter(|line| !line.to_ascii_lowercase().starts_with("default"))
        .count() as u32;

    FirewallState { engine: "ufw".to_owned(), enabled, rule_count, default_inbound_deny }
}

/// Parse `firewall-cmd --state`.
pub fn parse_firewalld_state(output: &str) -> FirewallState {
    let running = output.trim().eq_ignore_ascii_case("running");
    FirewallState {
        engine: "firewalld".to_owned(),
        enabled: running,
        rule_count: 0,
        // firewalld's shipped zones reject unsolicited inbound traffic.
        default_inbound_deny: running,
    }
}

/// Parse `nft list ruleset`.
pub fn parse_nft_ruleset(output: &str) -> FirewallState {
    let rule_count = output
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("ip ")
                || trimmed.starts_with("tcp ")
                || trimmed.starts_with("udp ")
                || trimmed.starts_with("ct ")
        })
        .count() as u32;
    let default_inbound_deny = output.contains("hook input") && output.contains("policy drop");

    FirewallState {
        engine: "nftables".to_owned(),
        enabled: output.contains("hook input"),
        rule_count,
        default_inbound_deny,
    }
}

/// Parse `netsh advfirewall show allprofiles`.
pub fn parse_netsh_advfirewall(output: &str) -> FirewallState {
    let mut profiles = 0_u32;
    let mut enabled_profiles = 0_u32;
    let mut blocking_profiles = 0_u32;

    for line in output.lines() {
        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("STATE") || upper.starts_with("ESTADO") {
            profiles += 1;
            // "DESACTIVADO" ends in "ACTIVADO": the negative form is checked first
            // so a localised installation is never reported as protected.
            let switched_on = !upper.contains("DESACTIV")
                && (upper.ends_with("ON") || upper.ends_with("ACTIVADO") || upper.ends_with("SÍ"));
            if switched_on {
                enabled_profiles += 1;
            }
        }
        if upper.contains("BLOCKINBOUND") || upper.contains("BLOQUEARENTRADA") {
            blocking_profiles += 1;
        }
    }

    FirewallState {
        engine: "windows-defender-firewall".to_owned(),
        // A profile left off is a hole, even if the other two are on.
        enabled: profiles > 0 && enabled_profiles == profiles,
        rule_count: enabled_profiles,
        default_inbound_deny: blocking_profiles > 0 && blocking_profiles == profiles,
    }
}

/// Parse `socketfilterfw --getglobalstate`.
pub fn parse_socketfilterfw(output: &str) -> FirewallState {
    let enabled = output.contains("State = 1") || output.contains("State = 2");
    FirewallState {
        engine: "application-firewall".to_owned(),
        enabled,
        rule_count: 0,
        default_inbound_deny: enabled,
    }
}

/// Count security packages in the output of `apt-get --simulate upgrade`.
pub fn parse_apt_simulation(output: &str) -> u32 {
    output
        .lines()
        .filter(|line| line.starts_with("Inst "))
        .filter(|line| line.to_ascii_lowercase().contains("security"))
        .count() as u32
}

/// Count packages listed by `dnf check-update --security`.
pub fn parse_dnf_security(output: &str) -> u32 {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("Last metadata") && !line.starts_with("Obsoleting"))
        .filter(|line| line.split_whitespace().count() == 3 && line.contains('.'))
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const UFW_ACTIVE: &str = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
";

    const UFW_INACTIVE: &str = "Status: inactive\n";

    const NETSH_ALL_ON: &str = "\
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
";

    const NETSH_ONE_OFF: &str = "\
Domain Profile Settings:
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
State                                 OFF
Firewall Policy                       AllowInbound,AllowOutbound
";

    const APT_SIMULATION: &str = "\
Inst libssl3 [3.0.13-1] (3.0.14-1 Ubuntu:24.04/noble-security [amd64])
Inst openssh-server [1:9.6p1] (1:9.6p2 Ubuntu:24.04/noble-security [amd64])
Inst vim [2:9.1] (2:9.2 Ubuntu:24.04/noble-updates [amd64])
Conf libssl3 (3.0.14-1 Ubuntu:24.04/noble-security [amd64])
";

    #[test]
    fn an_active_ufw_with_default_deny_is_reported_as_filtering() {
        let state = parse_ufw_status(UFW_ACTIVE);
        assert!(state.enabled);
        assert!(state.default_inbound_deny);
        assert_eq!(state.rule_count, 2);
        assert_eq!(state.engine, "ufw");
    }

    #[test]
    fn an_inactive_ufw_is_reported_as_not_filtering() {
        let state = parse_ufw_status(UFW_INACTIVE);
        assert!(!state.enabled);
        assert!(!state.default_inbound_deny);
    }

    #[test]
    fn firewalld_running_counts_as_default_deny() {
        assert!(parse_firewalld_state("running\n").enabled);
        assert!(!parse_firewalld_state("not running\n").enabled);
    }

    #[test]
    fn an_nftables_input_chain_with_policy_drop_is_default_deny() {
        let ruleset = "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    tcp dport 22 accept\n  }\n}\n";
        let state = parse_nft_ruleset(ruleset);
        assert!(state.enabled);
        assert!(state.default_inbound_deny);
        assert_eq!(state.rule_count, 1);
    }

    #[test]
    fn windows_needs_every_profile_on_to_count_as_enabled() {
        let all_on = parse_netsh_advfirewall(NETSH_ALL_ON);
        assert!(all_on.enabled);
        assert!(all_on.default_inbound_deny);

        let one_off = parse_netsh_advfirewall(NETSH_ONE_OFF);
        assert!(!one_off.enabled, "a single profile left off is still a hole");
        assert!(!one_off.default_inbound_deny);
    }

    #[test]
    fn a_localised_windows_profile_is_not_mistaken_for_an_enabled_one() {
        let localised = "\
Configuración de perfil de dominio:
Estado                                DESACTIVADO
Directiva de firewall                 PermitirEntrada,PermitirSalida
";
        let state = parse_netsh_advfirewall(localised);
        assert!(!state.enabled, "DESACTIVADO must never read as enabled");
    }

    #[test]
    fn the_macos_application_firewall_states_are_understood() {
        assert!(parse_socketfilterfw("Firewall is enabled. (State = 1)\n").enabled);
        assert!(!parse_socketfilterfw("Firewall is disabled. (State = 0)\n").enabled);
    }

    #[test]
    fn only_security_packages_are_counted_from_apt() {
        assert_eq!(parse_apt_simulation(APT_SIMULATION), 2);
        assert_eq!(parse_apt_simulation(""), 0);
    }

    #[test]
    fn dnf_rows_are_counted_and_noise_is_not() {
        let output = "Last metadata expiration check: 0:12:01 ago.\n\nopenssl.x86_64  3.2.2-6.el9  updates\nkernel.x86_64   5.14.0-503  updates\n";
        assert_eq!(parse_dnf_security(output), 2);
    }

    #[test]
    fn empty_output_never_pretends_the_host_is_clean() {
        // An empty firewall reading is *not* an enabled firewall.
        assert!(!parse_ufw_status("").enabled);
        assert!(!parse_netsh_advfirewall("").enabled);
    }
}
