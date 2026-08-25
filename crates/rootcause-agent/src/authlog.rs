//! Who has been trying to log in, and from where.
//!
//! The agent reads the platform's own authentication record — it does not open
//! a socket, does not hook a service and does not touch PAM. What travels to the
//! server is an aggregate (`service`, `source`, `user`, `outcome`, `count`),
//! never a raw log line: the counts are what detection needs, and the raw lines
//! are what would leak.

use std::{collections::BTreeMap, time::Duration};

use chrono::{DateTime, Utc};
use rootcause_core::security::{AuthEvent, AuthOutcome, CollectionGap};

use crate::probe::{self, ProbeError};

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Aggregated rows reported per cycle; enough for the busiest offender list.
const MAX_EVENTS: usize = 200;

/// Authentication activity observed in one collection cycle.
#[derive(Debug, Default)]
pub struct AuthSurface {
    pub events: Vec<AuthEvent>,
    pub gaps: Vec<CollectionGap>,
}

impl AuthSurface {
    fn gap(reason: String) -> Self {
        Self { events: Vec::new(), gaps: vec![CollectionGap::new("auth-events", reason)] }
    }
}

/// Read the recent authentication record of this platform.
pub async fn collect(window_minutes: u32, now: DateTime<Utc>) -> AuthSurface {
    if cfg!(target_os = "linux") {
        collect_linux(window_minutes, now).await
    } else if cfg!(target_os = "windows") {
        collect_windows(now).await
    } else {
        AuthSurface::gap(
            "esta plataforma no tiene un lector de eventos de autenticación implementado"
                .to_owned(),
        )
    }
}

async fn collect_linux(window_minutes: u32, now: DateTime<Utc>) -> AuthSurface {
    let since = format!("-{window_minutes}min");
    match probe::run(
        "journalctl",
        &["--no-pager", "--since", &since, "_COMM=sshd", "SYSLOG_IDENTIFIER=sshd"],
        PROBE_TIMEOUT,
    )
    .await
    {
        Ok(output) => AuthSurface { events: parse_sshd_log(&output, now), gaps: Vec::new() },
        Err(error) => match read_auth_files().await {
            Some(content) => {
                AuthSurface { events: parse_sshd_log(&content, now), gaps: Vec::new() }
            }
            None => AuthSurface::gap(error.reason("journalctl")),
        },
    }
}

async fn read_auth_files() -> Option<String> {
    for path in ["/var/log/auth.log", "/var/log/secure"] {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            // Only the tail matters: the window is minutes, not months.
            let tail: Vec<&str> = content.lines().rev().take(5_000).collect();
            return Some(tail.into_iter().rev().collect::<Vec<_>>().join("\n"));
        }
    }
    None
}

async fn collect_windows(now: DateTime<Utc>) -> AuthSurface {
    let mut surface = AuthSurface::default();
    for (event_id, outcome) in [(4625_u32, AuthOutcome::Failure), (4624, AuthOutcome::Success)] {
        let query = format!("*[System[(EventID={event_id})]]");
        match probe::run(
            "wevtutil",
            &["qe", "Security", &format!("/q:{query}"), "/f:text", "/c:200", "/rd:true"],
            PROBE_TIMEOUT,
        )
        .await
        {
            Ok(output) => surface.events.extend(parse_windows_security_log(&output, outcome, now)),
            Err(ProbeError::Failed(code)) => surface.gaps.push(CollectionGap::new(
                "auth-events",
                format!(
                    "wevtutil no pudo leer el registro de seguridad (código {code}); el agente necesita privilegios de lectura sobre ese registro"
                ),
            )),
            Err(error) => {
                surface.gaps.push(CollectionGap::new("auth-events", error.reason("wevtutil")));
            }
        }
    }
    surface.events = aggregate(surface.events);
    surface
}

/// Collapse rows that share service, source, user and outcome.
fn aggregate(events: Vec<AuthEvent>) -> Vec<AuthEvent> {
    let mut grouped: BTreeMap<(String, String, String, &'static str), AuthEvent> = BTreeMap::new();
    for event in events {
        let key = (
            event.service.clone(),
            event.source_address.clone(),
            event.username.clone().unwrap_or_default(),
            event.outcome.as_str(),
        );
        grouped
            .entry(key)
            .and_modify(|existing| {
                existing.count = existing.count.saturating_add(event.count);
                existing.last_seen = existing.last_seen.max(event.last_seen);
            })
            .or_insert(event);
    }
    let mut events: Vec<AuthEvent> = grouped.into_values().collect();
    events.sort_by_key(|event| std::cmp::Reverse(event.count));
    events.truncate(MAX_EVENTS);
    events
}

/// Extract the address that follows the ` from ` marker of an sshd line.
fn source_after_from(line: &str) -> Option<&str> {
    line.split(" from ").nth(1)?.split_whitespace().next()
}

/// Parse `sshd` authentication lines, whatever produced them.
///
/// Accepts both classic syslog files and `journalctl` output; only the message
/// body is interpreted, so the timestamp format is irrelevant.
pub fn parse_sshd_log(output: &str, now: DateTime<Utc>) -> Vec<AuthEvent> {
    let mut events = Vec::new();
    for line in output.lines() {
        if !line.contains("sshd") {
            continue;
        }
        let (outcome, username) = if let Some(rest) = line.split("Failed password for ").nth(1) {
            let username = rest
                .strip_prefix("invalid user ")
                .unwrap_or(rest)
                .split_whitespace()
                .next()
                .map(str::to_owned);
            (AuthOutcome::Failure, username)
        } else if let Some(rest) = line.split("Invalid user ").nth(1) {
            (AuthOutcome::Failure, rest.split_whitespace().next().map(str::to_owned))
        } else if line.contains("Failed publickey for") {
            let username = line
                .split("Failed publickey for ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_owned);
            (AuthOutcome::Failure, username)
        } else if let Some(rest) = line.split("Accepted ").nth(1) {
            let username = rest
                .split(" for ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_owned);
            (AuthOutcome::Success, username)
        } else {
            continue;
        };

        let Some(source) = source_after_from(line) else { continue };
        if source.is_empty() {
            continue;
        }
        events.push(AuthEvent {
            service: "sshd".to_owned(),
            source_address: source.to_owned(),
            username,
            outcome,
            count: 1,
            last_seen: now,
        });
    }
    aggregate(events)
}

/// Read a `Field: value` line from a `wevtutil ... /f:text` block.
fn field_value<'a>(block: &'a str, field: &str) -> Option<&'a str> {
    block
        .lines()
        .filter_map(|line| line.trim().strip_prefix(field))
        .map(|rest| rest.trim_start_matches(':').trim())
        .rfind(|value| !value.is_empty() && *value != "-")
}

/// Parse the text rendering of Windows security events 4624 and 4625.
pub fn parse_windows_security_log(
    output: &str,
    outcome: AuthOutcome,
    now: DateTime<Utc>,
) -> Vec<AuthEvent> {
    let mut events = Vec::new();
    for block in output.split("Event[").skip(1) {
        let Some(source) = field_value(block, "Source Network Address") else { continue };
        // Local and service logons report no usable network source.
        if source == "127.0.0.1" || source == "::1" {
            continue;
        }
        let username = field_value(block, "Account Name").map(str::to_owned);
        events.push(AuthEvent {
            service: "windows-logon".to_owned(),
            source_address: source.to_owned(),
            username,
            outcome,
            count: 1,
            last_seen: now,
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSHD_LOG: &str = "\
Aug 25 10:12:33 srv sshd[1234]: Failed password for root from 203.0.113.10 port 51234 ssh2
Aug 25 10:12:35 srv sshd[1234]: Failed password for root from 203.0.113.10 port 51236 ssh2
Aug 25 10:12:37 srv sshd[1235]: Failed password for invalid user admin from 203.0.113.10 port 51240 ssh2
Aug 25 10:12:40 srv sshd[1236]: Invalid user oracle from 198.51.100.4 port 39000
Aug 25 10:13:01 srv sshd[1250]: Accepted publickey for deploy from 10.0.0.9 port 40122 ssh2
Aug 25 10:13:10 srv CRON[900]: pam_unix(cron:session): session opened for user root
";

    const WEVTUTIL_TEXT: &str = "\
Event[0]:
  Log Name: Security
  Event ID: 4625
  Description:
An account failed to log on.

Subject:
	Account Name:		-
Account For Which Logon Failed:
	Account Name:		administrador
Network Information:
	Workstation Name:	KALI
	Source Network Address:	203.0.113.77
	Source Port:		51222

Event[1]:
  Log Name: Security
  Event ID: 4625
  Description:
An account failed to log on.

Account For Which Logon Failed:
	Account Name:		administrador
Network Information:
	Source Network Address:	203.0.113.77

Event[2]:
  Log Name: Security
  Event ID: 4625
  Description:
An account failed to log on.

Account For Which Logon Failed:
	Account Name:		servicio
Network Information:
	Source Network Address:	127.0.0.1
";

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-25T10:15:00Z").unwrap().with_timezone(&Utc)
    }

    #[test]
    fn repeated_failures_from_one_source_are_counted_once() {
        let events = parse_sshd_log(SSHD_LOG, now());
        let root = events
            .iter()
            .find(|event| {
                event.source_address == "203.0.113.10" && event.username.as_deref() == Some("root")
            })
            .unwrap();
        assert_eq!(root.count, 2);
        assert_eq!(root.outcome, AuthOutcome::Failure);
        assert_eq!(root.service, "sshd");
    }

    #[test]
    fn an_invalid_user_keeps_its_real_name() {
        let events = parse_sshd_log(SSHD_LOG, now());
        assert!(events.iter().any(|event| event.username.as_deref() == Some("admin")
            && event.source_address == "203.0.113.10"));
        assert!(events.iter().any(|event| event.username.as_deref() == Some("oracle")
            && event.source_address == "198.51.100.4"));
    }

    #[test]
    fn a_successful_login_is_recorded_as_such() {
        let events = parse_sshd_log(SSHD_LOG, now());
        let accepted = events
            .iter()
            .find(|event| event.outcome == AuthOutcome::Success)
            .expect("the accepted key must be reported");
        assert_eq!(accepted.username.as_deref(), Some("deploy"));
        assert_eq!(accepted.source_address, "10.0.0.9");
    }

    #[test]
    fn lines_from_other_services_are_ignored() {
        let events = parse_sshd_log(SSHD_LOG, now());
        assert!(events.iter().all(|event| event.service == "sshd"));
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn no_raw_log_line_ever_reaches_the_event() {
        for event in parse_sshd_log(SSHD_LOG, now()) {
            assert!(!event.source_address.contains(' '));
            assert!(event.username.as_deref().is_none_or(|name| !name.contains(' ')));
        }
    }

    #[test]
    fn garbage_produces_no_events() {
        assert!(parse_sshd_log("", now()).is_empty());
        assert!(parse_sshd_log("sshd: something else entirely\n", now()).is_empty());
    }

    #[test]
    fn windows_events_are_grouped_by_source_and_account() {
        let events = parse_windows_security_log(WEVTUTIL_TEXT, AuthOutcome::Failure, now());
        let events = aggregate(events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_address, "203.0.113.77");
        assert_eq!(events[0].username.as_deref(), Some("administrador"));
        assert_eq!(events[0].count, 2);
    }

    #[test]
    fn windows_local_logons_are_not_reported_as_remote_pressure() {
        let events = parse_windows_security_log(WEVTUTIL_TEXT, AuthOutcome::Failure, now());
        assert!(events.iter().all(|event| event.source_address != "127.0.0.1"));
    }

    #[test]
    fn the_subject_placeholder_never_becomes_a_username() {
        let events = parse_windows_security_log(WEVTUTIL_TEXT, AuthOutcome::Failure, now());
        assert!(events.iter().all(|event| event.username.as_deref() != Some("-")));
    }

    #[test]
    fn the_aggregate_is_bounded() {
        let events: Vec<AuthEvent> = (0..MAX_EVENTS + 50)
            .map(|n| AuthEvent {
                service: "sshd".to_owned(),
                source_address: format!("198.51.100.{n}"),
                username: Some("root".to_owned()),
                outcome: AuthOutcome::Failure,
                count: 1,
                last_seen: now(),
            })
            .collect();
        assert_eq!(aggregate(events).len(), MAX_EVENTS);
    }
}
