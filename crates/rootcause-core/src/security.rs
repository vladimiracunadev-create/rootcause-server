//! Security-facing observations reported by a RootCause agent.
//!
//! Everything in this module describes *what the agent saw*, never *what the
//! server decided*. Detection lives in [`crate::detect`]; keeping the two apart
//! is what allows an incident to be re-evaluated later against the same
//! evidence.

use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Transport protocol of an observed socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Reachability of a bind address, derived from the address itself.
///
/// This is the most important classification in the product: the same database
/// port is routine on `127.0.0.1` and an emergency on `0.0.0.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindScope {
    /// Only reachable from the machine itself.
    Loopback,
    /// Reachable from the local network (RFC1918, CGNAT, link-local, ULA).
    Private,
    /// Reachable from any interface, including public ones.
    Public,
}

impl BindScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::Public => "public",
        }
    }

    /// Classify a textual bind address.
    ///
    /// Unparseable addresses are treated as `Public`: when the evidence is
    /// ambiguous the product reports the worse case instead of silently
    /// downgrading a finding.
    pub fn classify(address: &str) -> Self {
        let trimmed = address.trim().trim_start_matches('[').trim_end_matches(']');
        if trimmed == "*" || trimmed.is_empty() {
            return Self::Public;
        }
        IpAddr::from_str(trimmed).map_or(Self::Public, Self::classify_ip)
    }

    pub fn classify_ip(ip: IpAddr) -> Self {
        if ip.is_loopback() {
            return Self::Loopback;
        }
        if ip.is_unspecified() {
            return Self::Public;
        }
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, ..] = v4.octets();
                let is_private =
                    v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b));
                if is_private { Self::Private } else { Self::Public }
            }
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                // fc00::/7 unique-local and fe80::/10 link-local.
                if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
                    Self::Private
                } else {
                    Self::Public
                }
            }
        }
    }
}

/// Risk family of a well-known port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortClass {
    /// Remote administration: owning it owns the machine.
    RemoteAdmin,
    /// Data stores that frequently ship with no authentication at all.
    Database,
    /// Orchestration and cluster control planes.
    Infrastructure,
    /// Protocols that carry credentials in the clear.
    Cleartext,
    /// File and directory sharing.
    FileShare,
    /// Mail transport and retrieval.
    Mail,
    /// Ordinary application traffic.
    Web,
    /// Everything the catalog does not recognise.
    Other,
}

impl PortClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteAdmin => "remote-admin",
            Self::Database => "database",
            Self::Infrastructure => "infrastructure",
            Self::Cleartext => "cleartext",
            Self::FileShare => "file-share",
            Self::Mail => "mail",
            Self::Web => "web",
            Self::Other => "other",
        }
    }

    /// Spanish label used by the console and the exported reports.
    pub const fn label(self) -> &'static str {
        match self {
            Self::RemoteAdmin => "Administración remota",
            Self::Database => "Base de datos",
            Self::Infrastructure => "Infraestructura",
            Self::Cleartext => "Protocolo sin cifrar",
            Self::FileShare => "Compartición de archivos",
            Self::Mail => "Correo",
            Self::Web => "Aplicación web",
            Self::Other => "Otro",
        }
    }
}

/// A well-known port with the service behind it and why it matters.
#[derive(Debug, Clone, Copy)]
pub struct PortProfile {
    pub port: u16,
    pub service: &'static str,
    pub class: PortClass,
}

/// Catalog of ports whose public exposure changes the risk of a server.
///
/// Deliberately small and curated: a list where every port is a service would
/// bury the two or three findings that actually matter on a real server.
pub const PORT_CATALOG: &[PortProfile] = &[
    PortProfile { port: 21, service: "FTP", class: PortClass::Cleartext },
    PortProfile { port: 22, service: "SSH", class: PortClass::RemoteAdmin },
    PortProfile { port: 23, service: "Telnet", class: PortClass::Cleartext },
    PortProfile { port: 25, service: "SMTP", class: PortClass::Mail },
    PortProfile { port: 110, service: "POP3", class: PortClass::Cleartext },
    PortProfile { port: 111, service: "rpcbind", class: PortClass::Infrastructure },
    PortProfile { port: 135, service: "MSRPC", class: PortClass::Infrastructure },
    PortProfile { port: 137, service: "NetBIOS", class: PortClass::FileShare },
    PortProfile { port: 139, service: "NetBIOS", class: PortClass::FileShare },
    PortProfile { port: 143, service: "IMAP", class: PortClass::Cleartext },
    PortProfile { port: 389, service: "LDAP", class: PortClass::Cleartext },
    PortProfile { port: 445, service: "SMB", class: PortClass::FileShare },
    PortProfile { port: 512, service: "rexec", class: PortClass::Cleartext },
    PortProfile { port: 513, service: "rlogin", class: PortClass::Cleartext },
    PortProfile { port: 514, service: "rsh / syslog", class: PortClass::Cleartext },
    PortProfile { port: 623, service: "IPMI", class: PortClass::RemoteAdmin },
    PortProfile { port: 873, service: "rsync", class: PortClass::FileShare },
    PortProfile { port: 1433, service: "SQL Server", class: PortClass::Database },
    PortProfile { port: 1521, service: "Oracle Database", class: PortClass::Database },
    PortProfile { port: 2049, service: "NFS", class: PortClass::FileShare },
    PortProfile { port: 2375, service: "Docker API sin TLS", class: PortClass::Infrastructure },
    PortProfile { port: 2376, service: "Docker API", class: PortClass::Infrastructure },
    PortProfile { port: 2379, service: "etcd", class: PortClass::Infrastructure },
    PortProfile { port: 2380, service: "etcd peer", class: PortClass::Infrastructure },
    PortProfile { port: 3000, service: "Aplicación / Grafana", class: PortClass::Web },
    PortProfile { port: 3306, service: "MySQL / MariaDB", class: PortClass::Database },
    PortProfile { port: 3389, service: "RDP", class: PortClass::RemoteAdmin },
    PortProfile { port: 4243, service: "Docker API heredada", class: PortClass::Infrastructure },
    PortProfile { port: 5432, service: "PostgreSQL", class: PortClass::Database },
    PortProfile { port: 5601, service: "Kibana", class: PortClass::Web },
    PortProfile { port: 5900, service: "VNC", class: PortClass::RemoteAdmin },
    PortProfile { port: 5984, service: "CouchDB", class: PortClass::Database },
    PortProfile { port: 5985, service: "WinRM", class: PortClass::RemoteAdmin },
    PortProfile { port: 5986, service: "WinRM sobre TLS", class: PortClass::RemoteAdmin },
    PortProfile { port: 6379, service: "Redis", class: PortClass::Database },
    PortProfile { port: 6443, service: "API de Kubernetes", class: PortClass::Infrastructure },
    PortProfile { port: 7001, service: "WebLogic", class: PortClass::Web },
    PortProfile { port: 8080, service: "HTTP alternativo", class: PortClass::Web },
    PortProfile { port: 8086, service: "InfluxDB", class: PortClass::Database },
    PortProfile { port: 8500, service: "Consul", class: PortClass::Infrastructure },
    PortProfile { port: 9000, service: "Aplicación / SonarQube", class: PortClass::Web },
    PortProfile { port: 9042, service: "Cassandra", class: PortClass::Database },
    PortProfile { port: 9200, service: "Elasticsearch", class: PortClass::Database },
    PortProfile { port: 10250, service: "kubelet", class: PortClass::Infrastructure },
    PortProfile { port: 11211, service: "Memcached", class: PortClass::Database },
    PortProfile { port: 15672, service: "Consola de RabbitMQ", class: PortClass::Infrastructure },
    PortProfile { port: 27017, service: "MongoDB", class: PortClass::Database },
    PortProfile { port: 27018, service: "MongoDB shard", class: PortClass::Database },
];

/// Look up a port in the curated catalog.
pub fn port_profile(port: u16) -> Option<PortProfile> {
    PORT_CATALOG.iter().copied().find(|entry| entry.port == port)
}

/// Human-facing service name for a port, falling back to the port number.
pub fn service_name(port: u16) -> String {
    port_profile(port).map_or_else(|| format!("puerto {port}"), |entry| entry.service.to_owned())
}

/// A socket the machine is currently accepting connections on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub scope: BindScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

impl ListeningSocket {
    pub fn new(protocol: Protocol, address: impl Into<String>, port: u16) -> Self {
        let address = address.into();
        let scope = BindScope::classify(&address);
        Self { protocol, address, port, scope, process: None, pid: None }
    }

    #[must_use]
    pub fn with_process(mut self, process: Option<String>, pid: Option<u32>) -> Self {
        self.process = process;
        self.pid = pid;
        self
    }

    /// Endpoint in `address:port` form, bracketing IPv6 literals.
    pub fn endpoint(&self) -> String {
        if self.address.contains(':') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }

    pub fn class(&self) -> PortClass {
        port_profile(self.port).map_or(PortClass::Other, |entry| entry.class)
    }
}

/// An established connection observed on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePeer {
    pub remote_address: String,
    pub remote_port: u16,
    pub local_port: u16,
    #[serde(default = "default_peer_count")]
    pub connections: u32,
}

const fn default_peer_count() -> u32 {
    1
}

/// Result of an authentication attempt seen by the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthOutcome {
    Failure,
    Success,
}

impl AuthOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failure => "failure",
            Self::Success => "success",
        }
    }
}

/// Aggregated authentication attempts from one source address.
///
/// The agent aggregates before sending: RootCause never ships raw log lines,
/// which keeps the payload small and the personal data off the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEvent {
    pub service: String,
    pub source_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub outcome: AuthOutcome,
    pub count: u32,
    pub last_seen: DateTime<Utc>,
}

/// Fingerprint of a file whose content must not change unnoticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedFile {
    pub path: String,
    pub digest: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<DateTime<Utc>>,
    /// Unix permission bits, when the platform exposes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

impl WatchedFile {
    /// True when the file is writable by users outside its owner and group.
    pub fn is_world_writable(&self) -> bool {
        self.mode.is_some_and(|mode| mode & 0o002 != 0)
    }
}

/// Host firewall state as reported by the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    pub engine: String,
    pub enabled: bool,
    #[serde(default)]
    pub rule_count: u32,
    #[serde(default)]
    pub default_inbound_deny: bool,
}

/// A surface the agent was unable to inspect during this cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionGap {
    pub surface: String,
    pub reason: String,
}

impl CollectionGap {
    pub fn new(surface: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { surface: surface.into(), reason: reason.into() }
    }
}

/// Everything security-relevant a single collection cycle produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySignals {
    #[serde(default)]
    pub listeners: Vec<ListeningSocket>,
    #[serde(default)]
    pub peers: Vec<RemotePeer>,
    #[serde(default)]
    pub auth_events: Vec<AuthEvent>,
    #[serde(default)]
    pub watched_files: Vec<WatchedFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<FirewallState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_security_updates: Option<u32>,
    /// What the agent could **not** collect, and why.
    ///
    /// A gap is reported, never hidden: an empty listener list because the
    /// platform is unsupported must not read as "no open ports".
    #[serde(default)]
    pub collection_gaps: Vec<CollectionGap>,
}

impl SecuritySignals {
    /// Number of distinct remote addresses connected to the machine.
    pub fn distinct_peers(&self) -> usize {
        self.peers
            .iter()
            .map(|peer| peer.remote_address.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Failed attempts grouped by source address.
    pub fn failures_by_source(&self) -> BTreeMap<&str, u32> {
        let mut grouped = BTreeMap::new();
        for event in &self.auth_events {
            if event.outcome == AuthOutcome::Failure {
                *grouped.entry(event.source_address.as_str()).or_insert(0) += event.count;
            }
        }
        grouped
    }

    /// Listeners reachable from outside the machine.
    pub fn exposed_listeners(&self) -> impl Iterator<Item = &ListeningSocket> {
        self.listeners.iter().filter(|socket| socket.scope != BindScope::Loopback)
    }

    pub fn has_gap(&self, surface: &str) -> bool {
        self.collection_gaps.iter().any(|gap| gap.surface == surface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses_are_not_exposed() {
        assert_eq!(BindScope::classify("127.0.0.1"), BindScope::Loopback);
        assert_eq!(BindScope::classify("::1"), BindScope::Loopback);
        assert_eq!(BindScope::classify("[::1]"), BindScope::Loopback);
    }

    #[test]
    fn wildcard_addresses_are_public() {
        assert_eq!(BindScope::classify("0.0.0.0"), BindScope::Public);
        assert_eq!(BindScope::classify("::"), BindScope::Public);
        assert_eq!(BindScope::classify("*"), BindScope::Public);
    }

    #[test]
    fn rfc1918_and_ula_are_private() {
        assert_eq!(BindScope::classify("10.0.0.5"), BindScope::Private);
        assert_eq!(BindScope::classify("192.168.1.20"), BindScope::Private);
        assert_eq!(BindScope::classify("172.16.4.4"), BindScope::Private);
        assert_eq!(BindScope::classify("100.64.0.1"), BindScope::Private);
        assert_eq!(BindScope::classify("fd00::1"), BindScope::Private);
        assert_eq!(BindScope::classify("fe80::1"), BindScope::Private);
    }

    #[test]
    fn unparseable_addresses_fail_towards_the_worse_case() {
        assert_eq!(BindScope::classify("no-es-una-ip"), BindScope::Public);
    }

    #[test]
    fn public_addresses_are_public() {
        assert_eq!(BindScope::classify("203.0.113.9"), BindScope::Public);
        assert_eq!(BindScope::classify("2001:db8::1"), BindScope::Public);
    }

    #[test]
    fn catalog_stays_sorted_and_unique() {
        let mut previous = 0;
        for entry in PORT_CATALOG {
            assert!(entry.port > previous, "catalog must stay sorted and unique: {}", entry.port);
            previous = entry.port;
        }
    }

    #[test]
    fn known_ports_resolve_to_their_class() {
        assert_eq!(port_profile(5432).unwrap().class, PortClass::Database);
        assert_eq!(port_profile(3389).unwrap().class, PortClass::RemoteAdmin);
        assert!(port_profile(49213).is_none());
        assert_eq!(service_name(49213), "puerto 49213");
    }

    #[test]
    fn ipv6_endpoints_are_bracketed() {
        let socket = ListeningSocket::new(Protocol::Tcp, "::", 443);
        assert_eq!(socket.endpoint(), "[::]:443");
        let socket = ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 443);
        assert_eq!(socket.endpoint(), "0.0.0.0:443");
    }

    #[test]
    fn world_writable_mode_is_detected() {
        let file = WatchedFile {
            path: "/etc/ssh/sshd_config".to_owned(),
            digest: "abc".to_owned(),
            size_bytes: 10,
            modified_at: None,
            mode: Some(0o666),
        };
        assert!(file.is_world_writable());
        let file = WatchedFile { mode: Some(0o600), ..file };
        assert!(!file.is_world_writable());
    }

    #[test]
    fn failures_are_grouped_by_source_and_successes_ignored() {
        let signals = SecuritySignals {
            auth_events: vec![
                AuthEvent {
                    service: "sshd".to_owned(),
                    source_address: "203.0.113.10".to_owned(),
                    username: Some("root".to_owned()),
                    outcome: AuthOutcome::Failure,
                    count: 40,
                    last_seen: Utc::now(),
                },
                AuthEvent {
                    service: "sshd".to_owned(),
                    source_address: "203.0.113.10".to_owned(),
                    username: Some("admin".to_owned()),
                    outcome: AuthOutcome::Failure,
                    count: 12,
                    last_seen: Utc::now(),
                },
                AuthEvent {
                    service: "sshd".to_owned(),
                    source_address: "203.0.113.10".to_owned(),
                    username: Some("admin".to_owned()),
                    outcome: AuthOutcome::Success,
                    count: 1,
                    last_seen: Utc::now(),
                },
            ],
            ..SecuritySignals::default()
        };
        assert_eq!(signals.failures_by_source().get("203.0.113.10"), Some(&52));
    }

    #[test]
    fn exposed_listeners_exclude_loopback() {
        let signals = SecuritySignals {
            listeners: vec![
                ListeningSocket::new(Protocol::Tcp, "127.0.0.1", 5432),
                ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 22),
            ],
            ..SecuritySignals::default()
        };
        let exposed: Vec<_> = signals.exposed_listeners().collect();
        assert_eq!(exposed.len(), 1);
        assert_eq!(exposed[0].port, 22);
    }
}
