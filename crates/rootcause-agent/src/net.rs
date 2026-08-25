//! What this machine is listening on, and who is currently talking to it.
//!
//! Three platforms expose the same fact in three different shapes. Each shape
//! gets a pure parser with its own fixtures, so the risky part — reading text
//! written by someone else's tool — is verified on every build, on every OS.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use rootcause_core::security::{BindScope, CollectionGap, ListeningSocket, Protocol, RemotePeer};

use crate::probe;

/// Upper bound on the sockets reported in one cycle.
///
/// A host under a scan can hold tens of thousands of connections; shipping them
/// all would turn the sensor into the incident.
const MAX_LISTENERS: usize = 256;
const MAX_PEERS: usize = 512;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything one network collection cycle produced.
#[derive(Debug, Default)]
pub struct NetworkSurface {
    pub listeners: Vec<ListeningSocket>,
    pub peers: Vec<RemotePeer>,
    pub gaps: Vec<CollectionGap>,
}

impl NetworkSurface {
    fn gap(surface: &str, reason: String) -> Self {
        Self { gaps: vec![CollectionGap::new(surface, reason)], ..Self::default() }
    }

    fn truncate(mut self) -> Self {
        if self.listeners.len() > MAX_LISTENERS {
            self.listeners.truncate(MAX_LISTENERS);
            self.gaps.push(CollectionGap::new(
                "listeners",
                format!("se reportan los primeros {MAX_LISTENERS} sockets en escucha"),
            ));
        }
        if self.peers.len() > MAX_PEERS {
            self.peers.truncate(MAX_PEERS);
            self.gaps.push(CollectionGap::new(
                "peers",
                format!("se reportan los primeros {MAX_PEERS} orígenes conectados"),
            ));
        }
        self
    }
}

/// Inspect the local network surface using whatever the platform offers.
pub async fn collect() -> NetworkSurface {
    let surface = if cfg!(target_os = "linux") {
        collect_linux().await
    } else if cfg!(target_os = "windows") {
        collect_windows().await
    } else if cfg!(target_os = "macos") {
        collect_macos().await
    } else {
        NetworkSurface::gap(
            "listeners",
            "esta plataforma no tiene un recolector de sockets implementado".to_owned(),
        )
    };
    surface.truncate()
}

async fn collect_linux() -> NetworkSurface {
    match probe::run("ss", &["-tunaH"], PROBE_TIMEOUT).await {
        Ok(output) => parse_ss(&output),
        Err(error) => {
            let mut surface = read_proc_net().await;
            if surface.listeners.is_empty() && surface.peers.is_empty() {
                surface.gaps.push(CollectionGap::new("listeners", error.reason("ss")));
            }
            surface
        }
    }
}

async fn collect_windows() -> NetworkSurface {
    match probe::run("netstat", &["-ano"], PROBE_TIMEOUT).await {
        Ok(output) => parse_netstat_windows(&output),
        Err(error) => NetworkSurface::gap("listeners", error.reason("netstat")),
    }
}

async fn collect_macos() -> NetworkSurface {
    match probe::run("netstat", &["-an"], PROBE_TIMEOUT).await {
        Ok(output) => parse_netstat_bsd(&output),
        Err(error) => NetworkSurface::gap("listeners", error.reason("netstat")),
    }
}

async fn read_proc_net() -> NetworkSurface {
    let mut surface = NetworkSurface::default();
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let parsed = parse_proc_net(&content, protocol, ipv6);
            surface.listeners.extend(parsed.listeners);
            surface.peers.extend(parsed.peers);
        }
    }
    surface.peers = aggregate_peers(surface.peers);
    surface
}

/// Collapse repeated connections from the same address into one entry.
fn aggregate_peers(peers: Vec<RemotePeer>) -> Vec<RemotePeer> {
    let mut grouped: BTreeMap<(String, u16), RemotePeer> = BTreeMap::new();
    for peer in peers {
        grouped
            .entry((peer.remote_address.clone(), peer.local_port))
            .and_modify(|existing| existing.connections = existing.connections.saturating_add(1))
            .or_insert(peer);
    }
    grouped.into_values().collect()
}

/// Split `address:port`, tolerating bracketed IPv6 literals.
fn split_endpoint(value: &str) -> Option<(String, u16)> {
    let (address, port) = value.rsplit_once(':')?;
    let port = port.trim().parse::<u16>().ok()?;
    let address = address.trim().trim_start_matches('[').trim_end_matches(']');
    let address = address.split('%').next().unwrap_or(address);
    Some((normalise_wildcard(address), port))
}

/// Split a BSD `address.port` endpoint, where the port follows the last dot.
fn split_endpoint_bsd(value: &str) -> Option<(String, u16)> {
    let (address, port) = value.rsplit_once('.')?;
    let port = port.trim().parse::<u16>().ok()?;
    let address = address.split('%').next().unwrap_or(address);
    Some((normalise_wildcard(address), port))
}

fn normalise_wildcard(address: &str) -> String {
    match address {
        "*" | "" => "0.0.0.0".to_owned(),
        other => other.to_owned(),
    }
}

fn is_listen_state(state: &str) -> bool {
    matches!(
        state.trim().to_ascii_uppercase().as_str(),
        "LISTEN" | "LISTENING" | "ESCUCHANDO" | "UNCONN"
    )
}

fn is_established_state(state: &str) -> bool {
    matches!(
        state.trim().to_ascii_uppercase().as_str(),
        "ESTAB" | "ESTABLISHED" | "ESTABLECIDO" | "ESTABLECIDA"
    )
}

/// Extract `sshd` and `812` from `users:(("sshd",pid=812,fd=3))`.
fn parse_ss_process(field: &str) -> (Option<String>, Option<u32>) {
    let Some(rest) = field.split_once("((").map(|(_, rest)| rest) else {
        return (None, None);
    };
    let name = rest.split('"').nth(1).map(str::to_owned);
    let pid = rest
        .split("pid=")
        .nth(1)
        .and_then(|value| value.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|value| value.parse::<u32>().ok());
    (name, pid)
}

/// Parse the output of `ss -tunaH` (Linux).
pub fn parse_ss(output: &str) -> NetworkSurface {
    let mut surface = NetworkSurface::default();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let protocol = match fields[0] {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => continue,
        };
        let state = fields[1];
        let Some((local_address, local_port)) = split_endpoint(fields[4]) else { continue };

        if is_listen_state(state) {
            let (process, pid) = parse_ss_process(fields.get(6).copied().unwrap_or_default());
            surface.listeners.push(
                ListeningSocket::new(protocol, local_address, local_port)
                    .with_process(process, pid),
            );
        } else if is_established_state(state)
            && let Some((remote_address, remote_port)) = split_endpoint(fields[5])
        {
            surface.peers.push(RemotePeer {
                remote_address,
                remote_port,
                local_port,
                connections: 1,
            });
        }
    }
    surface.peers = aggregate_peers(std::mem::take(&mut surface.peers));
    surface
}

/// Parse the output of `netstat -ano` (Windows).
pub fn parse_netstat_windows(output: &str) -> NetworkSurface {
    let mut surface = NetworkSurface::default();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let protocol = match fields[0].to_ascii_uppercase().as_str() {
            "TCP" => Protocol::Tcp,
            "UDP" => Protocol::Udp,
            _ => continue,
        };
        let Some((local_address, local_port)) = split_endpoint(fields[1]) else { continue };

        // UDP rows carry no state column; they are listeners by nature.
        let state = if protocol == Protocol::Udp {
            "LISTENING"
        } else {
            fields.get(3).copied().unwrap_or_default()
        };
        let pid = fields.last().and_then(|value| value.parse::<u32>().ok());

        if is_listen_state(state) {
            surface.listeners.push(
                ListeningSocket::new(protocol, local_address, local_port).with_process(None, pid),
            );
        } else if is_established_state(state)
            && let Some((remote_address, remote_port)) = split_endpoint(fields[2])
        {
            surface.peers.push(RemotePeer {
                remote_address,
                remote_port,
                local_port,
                connections: 1,
            });
        }
    }
    surface.peers = aggregate_peers(std::mem::take(&mut surface.peers));
    surface
}

/// Parse the output of `netstat -an` (macOS and other BSD systems).
pub fn parse_netstat_bsd(output: &str) -> NetworkSurface {
    let mut surface = NetworkSurface::default();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let protocol = match fields[0] {
            "tcp4" | "tcp6" | "tcp" => Protocol::Tcp,
            "udp4" | "udp6" | "udp" => Protocol::Udp,
            _ => continue,
        };
        let Some((local_address, local_port)) = split_endpoint_bsd(fields[3]) else { continue };
        let state = fields.get(5).copied().unwrap_or_default();

        if protocol == Protocol::Udp || is_listen_state(state) {
            surface.listeners.push(ListeningSocket::new(protocol, local_address, local_port));
        } else if is_established_state(state)
            && let Some((remote_address, remote_port)) = split_endpoint_bsd(fields[4])
        {
            surface.peers.push(RemotePeer {
                remote_address,
                remote_port,
                local_port,
                connections: 1,
            });
        }
    }
    surface.peers = aggregate_peers(std::mem::take(&mut surface.peers));
    surface
}

/// Decode the little-endian hexadecimal address used by `/proc/net/*`.
fn parse_proc_address(value: &str, ipv6: bool) -> Option<String> {
    if ipv6 {
        if value.len() != 32 {
            return None;
        }
        let mut octets = [0_u8; 16];
        for (word, chunk) in value.as_bytes().chunks(8).enumerate() {
            let text = std::str::from_utf8(chunk).ok()?;
            let raw = u32::from_str_radix(text, 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&raw.to_le_bytes());
        }
        return Some(Ipv6Addr::from(octets).to_string());
    }
    if value.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(value, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_le_bytes()).to_string())
}

/// Parse one `/proc/net/{tcp,tcp6,udp,udp6}` table (Linux fallback).
pub fn parse_proc_net(content: &str, protocol: Protocol, ipv6: bool) -> NetworkSurface {
    let mut surface = NetworkSurface::default();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (local_hex, local_port_hex) = fields[1].split_once(':').unwrap_or_default();
        let Some(local_address) = parse_proc_address(local_hex, ipv6) else { continue };
        let Ok(local_port) = u16::from_str_radix(local_port_hex, 16) else { continue };
        let state = fields[3];

        // 0A is TCP LISTEN; UDP sockets have no listening state of their own.
        if state == "0A" || (protocol == Protocol::Udp && state == "07") {
            surface.listeners.push(ListeningSocket::new(protocol, local_address, local_port));
        } else if state == "01" {
            let (remote_hex, remote_port_hex) = fields[2].split_once(':').unwrap_or_default();
            let Some(remote_address) = parse_proc_address(remote_hex, ipv6) else { continue };
            let Ok(remote_port) = u16::from_str_radix(remote_port_hex, 16) else { continue };
            surface.peers.push(RemotePeer {
                remote_address,
                remote_port,
                local_port,
                connections: 1,
            });
        }
    }
    surface
}

/// Ports this host publishes beyond loopback, for the agent log line.
pub fn exposed_ports(listeners: &[ListeningSocket]) -> Vec<u16> {
    let mut ports: Vec<u16> = listeners
        .iter()
        .filter(|socket| socket.scope != BindScope::Loopback)
        .map(|socket| socket.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS_OUTPUT: &str = "\
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:((\"sshd\",pid=812,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:((\"postgres\",pid=901,fd=5))
tcp   LISTEN 0      511             [::]:80            [::]:*    users:((\"nginx\",pid=1020,fd=6))
tcp   ESTAB  0      0           10.0.0.5:22     203.0.113.8:51514
tcp   ESTAB  0      0           10.0.0.5:22     203.0.113.8:51515
tcp   TIME-WAIT 0   0           10.0.0.5:443    198.51.100.4:33221
";

    const NETSTAT_WINDOWS: &str = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1044
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    10.0.0.5:52134         93.184.216.34:443      ESTABLISHED     2312
  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       880
  UDP    0.0.0.0:500            *:*                                    2116
";

    const NETSTAT_BSD: &str = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.5432         *.*                    LISTEN
tcp6       0      0  *.80                   *.*                    LISTEN
tcp4       0      0  192.168.1.5.52134      93.184.216.34.443      ESTABLISHED
";

    const PROC_NET_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 12346 1
   2: 0500000A:0016 087100CB:C92A 01 00000000:00000000 00:00000000 00000000     0        0 12347 1
";

    #[test]
    fn ss_reports_listeners_with_their_process() {
        let surface = parse_ss(SS_OUTPUT);
        let ssh = surface.listeners.iter().find(|socket| socket.port == 22).unwrap();
        assert_eq!(ssh.address, "0.0.0.0");
        assert_eq!(ssh.scope, BindScope::Public);
        assert_eq!(ssh.process.as_deref(), Some("sshd"));
        assert_eq!(ssh.pid, Some(812));
    }

    #[test]
    fn ss_keeps_loopback_services_out_of_the_exposed_set() {
        let surface = parse_ss(SS_OUTPUT);
        let postgres = surface.listeners.iter().find(|socket| socket.port == 5432).unwrap();
        assert_eq!(postgres.scope, BindScope::Loopback);
        assert_eq!(exposed_ports(&surface.listeners), vec![22, 68, 80]);
    }

    #[test]
    fn ss_unwraps_bracketed_ipv6_listeners() {
        let surface = parse_ss(SS_OUTPUT);
        let nginx = surface.listeners.iter().find(|socket| socket.port == 80).unwrap();
        assert_eq!(nginx.address, "::");
        assert_eq!(nginx.scope, BindScope::Public);
    }

    #[test]
    fn ss_aggregates_repeated_connections_from_one_address() {
        let surface = parse_ss(SS_OUTPUT);
        assert_eq!(surface.peers.len(), 1);
        assert_eq!(surface.peers[0].remote_address, "203.0.113.8");
        assert_eq!(surface.peers[0].connections, 2);
        assert_eq!(surface.peers[0].local_port, 22);
    }

    #[test]
    fn windows_netstat_separates_listeners_from_connections() {
        let surface = parse_netstat_windows(NETSTAT_WINDOWS);
        assert_eq!(surface.listeners.len(), 4);
        assert_eq!(surface.peers.len(), 1);
        assert_eq!(surface.peers[0].remote_address, "93.184.216.34");
        let smb = surface.listeners.iter().find(|socket| socket.port == 445).unwrap();
        assert_eq!(smb.scope, BindScope::Public);
        assert_eq!(smb.pid, Some(4));
    }

    #[test]
    fn windows_netstat_understands_a_localised_state_column() {
        let localised =
            "  TCP    0.0.0.0:3389           0.0.0.0:0              ESCUCHANDO      620";
        let surface = parse_netstat_windows(localised);
        assert_eq!(surface.listeners.len(), 1);
        assert_eq!(surface.listeners[0].port, 3389);
    }

    #[test]
    fn bsd_netstat_uses_a_dot_before_the_port() {
        let surface = parse_netstat_bsd(NETSTAT_BSD);
        assert_eq!(exposed_ports(&surface.listeners), vec![22, 80]);
        assert_eq!(surface.peers.len(), 1);
        assert_eq!(surface.peers[0].remote_port, 443);
    }

    #[test]
    fn proc_net_decodes_little_endian_addresses() {
        let surface = parse_proc_net(PROC_NET_TCP, Protocol::Tcp, false);
        let public = surface.listeners.iter().find(|socket| socket.port == 22).unwrap();
        assert_eq!(public.address, "0.0.0.0");
        let local = surface.listeners.iter().find(|socket| socket.port == 5432).unwrap();
        assert_eq!(local.address, "127.0.0.1");
        assert_eq!(surface.peers[0].remote_address, "203.0.113.8");
        assert_eq!(surface.peers[0].remote_port, 51498);
    }

    #[test]
    fn proc_net_decodes_ipv6_addresses() {
        let content = "  sl  local_address rem_address st\n   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A x x x x x x\n";
        let surface = parse_proc_net(content, Protocol::Tcp, true);
        assert_eq!(surface.listeners.len(), 1);
        assert_eq!(surface.listeners[0].address, "::");
    }

    #[test]
    fn garbage_input_produces_nothing_instead_of_panicking() {
        let parsers: [fn(&str) -> NetworkSurface; 3] =
            [parse_ss, parse_netstat_windows, parse_netstat_bsd];
        for parser in parsers {
            let surface = parser("no es una tabla\n\n:::\t\t\n1 2 3\n");
            assert!(surface.listeners.is_empty());
            assert!(surface.peers.is_empty());
        }
    }

    #[test]
    fn oversized_surfaces_are_truncated_and_the_truncation_is_declared() {
        let listeners = (0..MAX_LISTENERS + 10)
            .map(|n| ListeningSocket::new(Protocol::Tcp, "0.0.0.0", 1000 + n as u16))
            .collect();
        let surface = NetworkSurface { listeners, ..NetworkSurface::default() }.truncate();
        assert_eq!(surface.listeners.len(), MAX_LISTENERS);
        assert!(surface.gaps.iter().any(|gap| gap.surface == "listeners"));
    }

    #[test]
    fn a_process_field_without_a_pid_does_not_break_parsing() {
        assert_eq!(parse_ss_process("users:((\"nginx\"))"), (Some("nginx".to_owned()), None));
        assert_eq!(parse_ss_process(""), (None, None));
    }
}
