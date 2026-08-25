//! One collection cycle: resources first, then the security surface.

use std::{collections::BTreeMap, path::PathBuf, thread};

use anyhow::Context;
use chrono::Utc;
use rootcause_core::{
    models::{AssetRegistration, MetricSample, Platform},
    security::SecuritySignals,
};
use sysinfo::{Disks, MINIMUM_CPU_UPDATE_INTERVAL, Networks, System};

use crate::{authlog, baseline, integrity, net, stable_agent_id};

/// What the agent is allowed to look at during a cycle.
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// Collect the security surface as well as the resource metrics.
    pub security: bool,
    /// Files to fingerprint on every cycle.
    pub watched_files: Vec<PathBuf>,
    /// Minutes of authentication history to read per cycle.
    pub auth_window_minutes: u32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self { security: true, watched_files: integrity::default_paths(), auth_window_minutes: 15 }
    }
}

/// Holds the platform handles between cycles so rates stay meaningful.
#[derive(Debug)]
pub struct Collector {
    system: System,
    disks: Disks,
    networks: Networks,
    registration: AssetRegistration,
    config: CollectorConfig,
}

impl Collector {
    pub fn new(labels: BTreeMap<String, String>, config: CollectorConfig) -> Self {
        let hostname = System::host_name().unwrap_or_else(|| "unknown-host".to_owned());
        let mut system = System::new();
        system.refresh_memory();
        system.refresh_cpu_usage();
        // The first CPU reading is meaningless without a second one to diff.
        thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_cpu_usage();

        let registration = AssetRegistration {
            agent_id: stable_agent_id(&hostname),
            hostname,
            platform: Platform::current(),
            os_version: System::long_os_version(),
            kernel_version: System::kernel_version(),
            architecture: std::env::consts::ARCH.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            labels,
        };
        Self {
            system,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            registration,
            config,
        }
    }

    pub fn registration(&self) -> AssetRegistration {
        self.registration.clone()
    }

    /// Sample resource usage. Never fails on a healthy host.
    pub fn sample(&mut self) -> anyhow::Result<MetricSample> {
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        self.system.refresh_processes(sysinfo::ProcessesToUpdate::All, false);
        self.disks.refresh(true);
        self.networks.refresh(true);

        let total_memory = self.system.total_memory();
        let memory_percent = percent(self.system.used_memory(), total_memory);
        let (disk_total, disk_used, disk_free) =
            self.disks.iter().fold((0_u64, 0_u64, 0_u64), |acc, disk| {
                let total = disk.total_space();
                let available = disk.available_space();
                (
                    acc.0.saturating_add(total),
                    acc.1.saturating_add(total.saturating_sub(available)),
                    acc.2.saturating_add(available),
                )
            });
        let (network_rx_bytes, network_tx_bytes) =
            self.networks.iter().fold((0_u64, 0_u64), |acc, (_, network)| {
                (
                    acc.0.saturating_add(network.total_received()),
                    acc.1.saturating_add(network.total_transmitted()),
                )
            });
        let load = System::load_average();

        let sample = MetricSample {
            agent_id: self.registration.agent_id,
            observed_at: Utc::now(),
            cpu_percent: self.system.global_cpu_usage().clamp(0.0, 100.0),
            memory_percent,
            disk_percent: percent(disk_used, disk_total),
            uptime_seconds: System::uptime(),
            load_average: Some([load.one, load.five, load.fifteen]),
            network_rx_bytes,
            network_tx_bytes,
            disk_free_bytes: Some(disk_free),
            process_count: u32::try_from(self.system.processes().len()).ok(),
        };
        sample
            .validate()
            .map_err(anyhow::Error::msg)
            .context("collector produced invalid telemetry")?;
        Ok(sample)
    }

    /// Inspect the security surface: sockets, logins, files and baseline controls.
    ///
    /// Never returns an error: a surface that could not be read becomes a
    /// declared gap, because a failed probe must not silence the whole cycle.
    pub async fn security(&self) -> SecuritySignals {
        if !self.config.security {
            return SecuritySignals {
                collection_gaps: vec![rootcause_core::security::CollectionGap::new(
                    "security",
                    "la recolección de seguridad está desactivada en este agente".to_owned(),
                )],
                ..SecuritySignals::default()
            };
        }

        let now = Utc::now();
        let (network, auth, files, controls) = tokio::join!(
            net::collect(),
            authlog::collect(self.config.auth_window_minutes, now),
            integrity::collect(&self.config.watched_files),
            baseline::collect(),
        );

        let mut collection_gaps = network.gaps;
        collection_gaps.extend(auth.gaps);
        collection_gaps.extend(files.gaps);
        collection_gaps.extend(controls.gaps);

        SecuritySignals {
            listeners: network.listeners,
            peers: network.peers,
            auth_events: auth.events,
            watched_files: files.files,
            firewall: controls.firewall,
            pending_security_updates: controls.pending_security_updates,
            collection_gaps,
        }
    }
}

fn percent(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    ((used as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_handles_an_empty_total() {
        assert_eq!(percent(0, 0), 0.0);
    }

    #[test]
    fn percent_is_bounded() {
        assert_eq!(percent(150, 100), 100.0);
        assert_eq!(percent(25, 100), 25.0);
    }

    #[test]
    fn the_default_configuration_inspects_the_security_surface() {
        let config = CollectorConfig::default();
        assert!(config.security);
        assert!(!config.watched_files.is_empty());
        assert!(config.auth_window_minutes > 0);
    }

    #[tokio::test]
    async fn disabling_security_declares_the_gap_instead_of_reporting_nothing() {
        let config = CollectorConfig { security: false, ..CollectorConfig::default() };
        let collector = Collector::new(BTreeMap::new(), config);
        let signals = collector.security().await;
        assert!(signals.listeners.is_empty());
        assert!(signals.has_gap("security"));
    }

    #[test]
    fn a_sample_from_this_machine_is_valid() {
        let mut collector = Collector::new(BTreeMap::new(), CollectorConfig::default());
        let sample = collector.sample().expect("the local host must produce a valid sample");
        assert!(sample.validate().is_ok());
        assert_eq!(sample.agent_id, collector.registration().agent_id);
    }
}
