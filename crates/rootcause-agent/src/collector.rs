use std::{collections::BTreeMap, thread};

use anyhow::Context;
use chrono::Utc;
use rootcause_core::{AssetRegistration, MetricSample, Platform};
use sysinfo::{Disks, MINIMUM_CPU_UPDATE_INTERVAL, Networks, System};

use crate::stable_agent_id;

pub struct Collector {
    system: System,
    disks: Disks,
    networks: Networks,
    registration: AssetRegistration,
}

impl Collector {
    pub fn new(labels: BTreeMap<String, String>) -> Self {
        let hostname = System::host_name().unwrap_or_else(|| "unknown-host".to_owned());
        let mut system = System::new();
        system.refresh_memory();
        system.refresh_cpu_usage();
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
        }
    }

    pub fn registration(&self) -> AssetRegistration {
        self.registration.clone()
    }

    pub fn collect(&mut self) -> anyhow::Result<MetricSample> {
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        self.disks.refresh(true);
        self.networks.refresh(true);

        let total_memory = self.system.total_memory();
        let memory_percent = percent(self.system.used_memory(), total_memory);
        let (disk_total, disk_used) = self.disks.iter().fold((0_u64, 0_u64), |acc, disk| {
            let total = disk.total_space();
            let used = total.saturating_sub(disk.available_space());
            (acc.0.saturating_add(total), acc.1.saturating_add(used))
        });
        let (network_rx_bytes, network_tx_bytes) =
            self.networks
                .iter()
                .fold((0_u64, 0_u64), |acc, (_, network)| {
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
        };
        sample
            .validate()
            .map_err(anyhow::Error::msg)
            .context("collector produced invalid telemetry")?;
        Ok(sample)
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
    fn percent_handles_empty_total() {
        assert_eq!(percent(0, 0), 0.0);
    }

    #[test]
    fn percent_is_bounded() {
        assert_eq!(percent(150, 100), 100.0);
        assert_eq!(percent(25, 100), 25.0);
    }
}
