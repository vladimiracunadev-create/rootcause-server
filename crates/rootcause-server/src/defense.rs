//! The control plane's own perimeter.
//!
//! A server that watches other servers is itself a target: it holds the token
//! that reaches every agent and the evidence of every incident. This module is
//! what stands between that and an open Internet — a per-address token bucket
//! and a lockout that turns credential guessing into a dead end.
//!
//! Everything here is in memory on purpose. Perimeter state must survive a
//! burst, not a restart, and a restart is exactly when an operator wants a
//! clean slate.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Addresses tracked at once before the oldest entries are dropped.
const MAX_TRACKED_CLIENTS: usize = 20_000;

/// What the perimeter decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed to authentication.
    Allow,
    /// Too many requests from this address.
    RateLimited { retry_after_seconds: u64 },
    /// This address is serving a lockout for repeated authentication failures.
    LockedOut { retry_after_seconds: u64 },
}

impl Decision {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::RateLimited { .. } => "rate.limit",
            Self::LockedOut { .. } => "auth.lockout",
        }
    }

    pub const fn retry_after_seconds(self) -> u64 {
        match self {
            Self::Allow => 0,
            Self::RateLimited { retry_after_seconds } | Self::LockedOut { retry_after_seconds } => {
                retry_after_seconds
            }
        }
    }
}

#[derive(Debug)]
struct ClientState {
    tokens: f64,
    last_seen: Instant,
    failures: u32,
    locked_until: Option<Instant>,
}

/// Per-address rate limiting and authentication lockout.
#[derive(Debug)]
pub struct Perimeter {
    clients: Mutex<HashMap<IpAddr, ClientState>>,
    capacity: f64,
    refill_per_second: f64,
    lockout_threshold: u32,
    lockout: Duration,
}

impl Perimeter {
    pub fn new(rate_limit_per_minute: u32, lockout_threshold: u32, lockout_seconds: u64) -> Self {
        let capacity = f64::from(rate_limit_per_minute.max(1));
        Self {
            clients: Mutex::new(HashMap::new()),
            capacity,
            refill_per_second: capacity / 60.0,
            lockout_threshold: lockout_threshold.max(1),
            lockout: Duration::from_secs(lockout_seconds.max(1)),
        }
    }

    /// Consume one request slot for `address`.
    pub fn check(&self, address: IpAddr, now: Instant) -> Decision {
        let mut clients = self.lock();
        if clients.len() >= MAX_TRACKED_CLIENTS && !clients.contains_key(&address) {
            evict_oldest(&mut clients);
        }
        let state = clients.entry(address).or_insert_with(|| ClientState {
            tokens: self.capacity,
            last_seen: now,
            failures: 0,
            locked_until: None,
        });

        if let Some(until) = state.locked_until {
            if until > now {
                return Decision::LockedOut { retry_after_seconds: seconds_until(until, now) };
            }
            // The lockout expired: forgive the counter, keep watching.
            state.locked_until = None;
            state.failures = 0;
        }

        let elapsed = now.saturating_duration_since(state.last_seen).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_second).min(self.capacity);
        state.last_seen = now;

        if state.tokens < 1.0 {
            let missing = 1.0 - state.tokens;
            return Decision::RateLimited {
                retry_after_seconds: (missing / self.refill_per_second).ceil().max(1.0) as u64,
            };
        }
        state.tokens -= 1.0;
        Decision::Allow
    }

    /// Record a rejected credential. Returns `true` when this locked the address.
    pub fn record_failure(&self, address: IpAddr, now: Instant) -> bool {
        let mut clients = self.lock();
        let state = clients.entry(address).or_insert_with(|| ClientState {
            tokens: self.capacity,
            last_seen: now,
            failures: 0,
            locked_until: None,
        });
        state.failures = state.failures.saturating_add(1);
        state.last_seen = now;
        if state.failures >= self.lockout_threshold && state.locked_until.is_none() {
            state.locked_until = Some(now + self.lockout);
            return true;
        }
        false
    }

    /// A valid credential clears the failure counter for that address.
    pub fn record_success(&self, address: IpAddr) {
        if let Some(state) = self.lock().get_mut(&address) {
            state.failures = 0;
            state.locked_until = None;
        }
    }

    /// Addresses currently serving a lockout.
    pub fn locked_sources(&self, now: Instant) -> usize {
        self.lock()
            .values()
            .filter(|state| state.locked_until.is_some_and(|until| until > now))
            .count()
    }

    /// Drop clients that have been idle longer than `idle`.
    pub fn prune(&self, now: Instant, idle: Duration) {
        self.lock().retain(|_, state| {
            state.locked_until.is_some_and(|until| until > now)
                || now.saturating_duration_since(state.last_seen) < idle
        });
    }

    pub fn tracked_clients(&self) -> usize {
        self.lock().len()
    }

    /// A poisoned perimeter mutex must not take the server down: the lock only
    /// ever guards a map of counters, so recovering it is always safe.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, ClientState>> {
        self.clients.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn seconds_until(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

fn evict_oldest(clients: &mut HashMap<IpAddr, ClientState>) {
    if let Some(oldest) =
        clients.iter().min_by_key(|(_, state)| state.last_seen).map(|(address, _)| *address)
    {
        clients.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn address(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn ordinary_traffic_is_allowed() {
        let perimeter = Perimeter::new(600, 10, 300);
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(perimeter.check(address(1), now), Decision::Allow);
        }
    }

    #[test]
    fn a_burst_beyond_the_budget_is_rate_limited_with_a_retry_hint() {
        let perimeter = Perimeter::new(60, 10, 300);
        let now = Instant::now();
        for _ in 0..60 {
            assert!(perimeter.check(address(1), now).is_allowed());
        }
        let decision = perimeter.check(address(1), now);
        assert!(matches!(decision, Decision::RateLimited { .. }));
        assert!(decision.retry_after_seconds() >= 1);
        assert_eq!(decision.reason(), "rate.limit");
    }

    #[test]
    fn the_budget_refills_over_time() {
        let perimeter = Perimeter::new(60, 10, 300);
        let now = Instant::now();
        for _ in 0..60 {
            perimeter.check(address(1), now);
        }
        assert!(!perimeter.check(address(1), now).is_allowed());
        assert!(perimeter.check(address(1), now + Duration::from_secs(2)).is_allowed());
    }

    #[test]
    fn one_address_never_starves_another() {
        let perimeter = Perimeter::new(60, 10, 300);
        let now = Instant::now();
        for _ in 0..60 {
            perimeter.check(address(1), now);
        }
        assert!(!perimeter.check(address(1), now).is_allowed());
        assert!(perimeter.check(address(2), now).is_allowed());
    }

    #[test]
    fn repeated_credential_failures_lock_the_address_out() {
        let perimeter = Perimeter::new(600, 3, 300);
        let now = Instant::now();
        assert!(!perimeter.record_failure(address(1), now));
        assert!(!perimeter.record_failure(address(1), now));
        assert!(perimeter.record_failure(address(1), now), "the third failure must lock out");

        let decision = perimeter.check(address(1), now);
        assert!(matches!(decision, Decision::LockedOut { .. }));
        assert_eq!(decision.reason(), "auth.lockout");
        assert_eq!(perimeter.locked_sources(now), 1);
    }

    #[test]
    fn a_lockout_expires_and_forgives_the_counter() {
        let perimeter = Perimeter::new(600, 3, 60);
        let now = Instant::now();
        for _ in 0..3 {
            perimeter.record_failure(address(1), now);
        }
        assert!(!perimeter.check(address(1), now).is_allowed());

        let later = now + Duration::from_secs(61);
        assert!(perimeter.check(address(1), later).is_allowed());
        assert_eq!(perimeter.locked_sources(later), 0);
    }

    #[test]
    fn a_valid_credential_clears_the_failure_counter() {
        let perimeter = Perimeter::new(600, 3, 300);
        let now = Instant::now();
        perimeter.record_failure(address(1), now);
        perimeter.record_failure(address(1), now);
        perimeter.record_success(address(1));
        assert!(!perimeter.record_failure(address(1), now), "the counter must have restarted");
    }

    #[test]
    fn locking_out_one_address_does_not_lock_out_the_fleet() {
        let perimeter = Perimeter::new(600, 2, 300);
        let now = Instant::now();
        perimeter.record_failure(address(1), now);
        perimeter.record_failure(address(1), now);
        assert!(!perimeter.check(address(1), now).is_allowed());
        assert!(perimeter.check(address(9), now).is_allowed());
    }

    #[test]
    fn idle_clients_are_pruned_but_locked_ones_are_kept() {
        let perimeter = Perimeter::new(600, 2, 600);
        let now = Instant::now();
        perimeter.check(address(1), now);
        perimeter.record_failure(address(2), now);
        perimeter.record_failure(address(2), now);

        perimeter.prune(now + Duration::from_secs(400), Duration::from_secs(300));
        assert_eq!(perimeter.tracked_clients(), 1, "the locked address must survive the prune");
    }

    #[test]
    fn the_tracking_table_is_bounded() {
        let perimeter = Perimeter::new(600, 10, 300);
        let now = Instant::now();
        let mut clients = perimeter.lock();
        for index in 0..MAX_TRACKED_CLIENTS {
            clients.insert(
                IpAddr::V4(Ipv4Addr::from(index as u32)),
                ClientState { tokens: 1.0, last_seen: now, failures: 0, locked_until: None },
            );
        }
        drop(clients);
        assert_eq!(perimeter.tracked_clients(), MAX_TRACKED_CLIENTS);
        perimeter.check(address(1), now + Duration::from_secs(1));
        assert_eq!(perimeter.tracked_clients(), MAX_TRACKED_CLIENTS);
    }
}
