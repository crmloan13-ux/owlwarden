//! The scan budget: how much time and how many requests are left.
//!
//! A budget is shared by every detector in a run, so it is interior-mutable and
//! thread-safe. Detectors ask; they never set. Spending is a compare-and-swap,
//! so two detectors racing at the last remaining request cannot both win.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::limits;

/// Remaining resources for a scan.
#[derive(Debug)]
pub struct Budget {
    requests_remaining: AtomicU32,
    started: Instant,
    total_time: Duration,
}

impl Budget {
    /// Creates a budget with explicit caps.
    #[must_use]
    pub fn new(max_requests: u32, total_time: Duration) -> Self {
        Self {
            requests_remaining: AtomicU32::new(max_requests),
            started: Instant::now(),
            total_time,
        }
    }

    /// A budget for a passive, static-only run: no requests at all.
    ///
    /// Used for every v0.0 scan. If a detector tries to send anything, it is
    /// refused here as well as by the deny-all scope.
    #[must_use]
    pub fn passive() -> Self {
        Self::new(0, limits::scan::TOTAL_TIME)
    }

    /// Claims one request. Returns `false` when the budget is spent.
    ///
    /// Uses a CAS loop rather than `fetch_sub` so the counter can never
    /// underflow past zero under concurrency.
    pub fn try_spend_request(&self) -> bool {
        let mut current = self.requests_remaining.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return false;
            }
            match self.requests_remaining.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Requests still available.
    #[must_use]
    pub fn requests_remaining(&self) -> u32 {
        self.requests_remaining.load(Ordering::Acquire)
    }

    /// Time since the scan started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Whether the wall-clock budget is spent.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.elapsed() >= self.total_time
    }

    /// Time left before the scan must stop, saturating at zero.
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        self.total_time.saturating_sub(self.elapsed())
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(limits::scan::MAX_REQUESTS, limits::scan::TOTAL_TIME)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn passive_budget_permits_no_requests() {
        let budget = Budget::passive();
        assert!(!budget.try_spend_request());
        assert_eq!(budget.requests_remaining(), 0);
    }

    #[test]
    fn spending_stops_at_zero_under_concurrency() {
        let budget = std::sync::Arc::new(Budget::new(100, Duration::from_secs(60)));
        let granted = std::sync::Arc::new(AtomicU32::new(0));

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let budget = std::sync::Arc::clone(&budget);
                let granted = std::sync::Arc::clone(&granted);
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        if budget.try_spend_request() {
                            granted.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            assert!(thread.join().is_ok());
        }

        // 400 attempts against a 100-request budget: exactly 100 win.
        assert_eq!(granted.load(Ordering::Acquire), 100);
        assert_eq!(budget.requests_remaining(), 0);
    }

    #[test]
    fn expired_budget_reports_zero_remaining_time() {
        let budget = Budget::new(1, Duration::ZERO);
        assert!(budget.is_expired());
        assert_eq!(budget.time_remaining(), Duration::ZERO);
    }
}
