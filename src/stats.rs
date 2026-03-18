use crate::luck::{SearchOdds, format_percent};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub struct Stats {
    started_at: Instant,
    total_keys: AtomicU64,
    found: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct StatsSnapshot {
    pub elapsed: Duration,
    pub total_keys: u64,
    pub found: u64,
    pub overall_keys_per_sec: f64,
}

impl Stats {
    #[inline]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            total_keys: AtomicU64::new(0),
            found: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn add_keys(&self, count: u64) {
        self.total_keys.fetch_add(count, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_match(&self) {
        self.found.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn snapshot(&self) -> StatsSnapshot {
        let elapsed = self.started_at.elapsed();
        let total_keys = self.total_keys.load(Ordering::Relaxed);
        let found = self.found.load(Ordering::Relaxed);
        let overall_keys_per_sec = if elapsed.is_zero() {
            0.0
        } else {
            total_keys as f64 / elapsed.as_secs_f64()
        };

        StatsSnapshot {
            elapsed,
            total_keys,
            found,
            overall_keys_per_sec,
        }
    }
}

pub fn spawn_reporter(
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    interval: Duration,
    odds: SearchOdds,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_total = 0u64;
        let mut last_tick = Instant::now();

        while !stop.load(Ordering::Relaxed) {
            let wait_started = Instant::now();
            while wait_started.elapsed() < interval {
                if stop.load(Ordering::Relaxed) {
                    return;
                }

                let remaining = interval.saturating_sub(wait_started.elapsed());
                thread::sleep(remaining.min(Duration::from_millis(100)));
            }

            let snapshot = stats.snapshot();
            let elapsed_since_last = last_tick.elapsed().as_secs_f64();
            let delta = snapshot.total_keys.saturating_sub(last_total);
            let recent_rate = if elapsed_since_last == 0.0 {
                0.0
            } else {
                delta as f64 / elapsed_since_last
            };
            let unluckiness = odds.unluckiness_pct(snapshot.total_keys, snapshot.found);

            eprintln!(
                "elapsed={:.1}s keys={} rate={:.0}/s overall={:.0}/s found={} unlucky={} exp≈{:.3e}",
                snapshot.elapsed.as_secs_f64(),
                snapshot.total_keys,
                recent_rate,
                snapshot.overall_keys_per_sec,
                snapshot.found,
                format_percent(unluckiness),
                odds.expected_attempts(),
            );

            last_total = snapshot.total_keys;
            last_tick = Instant::now();
        }
    })
}
