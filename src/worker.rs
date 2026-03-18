use crate::derive::pubkey_to_ipv6_u128;
use crate::generator::{GeneratedCandidate, GeneratedKeypair, KeyGenerator};
use crate::matcher::Matcher;
use crate::stats::Stats;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SendError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const DEFAULT_BATCH_SIZE: u64 = 4096;
const STOP_CHECK_INTERVAL: u64 = 256;
const AUTOTUNE_MIN_BATCH_SIZE: u64 = 512;
const AUTOTUNE_MAX_BATCH_SIZE: u64 = 16_384;
const AUTOTUNE_UP_STEP: u64 = 1024;
const AUTOTUNE_DOWN_STEP: u64 = 512;
const AUTOTUNE_REFINE_STEP: u64 = 256;
const AUTOTUNE_IMPROVEMENT_EPSILON: f64 = 0.01;

#[derive(Clone, Copy, Debug)]
pub struct MatchResult {
    pub keypair: GeneratedKeypair,
    pub addr: [u8; 16],
    pub worker_id: usize,
}

pub struct WorkerPool {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    receiver: Receiver<MatchResult>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AutoBatchResult {
    pub batch_size: u64,
    pub keys_per_sec: f64,
}

impl WorkerPool {
    pub fn start(threads: usize, matcher: Matcher, stats: Arc<Stats>, batch_size: u64) -> Self {
        let batch_size = normalize_batch_size(batch_size);
        let stop = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel();
        let mut handles = Vec::with_capacity(threads);

        for worker_id in 0..threads {
            let stop_flag = Arc::clone(&stop);
            let stats_ref = Arc::clone(&stats);
            let thread_sender = sender.clone();
            let thread_matcher = matcher;

            let handle = thread::spawn(move || {
                let mut generator = KeyGenerator::new();
                let mut pending = 0u64;

                'search: loop {
                    for _ in 0..STOP_CHECK_INTERVAL {
                        let candidate = generator.generate_candidate();
                        pending += 1;

                        if thread_matcher.matches_pubkey(&candidate.pubkey) {
                            stats_ref.add_keys(pending);
                            pending = 0;
                            let addr = pubkey_to_ipv6_u128(&candidate.pubkey);

                            if send_match(&thread_sender, candidate, addr, worker_id).is_err() {
                                stop_flag.store(true, Ordering::Relaxed);
                                break 'search;
                            }

                            stats_ref.record_match();
                        } else if pending == batch_size {
                            stats_ref.add_keys(pending);
                            pending = 0;
                        }
                    }

                    if stop_flag.load(Ordering::Relaxed) {
                        break 'search;
                    }
                }

                if pending != 0 {
                    stats_ref.add_keys(pending);
                }
            });

            handles.push(handle);
        }

        drop(sender);

        Self {
            stop,
            handles,
            receiver,
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    pub fn receiver(&self) -> &Receiver<MatchResult> {
        &self.receiver
    }

    pub fn stop_and_join(self) {
        self.stop.store(true, Ordering::Relaxed);

        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

pub fn autotune_batch(threads: usize, matcher: Matcher, probe_time: Duration) -> AutoBatchResult {
    let probe_time = probe_time.max(Duration::from_secs(1));
    let mut best = probe_batch(threads, matcher, DEFAULT_BATCH_SIZE, probe_time);

    eprintln!(
        "batch autotune: batch={} -> {:.0}/s",
        best.batch_size, best.keys_per_sec
    );

    let upward = probe_batch(
        threads,
        matcher,
        DEFAULT_BATCH_SIZE + AUTOTUNE_UP_STEP,
        probe_time,
    );
    eprintln!(
        "batch autotune: batch={} -> {:.0}/s",
        upward.batch_size, upward.keys_per_sec
    );

    if meaningfully_better(upward.keys_per_sec, best.keys_per_sec) {
        best = upward;

        loop {
            let candidate_size = best.batch_size.saturating_add(AUTOTUNE_UP_STEP);
            if candidate_size > AUTOTUNE_MAX_BATCH_SIZE {
                break;
            }

            let candidate = probe_batch(threads, matcher, candidate_size, probe_time);
            eprintln!(
                "batch autotune: batch={} -> {:.0}/s",
                candidate.batch_size, candidate.keys_per_sec
            );

            if !meaningfully_better(candidate.keys_per_sec, best.keys_per_sec) {
                break;
            }

            best = candidate;
        }
    } else {
        let mut candidate_size = DEFAULT_BATCH_SIZE.saturating_sub(AUTOTUNE_DOWN_STEP);

        while candidate_size >= AUTOTUNE_MIN_BATCH_SIZE {
            let candidate = probe_batch(threads, matcher, candidate_size, probe_time);
            eprintln!(
                "batch autotune: batch={} -> {:.0}/s",
                candidate.batch_size, candidate.keys_per_sec
            );

            if !meaningfully_better(candidate.keys_per_sec, best.keys_per_sec) {
                break;
            }

            best = candidate;

            if candidate_size == AUTOTUNE_MIN_BATCH_SIZE {
                break;
            }

            candidate_size = candidate_size.saturating_sub(AUTOTUNE_DOWN_STEP);
        }
    }

    let refined = refined_candidates(best.batch_size);
    for candidate_size in refined {
        if candidate_size == best.batch_size {
            continue;
        }

        let candidate = probe_batch(threads, matcher, candidate_size, probe_time);
        eprintln!(
            "batch autotune: batch={} -> {:.0}/s",
            candidate.batch_size, candidate.keys_per_sec
        );

        if meaningfully_better(candidate.keys_per_sec, best.keys_per_sec) {
            best = candidate;
        }
    }

    eprintln!(
        "batch autotune: selected batch={} -> {:.0}/s",
        best.batch_size, best.keys_per_sec
    );

    best
}

fn probe_batch(
    threads: usize,
    matcher: Matcher,
    batch_size: u64,
    duration: Duration,
) -> AutoBatchResult {
    let batch_size = normalize_batch_size(batch_size);
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::new());
    let mut handles = Vec::with_capacity(threads);

    for _ in 0..threads {
        let stop_flag = Arc::clone(&stop);
        let stats_ref = Arc::clone(&stats);
        let thread_matcher = matcher;

        handles.push(thread::spawn(move || {
            let mut generator = KeyGenerator::new();
            let mut pending = 0u64;

            'search: loop {
                for _ in 0..STOP_CHECK_INTERVAL {
                    let candidate = generator.generate_candidate();
                    pending += 1;

                    if thread_matcher.matches_pubkey(&candidate.pubkey) || pending == batch_size {
                        stats_ref.add_keys(pending);
                        pending = 0;
                    }
                }

                if stop_flag.load(Ordering::Relaxed) {
                    break 'search;
                }
            }

            if pending != 0 {
                stats_ref.add_keys(pending);
            }
        }));
    }

    thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.join();
    }

    AutoBatchResult {
        batch_size,
        keys_per_sec: stats.snapshot().overall_keys_per_sec,
    }
}

fn refined_candidates(batch_size: u64) -> [u64; 2] {
    [
        clamp_autotune_batch(batch_size.saturating_sub(AUTOTUNE_REFINE_STEP)),
        clamp_autotune_batch(batch_size.saturating_add(AUTOTUNE_REFINE_STEP)),
    ]
}

#[inline(always)]
fn normalize_batch_size(batch_size: u64) -> u64 {
    batch_size.max(1)
}

#[inline(always)]
fn clamp_autotune_batch(batch_size: u64) -> u64 {
    batch_size.clamp(AUTOTUNE_MIN_BATCH_SIZE, AUTOTUNE_MAX_BATCH_SIZE)
}

#[inline(always)]
fn meaningfully_better(candidate: f64, best: f64) -> bool {
    candidate > best * (1.0 + AUTOTUNE_IMPROVEMENT_EPSILON)
}

#[cold]
#[inline(never)]
fn send_match(
    sender: &Sender<MatchResult>,
    candidate: GeneratedCandidate,
    addr: u128,
    worker_id: usize,
) -> Result<(), SendError<MatchResult>> {
    sender.send(MatchResult {
        keypair: candidate.into_keypair(),
        addr: addr.to_be_bytes(),
        worker_id,
    })
}
