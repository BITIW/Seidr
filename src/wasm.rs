use crate::derive::{format_ipv6, pubkey_to_ipv6_u128};
use crate::generator::KeyGenerator;
use crate::luck::SearchOdds;
use crate::matcher::{Matcher, MatcherError};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WasmProgress {
    pub total_keys: u64,
    pub found: u64,
    pub elapsed_secs: f64,
    pub keys_per_sec: f64,
    pub expected_attempts: f64,
    pub unluckiness_pct: f64,
    pub fixed_bits: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmMatch {
    pub private_key: String,
    pub public_key: String,
    pub address: String,
}

pub struct WasmVanityEngine {
    generator: KeyGenerator,
    matcher: Matcher,
    odds: SearchOdds,
    started_at_secs: f64,
    total_keys: u64,
    found: u64,
}

impl WasmVanityEngine {
    pub fn from_template(template: &str) -> Result<Self, MatcherError> {
        let matcher = Matcher::from_template(template)?;
        let odds = SearchOdds::from_fixed_bits(matcher.fixed_bits());

        Ok(Self {
            generator: KeyGenerator::new(),
            matcher,
            odds,
            started_at_secs: now_secs(),
            total_keys: 0,
            found: 0,
        })
    }

    pub fn step(&mut self, iterations: usize, max_results: usize) -> Vec<WasmMatch> {
        let iterations = iterations.max(1);
        let max_results = max_results.max(1);
        let mut matches = Vec::with_capacity(max_results.min(8));

        for _ in 0..iterations {
            let candidate = self.generator.generate_candidate();
            self.total_keys += 1;

            if self.matcher.matches_pubkey(&candidate.pubkey) {
                self.found += 1;
                let addr = pubkey_to_ipv6_u128(&candidate.pubkey);
                let keypair = candidate.into_keypair();
                let addr_bytes = addr.to_be_bytes();
                matches.push(WasmMatch {
                    private_key: hex::encode(keypair.secret),
                    public_key: hex::encode(keypair.pubkey),
                    address: format_ipv6(&addr_bytes).to_string(),
                });

                if matches.len() >= max_results {
                    break;
                }
            }
        }

        matches
    }

    pub fn progress(&self) -> WasmProgress {
        let elapsed_secs = (now_secs() - self.started_at_secs).max(0.0);
        let keys_per_sec = if elapsed_secs == 0.0 {
            0.0
        } else {
            self.total_keys as f64 / elapsed_secs
        };
        let unluckiness_pct = self.odds.unluckiness_pct(self.total_keys, self.found);

        WasmProgress {
            total_keys: self.total_keys,
            found: self.found,
            elapsed_secs,
            keys_per_sec,
            expected_attempts: self.odds.expected_attempts(),
            unluckiness_pct,
            fixed_bits: self.odds.fixed_bits(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn now_secs() -> f64 {
    js_sys::Date::now() / 1000.0
}

#[cfg(not(target_arch = "wasm32"))]
fn now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
