#[derive(Clone, Copy, Debug)]
pub struct SearchOdds {
    fixed_bits: u32,
    expected_attempts: f64,
    log_no_match_per_try: f64,
}

impl SearchOdds {
    pub fn from_fixed_bits(fixed_bits: u32) -> Self {
        let single_match_prob = 2f64.powi(-(fixed_bits as i32));
        let expected_attempts = 2f64.powi(fixed_bits as i32);
        let log_no_match_per_try = (-single_match_prob).ln_1p();

        Self {
            fixed_bits,
            expected_attempts,
            log_no_match_per_try,
        }
    }

    pub fn fixed_bits(&self) -> u32 {
        self.fixed_bits
    }

    pub fn expected_attempts(&self) -> f64 {
        self.expected_attempts
    }

    pub fn unluckiness_pct(&self, total_keys: u64, found: u64) -> f64 {
        if found > 0 || total_keys == 0 {
            return 0.0;
        }

        let log_no_match = (total_keys as f64) * self.log_no_match_per_try;
        (-log_no_match.exp_m1() * 100.0).clamp(0.0, 100.0)
    }
}

pub fn format_percent(value: f64) -> String {
    if value == 0.0 {
        "0.00%".to_owned()
    } else if value < 0.01 {
        format!("{value:.3e}%")
    } else {
        format!("{value:.2}%")
    }
}

#[cfg(test)]
mod tests {
    use super::SearchOdds;

    #[test]
    fn unluckiness_matches_geometric_distribution() {
        let odds = SearchOdds::from_fixed_bits(1);

        assert!((odds.unluckiness_pct(1, 0) - 50.0).abs() < 1e-9);
        assert!((odds.unluckiness_pct(2, 0) - 75.0).abs() < 1e-9);
    }

    #[test]
    fn unluckiness_drops_after_first_match() {
        let odds = SearchOdds::from_fixed_bits(32);

        assert_eq!(odds.unluckiness_pct(1_000_000, 1), 0.0);
    }
}
