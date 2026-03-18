use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use ygg_vanity::derive::format_ipv6;
use ygg_vanity::luck::{SearchOdds, format_percent};
use ygg_vanity::matcher::{Matcher, MatcherError};
use ygg_vanity::stats::{Stats, spawn_reporter};
use ygg_vanity::worker::{DEFAULT_BATCH_SIZE, WorkerPool, autotune_batch};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse(env::args().skip(1))?;

    let matcher = match (&args.hex, &args.cidr, &args.template) {
        (Some(hex), None, None) => Matcher::from_hex_prefix(hex)?,
        (None, Some(cidr), None) => Matcher::from_cidr(cidr)?,
        (None, None, Some(template)) => Matcher::from_template(template)?,
        _ => unreachable!("argument validation handled in parser"),
    };
    let odds = SearchOdds::from_fixed_bits(matcher.fixed_bits());
    let batch_size = match args.batch {
        BatchSetting::Fixed(size) => size,
        BatchSetting::Auto => {
            let result = autotune_batch(args.threads, matcher, args.batch_auto_secs);
            result.batch_size
        }
    };

    let stats = Arc::new(Stats::new());
    let pool = WorkerPool::start(args.threads, matcher, Arc::clone(&stats), batch_size);
    let stop_flag = pool.stop_flag();
    let reporter = spawn_reporter(
        Arc::clone(&stats),
        Arc::clone(&stop_flag),
        args.stats_every,
        odds,
    );

    eprintln!(
        "threads={} max_found={} matcher={} stats_every={}s batch={} fixed_bits={} exp≈{:.3e}",
        args.threads,
        args.max_found,
        args.matcher_description(),
        args.stats_every.as_secs(),
        batch_size,
        odds.fixed_bits(),
        odds.expected_attempts(),
    );

    for found_index in 0..args.max_found {
        let result = pool
            .receiver()
            .recv()
            .map_err(|_| CliError::WorkerStoppedEarly)?;

        println!("match #{}", found_index + 1);
        println!("private_key: {}", hex::encode(result.keypair.secret));
        println!("public_key: {}", hex::encode(result.keypair.pubkey));
        println!("address: {}", format_ipv6(&result.addr));
        println!("worker: {}", result.worker_id);
        println!();
    }

    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    pool.stop_and_join();
    let _ = reporter.join();
    let final_snapshot = stats.snapshot();
    let final_unluckiness = odds.unluckiness_pct(final_snapshot.total_keys, final_snapshot.found);

    eprintln!(
        "finished: elapsed={:.1}s keys={} overall={:.0}/s found={} unlucky={} exp≈{:.3e}",
        final_snapshot.elapsed.as_secs_f64(),
        final_snapshot.total_keys,
        final_snapshot.overall_keys_per_sec,
        final_snapshot.found,
        format_percent(final_unluckiness),
        odds.expected_attempts(),
    );

    Ok(())
}

#[derive(Debug)]
struct Args {
    hex: Option<String>,
    cidr: Option<String>,
    template: Option<String>,
    batch: BatchSetting,
    batch_auto_secs: Duration,
    threads: usize,
    max_found: u64,
    stats_every: Duration,
}

#[derive(Clone, Copy, Debug)]
enum BatchSetting {
    Fixed(u64),
    Auto,
}

impl Args {
    fn parse<I>(iter: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut hex = None;
        let mut cidr = None;
        let mut template = None;
        let mut batch = BatchSetting::Fixed(DEFAULT_BATCH_SIZE);
        let mut batch_auto_secs = Duration::from_secs(3);
        let mut threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let mut max_found = 1u64;
        let mut stats_every = Duration::from_secs(1);

        let args = iter.into_iter().collect::<Vec<_>>();
        let mut index = 0usize;

        while index < args.len() {
            match args[index].as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "--hex" => {
                    hex = Some(next_value(&args, &mut index, "--hex")?);
                }
                "--cidr" => {
                    cidr = Some(next_value(&args, &mut index, "--cidr")?);
                }
                "--template" => {
                    template = Some(next_value(&args, &mut index, "--template")?);
                }
                "--threads" => {
                    threads = next_value(&args, &mut index, "--threads")?
                        .parse()
                        .map_err(|_| CliError::InvalidNumber("--threads"))?;
                }
                "--batch" => {
                    let value = next_value(&args, &mut index, "--batch")?;
                    batch = parse_batch_setting(&value)?;
                }
                "--batch-auto-secs" => {
                    let secs: u64 = next_value(&args, &mut index, "--batch-auto-secs")?
                        .parse()
                        .map_err(|_| CliError::InvalidNumber("--batch-auto-secs"))?;
                    batch_auto_secs = Duration::from_secs(secs.max(1));
                }
                "--max-found" => {
                    max_found = next_value(&args, &mut index, "--max-found")?
                        .parse()
                        .map_err(|_| CliError::InvalidNumber("--max-found"))?;
                }
                "--stats-every" => {
                    let secs: u64 = next_value(&args, &mut index, "--stats-every")?
                        .parse()
                        .map_err(|_| CliError::InvalidNumber("--stats-every"))?;
                    stats_every = Duration::from_secs(secs.max(1));
                }
                unknown => {
                    return Err(CliError::UnknownArgument(unknown.to_owned()));
                }
            }

            index += 1;
        }

        let matchers = [hex.is_some(), cidr.is_some(), template.is_some()]
            .into_iter()
            .filter(|is_set| *is_set)
            .count();

        if matchers != 1 {
            return Err(CliError::MatcherRequired);
        }

        if threads == 0 {
            return Err(CliError::InvalidNumber("--threads"));
        }

        if max_found == 0 {
            return Err(CliError::InvalidNumber("--max-found"));
        }

        Ok(Self {
            hex,
            cidr,
            template,
            batch,
            batch_auto_secs,
            threads,
            max_found,
            stats_every,
        })
    }

    fn matcher_description(&self) -> String {
        if let Some(hex) = &self.hex {
            format!("hex:{hex}")
        } else if let Some(cidr) = &self.cidr {
            format!("cidr:{cidr}")
        } else {
            format!("template:{}", self.template.as_deref().unwrap_or_default())
        }
    }
}

fn next_value(args: &[String], index: &mut usize, flag: &'static str) -> Result<String, CliError> {
    let value_index = *index + 1;
    if value_index >= args.len() {
        return Err(CliError::MissingValue(flag));
    }

    *index = value_index;
    Ok(args[value_index].clone())
}

fn parse_batch_setting(value: &str) -> Result<BatchSetting, CliError> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(BatchSetting::Auto);
    }

    let batch = value
        .parse()
        .map_err(|_| CliError::InvalidNumber("--batch"))?;

    if batch == 0 {
        return Err(CliError::InvalidNumber("--batch"));
    }

    Ok(BatchSetting::Fixed(batch))
}

fn print_usage() {
    println!("Usage:");
    println!(
        "  ygg-vanity (--hex HEX_PREFIX | --cidr IPV6_CIDR | --template IPV6_TEMPLATE) [--threads N] [--batch N|auto] [--batch-auto-secs SECONDS] [--max-found N] [--stats-every SECONDS]"
    );
    println!();
    println!("Examples:");
    println!("  ygg-vanity --hex 0202");
    println!("  ygg-vanity --hex 02020fca");
    println!("  ygg-vanity --cidr 202:fca::/32 --threads 8");
    println!("  ygg-vanity --template 200:?:?:?:dead:beef:?:? --threads 8");
    println!("  ygg-vanity --template 200:?:?:?:dead:beef:?:? --batch auto");
    println!();
    println!("Note: --batch auto benchmarks a few nearby batch sizes before search.");
    println!("Note: in --template the first hextet is ignored for matching and rarity.");
}

#[derive(Debug)]
enum CliError {
    MatcherRequired,
    MissingValue(&'static str),
    InvalidNumber(&'static str),
    UnknownArgument(String),
    Matcher(MatcherError),
    WorkerStoppedEarly,
}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MatcherRequired => {
                write!(
                    f,
                    "exactly one matcher must be supplied: --hex, --cidr or --template"
                )
            }
            Self::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Self::InvalidNumber(flag) => write!(f, "invalid numeric value for {flag}"),
            Self::UnknownArgument(arg) => write!(f, "unknown argument: {arg}"),
            Self::Matcher(err) => Display::fmt(err, f),
            Self::WorkerStoppedEarly => {
                write!(f, "workers stopped before producing enough matches")
            }
        }
    }
}

impl Error for CliError {}

impl From<MatcherError> for CliError {
    fn from(value: MatcherError) -> Self {
        Self::Matcher(value)
    }
}
