//! Run a grid search to compute the traffic positives and negatives for all combinations of parameters.
//!
//! This program needs access to the `cctld` database.
//! It fetches most data from there.
//! In addition, the program needs an attacker model.
//! This is a JSON file with a weighted list of attacker IP addresses like `{"198.51.100.100": 1.0, "198.51.100.101": 2.0}`.
//! Second a file describing the catchment area of all locations is needed, which tells for an IP to which location it routes.
//! The file is a JSON array containing these elements.
//! The first list contains the IP ranges which have this catchment behavior.
//! The second object describes for each anycast IP address, which locations receive which fraction of the traffic.
//!
//! ```json
//! [
//!     [
//!         "0.0.0.0/8",
//!         "198.51.100.0/24"
//!     ],
//!     {
//!         "203.0.113.1": {
//!             "xxx": 1.0,
//!             "xxy": 2.0
//!         },
//!         "203.0.113.2": {
//!             "xxx": 1.0
//!         }
//!     }
//! ]
//! ```
//!
//! The values for the parameter combinations can be changed by editing the constants in the source code.
//!
//! The result are many files with the given filename pattern: `eval_results_{location}_{ip_dst}_{attacker_bps}bps.json`.

#![deny(unused_import_braces, unused_qualifications)]

use color_eyre::eyre::{eyre, Context as _, Result};
use evaluation::{ok, DataConfiguration, EvaluationResults, Location};
use futures::stream::{StreamExt as _, TryStreamExt as _};
use ipnetwork::Ipv4Network;
use sqlx::postgres::PgConnectOptions;
use sqlx::types::ipnetwork::IpNetwork;
use sqlx::{ConnectOptions as _, PgPool};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, iter};
use tokio::sync::Mutex;

static KIBIBITS: u64 = 1024;
static MEBIBITS: u64 = 1024 * KIBIBITS;
static GIBIBITS: u64 = 1024 * MEBIBITS;
static TEBIBITS: u64 = 1024 * GIBIBITS;

/// NetFlow sampling takes 1-out-of-n packets.
const NETFLOW_SAMPLING_RATE: f64 = 10.;

/// Length of training windows
static WINDOWS_TRAIN: [u8; 11] = [1, 2, 4, 8, 12, 24, 25, 48, 49, 72, 73];
/// Length of training windows
/// Length of test windows
static WINDOWS_TEST: [u8; 3] = [8, 24, 72];
/// Minimum number of active time periods for a resolver to appear on the allowlist
static MIN_ACTIVE_PERIODS: [u8; 4] = [1, 4, 8, 12];
/// Minimum packets a resolver must send to appear on the allowlist
static MIN_PKTS_AVG: [u32; 3] = [/* 4, 8, 16, 32, */ 64, 128, 256];
/// Low pass filter of traffic allowed while not on the allowlist
static LOW_PASS_FILTER: [u32; 4] = [128, 512, 2048, 8192];
/// Total bandwidth for the attacker
#[allow(clippy::identity_op)]
static ATTACKER_TOTAL_TRAFFIC_BITS_PER_SECOND: [u64; 2] = [40 * GIBIBITS, 100 * TEBIBITS];
/// How much the training traffic may be exceeded by the traffic in the test window
static ABOVE_TRAIN_LIMITS: [f64; 3] = [1.0, 2.0, 4.0];
/// Total number of available time intervals
static TOTAL_TIME_LENGHT: u32 = 648;

#[derive(Debug, clap::Parser)]
struct CliArgs {
    /// JSON file with a weighted list of attacker IP addresses like `{"198.51.100.100": 1.0, "198.51.100.101": 2.0}`
    #[clap(long = "attacker-ips")]
    attacker_ips_file: PathBuf,
    #[clap(long = "catchment")]
    catchment_file: PathBuf,
    /// Number of evasion IPs
    #[clap(long = "evasion-ips")]
    evasion_ips: Option<usize>,
}

/// Maps from the attacker controlled IP addresses to the bandwidth assigned to each of them
#[derive(Clone, Default)]
struct AttackerTrafficDistribution(pub BTreeMap<IpNetwork, f64>, pub Vec<IpNetwork>);

impl fmt::Debug for AttackerTrafficDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttackerTrafficDistribution")
            .finish_non_exhaustive()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();
    // console_subscriber::init();
    let args: CliArgs = clap::Parser::parse();

    let mut pgoptions =
        PgConnectOptions::from_str("postgres:///cctld")?.application_name("evaluation");
    pgoptions
        .log_statements(log::LevelFilter::Debug)
        .log_slow_statements(log::LevelFilter::Info, Duration::new(60, 0));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(80)
        .acquire_timeout(Duration::new(60, 0))
        .idle_timeout(Duration::new(30, 0))
        .test_before_acquire(true)
        .connect_with(pgoptions)
        .await?;

    #[allow(clippy::type_complexity)]
    let catchment: Vec<(Vec<Ipv4Network>, BTreeMap<IpAddr, BTreeMap<String, f64>>)> = {
        let catchment_data = std::fs::read_to_string(&args.catchment_file)?;
        serde_json::from_str(&catchment_data)?
    };

    // Fetch all locations and destination combinations
    #[derive(Debug)]
    struct Record {
        location: String,
        iprange_dst: IpNetwork,
    }
    let loc_and_dst: Vec<Record> = sqlx::query_as!(
        Record,
        r#"
SELECT DISTINCT
    location AS "location!",
    iprange_dst AS "iprange_dst!"
FROM
    pre_test_intervals
WHERE
    family(iprange_dst) = 4
ORDER BY
    1,
    2
;"#
    )
    .fetch_all(&pool)
    .await?;
    let attacker_ips = {
        let attacker_ips = std::fs::read_to_string(&args.attacker_ips_file)?;
        serde_json::from_str(&attacker_ips)?
    };

    let num_locs_per_dst = {
        let mut num_locs_per_dst = BTreeMap::new();
        for rec in &loc_and_dst {
            let num_locs = num_locs_per_dst.entry(rec.iprange_dst).or_insert(0);
            *num_locs += 1;
        }
        num_locs_per_dst
    };

    for rec in loc_and_dst {
        let location: &'static str = Box::leak(Box::new(rec.location));
        let iprange_dst = rec.iprange_dst;

        for attacker_bps in ATTACKER_TOTAL_TRAFFIC_BITS_PER_SECOND {
            // Calculate one distribution of attacker IPs
            let mut attacker_traffic = create_weighted_attack_traffic(
                &attacker_ips,
                attacker_bps,
                args.evasion_ips.unwrap_or(0),
            );
            // Account for the catchment information
            // Scale each attacker source by the catchment factor
            attacker_traffic.0 = attacker_traffic
                .0
                .into_iter()
                .filter_map(|(net, bandwidth)| {
                    if let IpNetwork::V4(netv4) = net {
                        let catchment_idx =
                            catchment.binary_search_by(|(catchment_net, _)| {
                                match (
                                    catchment_net[0].network().cmp(&netv4.network()),
                                    catchment_net[catchment_net.len() - 1]
                                        .broadcast()
                                        .cmp(&netv4.broadcast()),
                                ) {
                                    (Ordering::Less, Ordering::Less) => Ordering::Less,
                                    (Ordering::Greater, Ordering::Greater) => Ordering::Greater,

                                    (Ordering::Less, Ordering::Equal | Ordering::Greater)
                                    | (Ordering::Equal, _) => Ordering::Equal,

                                    (Ordering::Greater, Ordering::Less)
                                    | (Ordering::Greater, Ordering::Equal) => {
                                        panic!("Nonsensical ordering of networks")
                                    }
                                }
                            });

                        match catchment_idx {
                            Ok(idx) => {
                                if let Some(catchment_loc) =
                                    catchment[idx].1.get(&iprange_dst.network())
                                {
                                    // If location is not in the catchment list, then we know that this location never received traffic
                                    // Therefore filter the source completely
                                    catchment_loc
                                        .get(location)
                                        .map(|catchment_factor| (net, bandwidth * catchment_factor))
                                } else {
                                    // In our catchment data the source never send traffic to this destination
                                    // We can therefore not estimate the catchment and split equal among locations
                                    Some((net, bandwidth / num_locs_per_dst[&iprange_dst] as f64))
                                }
                            }
                            // No pre-recorded catchment information for this network
                            // Split traffic equally among all locations
                            Err(_) => {
                                Some((net, bandwidth / num_locs_per_dst[&iprange_dst] as f64))
                            }
                        }
                    } else {
                        Some((net, bandwidth))
                    }
                })
                .collect();
            let attacker_traffic = Arc::new(attacker_traffic);

            let eval_results: Vec<_> = {
                // Given a fixed location and iprange_dst we can pre-fetch all the window information
                log::info!("Fetch window cache for {} {}", location, iprange_dst);
                let window_cache: Vec<_> = (1..=TOTAL_TIME_LENGHT)
                    .flat_map(|start| WINDOWS_TRAIN.into_iter().map(move |window| (start, window)))
                    .filter(|&(start, window)| (start + window as u32 - 1) <= TOTAL_TIME_LENGHT)
                    .map(|(start, window)| {
                        let pool = pool.clone();
                        async move {
                            ok((
                                (start, window),
                                tokio::spawn(fetch_traffic_interval(
                                    start,
                                    window,
                                    location,
                                    iprange_dst,
                                    pool.clone(),
                                ))
                                .await??,
                            ))
                        }
                    })
                    .collect();
                let window_cache: Result<BTreeMap<(u32, u8), BTreeMap<IpNetwork, f64>>> =
                    futures::future::join_all(window_cache)
                        .await
                        .into_iter()
                        .collect();
                let window_cache: &'static BTreeMap<_, _> = Box::leak(Box::new(window_cache?));
                log::info!(
                    "Finished fetching window cache for {} {}",
                    location,
                    iprange_dst
                );

                log::info!(
                    "Generate DataConfigurations for {} {}",
                    location,
                    iprange_dst
                );
                let mut windows_train = WINDOWS_TRAIN.to_vec();
                // If we simulate evasion, we only want to run it on one configuration, but different per location
                if args.evasion_ips.is_some() {
                    windows_train = vec![Location::from_str(location)?.best_train_length()];
                }

                let res = windows_train
                    .into_iter()
                    .flat_map(|train_length| {
                        WINDOWS_TEST.into_iter().flat_map({
                            let attacker_traffic = attacker_traffic.clone();
                            move |test_length| {
                                MIN_ACTIVE_PERIODS
                                    .into_iter()
                                    .filter(move |&min_active| min_active <= train_length)
                                    .flat_map({
                                        let attacker_traffic = attacker_traffic.clone();
                                        move |min_active| {
                                            MIN_PKTS_AVG.into_iter().flat_map({
                                                let attacker_traffic = attacker_traffic.clone();
                                                move |min_pkts_avg| {
                                                    LOW_PASS_FILTER.into_iter().flat_map({
                                                        let attacker_traffic =
                                                            attacker_traffic.clone();
                                                        move |low_pass| {
                                                            ABOVE_TRAIN_LIMITS.into_iter().flat_map(
                                                                {
                                                                    let attacker_traffic =
                                                                        attacker_traffic.clone();
                                                                    move |above_train_limit| {
                                                                        (1..=(TOTAL_TIME_LENGHT
                                                                    - train_length as u32
                                                                    - test_length as u32
                                                                    + 1))
                                                                    .map({
                                                                        let attacker_traffic =
                                                                            attacker_traffic
                                                                                .clone();
                                                                        move |window_start| {
                                                                            DataConfiguration {
                                                                                location: location.parse().unwrap(),
                                                                                iprange_dst,
                                                                                window_start,
                                                                                train_length,
                                                                                test_length,
                                                                                min_active,
                                                                                min_pkts_avg,
                                                                                low_pass,
                                                                                attacker:
                                                                                    attacker_traffic
                                                                                        .clone(),
                                                                                above_train_limit: above_train_limit.try_into().unwrap(),
                                                                            }
                                                                        }
                                                                    })
                                                                    }
                                                                },
                                                            )
                                                        }
                                                    })
                                                }
                                            })
                                        }
                                    })
                            }
                        })
                    })
                    // .take(100_000)
                    .map({
                        |data_config: DataConfiguration<Arc<AttackerTrafficDistribution>>| {
                            let pool = pool.clone();
                            async move {
                                ok((
                                    data_config.clone(),
                                    evaluate_configuration(data_config, window_cache, pool.clone())
                                        .await?,
                                ))
                            }
                        }
                    })
                    .collect();
                log::info!(
                    "Finished DataConfigurations for {} {}",
                    location,
                    iprange_dst
                );
                res
            };

            // Run all the futures till completion
            let num_results = eval_results.len();
            let progress_bar = indicatif::ProgressBar::with_draw_target(
                Some(num_results as u64),
                indicatif::ProgressDrawTarget::stderr_with_hz(1),
            );
            progress_bar.set_style(indicatif::ProgressStyle::default_bar().template(
                "[{elapsed_precise}] ETA: {eta_precise} {wide_bar:40.cyan/blue} {pos:>7}/{len:7} \
                 {percent}%",
            )?);
            progress_bar.inc(0);
            let eval_results: Vec<(DataConfiguration<Arc<AttackerTrafficDistribution>>, EvaluationResults)> =
            // Iterate over all futures
            // Spawn them parallel into the tokio runtime
            // Run a limited set of them in parallel
            futures::stream::iter(eval_results)
                .map(|fut| tokio::spawn(fut))
                .buffer_unordered(80 * 10)
                .enumerate()
                .map(|(idx, v)| {
                    let (data_config, eval_results) = v??;

                    if idx % 100 == 0 {
                        progress_bar.inc(100)
                    };
                    ok((data_config, eval_results))
                })
                .try_collect()
                .await?;

            // Save the results
            std::fs::write(
                format!(
                    "./eval_results_{location}_{ip_dst}_{attacker_bps}bps.json",
                    ip_dst = iprange_dst.network()
                ),
                serde_json::to_string(&eval_results)?,
            )?;
        }
    }

    Ok(())
}

// fn create_equal_attack_traffic(
//     source_ips: &[IpAddr],
//     total_bps: u64,
// ) -> AttackerTrafficDistribution {
//     // 100 Byte packet. It is enough for a 16 Byte query name and all header including ethernet overhead.
//     const BITS_PER_PACKET: u64 = 100 * 8;

//     let total_sources = source_ips.len();
//     // We have some part of traffic we can uniformly distribute over all IP addresses
//     // Then we get a rest, which is only enough to cover parts of it
//     let packets_per_second = total_bps / BITS_PER_PACKET;
//     let packets_per_source = (packets_per_second / total_sources as u64) as f64;
//     let packets_per_source_rest = packets_per_second % total_sources as u64;

//     let mut attacker_traffic = BTreeMap::new();
//     for (idx, source_ip) in source_ips.iter().copied().enumerate() {
//         let source_net = IpNetwork::new(source_ip, 24).expect("Prefix size never exceeds limit.");
//         let packets_this_source = if idx < packets_per_source_rest as usize {
//             packets_per_source + 1.
//         } else {
//             packets_per_source
//         };
//         *attacker_traffic.entry(source_net).or_insert(0.) += packets_this_source;
//     }
//     AttackerTrafficDistribution(attacker_traffic)
// }

/// Create a [`AttackerTrafficDistribution`] from a set of weighted sources and a total traffic amount.
///
/// The argument `source_ips` provides a relative weight between each [`IpAddr`] to indicate
fn create_weighted_attack_traffic(
    source_ips: &BTreeMap<IpAddr, f64>,
    total_bits_per_second: u64,
    evasion_ips: usize,
) -> AttackerTrafficDistribution {
    // 100 Byte packet. It is enough for a 16 Byte query name and all header including ethernet overhead.
    const BITS_PER_PACKET: u64 = 100 * 8;

    let total_weight = source_ips.values().sum::<f64>();

    let total_bits_per_hour = total_bits_per_second as f64 * 3600.;

    // We have some part of traffic we can uniformly distribute over all IP addresses
    // Then we get a rest, which is only enough to cover parts of it
    let packets_per_hour = total_bits_per_hour / BITS_PER_PACKET as f64;
    let packets_per_weight = packets_per_hour / total_weight as f64;

    let mut attacker_traffic = BTreeMap::new();
    for (&source_ip, &weight) in source_ips {
        let source_net = IpNetwork::new(source_ip, 24).expect("Prefix size never exceeds limit.");
        // Normalize the IpNetwork type
        let source_net =
            IpNetwork::new(source_net.network(), 24).expect("Prefix size never exceeds limit.");
        *attacker_traffic.entry(source_net).or_insert(0.) += packets_per_weight * weight;
    }

    // Pick a stable subset of the attacker traffic
    // This subset is later used for evasion
    let mut rng =
        <rand_chacha::ChaCha12Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(0);
    let attacker_traffic_evasion: Vec<IpNetwork> = rand::seq::IteratorRandom::choose_multiple(
        attacker_traffic.keys().copied(),
        &mut rng,
        evasion_ips,
    );

    AttackerTrafficDistribution(attacker_traffic, attacker_traffic_evasion)
}

/// Evaluate the `data_config` with a given cache and database connection.
///
/// The database connection is used to retrieve pre-aggregated data from the database.
/// The cache is read-only and shared amoung multiple `data_config`
async fn evaluate_configuration(
    data_config: DataConfiguration<Arc<AttackerTrafficDistribution>>,
    window_cache: &'static BTreeMap<(u32, u8), BTreeMap<IpNetwork, f64>>,
    pool: PgPool,
) -> Result<EvaluationResults> {
    let mut train_traffic = window_cache
        .get(&(data_config.window_start, data_config.train_length))
        .ok_or_else(|| {
            eyre!(
                "Missing data in window cache for ({}, {})",
                data_config.window_start,
                data_config.train_length
            )
        })?
        .clone();
    let test_traffic = window_cache
        .get(&(
            data_config.window_start + data_config.train_length as u32,
            data_config.test_length,
        ))
        .ok_or_else(|| {
            eyre!(
                "Missing data in window cache for ({}, {})",
                data_config.window_start + data_config.train_length as u32,
                data_config.test_length
            )
        })?
        .clone();

    let allowlist = fetch_allowlist(data_config.clone(), pool.clone())
        .await
        .context("Failed to fetch allowlist")?;

    // To check evasion we extend the allowlist with entries from the attacker.
    // We also ensure these entries have sufficiently large entries under train_traffic, such that the allowed amount of traffic is not too small.
    // This only executes if evasion_ips is larger 0
    if let Some(largest_traffic) = train_traffic
        .values()
        .copied()
        .max_by(|a, b| a.total_cmp(b))
    {
        // Update the train_traffic with the given attacker traffic
        for &ip in &data_config.attacker.1 {
            train_traffic.insert(ip, largest_traffic);
        }
    }

    let mut total = 0.;
    let mut true_positives = 0.;
    let mut true_negatives = 0.;
    let mut false_positives = 0.;
    let mut false_negatives = 0.;
    for (ipnet, values) in giant_merge_join(
        &data_config.attacker.0,
        &allowlist,
        &train_traffic,
        &test_traffic,
    ) {
        // Filter out all cases, where there is neither attack nor test traffic
        // Prevents later divide by 0 issues
        if values.0.is_none() && values.3.is_none() {
            continue;
        }

        let values = (
            values.0.map(|&x| x as f64).unwrap_or(0.),
            values.1.copied(),
            values.2.map(|x| x * NETFLOW_SAMPLING_RATE),
            values.3.map(|x| x * NETFLOW_SAMPLING_RATE).unwrap_or(0.),
        );

        // Add the total traffic observed, by summing attack and test traffic
        total += values.0 + values.3;

        match values {
            // Mixed traffic received but the IP is not on the allowlist
            (attack, None, _, test) => {
                let attack_ratio = attack / (attack + test);

                // Low Pass threshold adjusted by the fraction between test and attack traffic
                let test_low_pass = data_config.low_pass as f64 * (1. - attack_ratio);
                if test <= test_low_pass {
                    true_negatives += test;
                } else {
                    true_negatives += test_low_pass;
                    false_positives += test - test_low_pass;
                }

                let attack_low_pass = data_config.low_pass as f64 * attack_ratio;
                if attack <= attack_low_pass {
                    false_negatives += attack;
                } else {
                    false_negatives += attack_low_pass;
                    true_positives += attack - attack_low_pass;
                }
            }

            // Mixed traffic received but the IP is allowed
            (attack, Some(()), Some(train), test) => {
                let attack_ratio = attack / (attack + test);

                // Training threshold adjusted by the fraction between test and attack traffic
                let test_train_threshold =
                    train * data_config.above_train_limit.0 * (1. - attack_ratio);
                if test <= test_train_threshold {
                    true_negatives += test;
                } else {
                    true_negatives += test_train_threshold;
                    false_positives += test - test_train_threshold;
                }

                let attack_train_threshold = train * data_config.above_train_limit.0 * attack_ratio;
                if attack <= attack_train_threshold {
                    false_negatives += attack;
                } else {
                    false_negatives += attack_train_threshold;
                    true_positives += attack - attack_train_threshold;
                }
            }

            (_, Some(_), None, _) => panic!(
                "Received an allowlist entry for {ipnet} but no traffic in the train period."
            ),
        }
    }
    // Check that the computation makes sense
    assert!(!total.is_nan());
    assert!(!true_positives.is_nan());
    assert!(!true_negatives.is_nan());
    assert!(!false_positives.is_nan());
    assert!(!false_negatives.is_nan());
    assert!(
        // Check absolute difference
        ((total - 2.)..(total + 2.))
            .contains(&(true_positives + true_negatives + false_positives + false_negatives))
        ||
        // Check relative difference
        (1.0-0.000_000_001..1.0+0.000_000_001)
            .contains(&((true_positives + true_negatives + false_positives + false_negatives) / total)),
        "The total traffic {total} differs significantly from the computed total {} for {} {}",
        true_positives + true_negatives + false_positives + false_negatives,
        data_config.location,
        data_config.iprange_dst
    );

    Ok(EvaluationResults {
        total,
        true_positives,
        true_negatives,
        false_positives,
        false_negatives,
    })
}

/// Fetch the allowlist matching the time interval given via `data_config`.
async fn fetch_allowlist(
    data_config: DataConfiguration<Arc<AttackerTrafficDistribution>>,
    pool: PgPool,
) -> Result<BTreeMap<IpNetwork, ()>> {
    // Fields in allowlist table
    // time_start   │ integer
    // train_window │ integer
    // active_min   │ integer
    // pkts_min     │ integer
    // location     │ text
    // iprange_dst  │ inet
    // array_agg    │ cidr[]

    let dbresults = sqlx::query_scalar!(
        r#"SELECT array_agg as "array_agg!" FROM allowlist
        WHERE time_start = $1
        AND train_window = $2
        AND active_min = $3
        AND pkts_min = $4
        AND location = $5
        AND iprange_dst = $6"#,
        data_config.window_start as i32,
        data_config.train_length as i32,
        data_config.min_active as i32,
        data_config.min_pkts_avg as i32,
        <&'static str>::from(data_config.location),
        data_config.iprange_dst,
    )
    .fetch_optional(&pool)
    .await
    .with_context(|| {
        format!(
            "Allowlist for time_start {}, train_window {}, active_min {}, pkts_min {}, location \
             {}, iprange_dst {}",
            data_config.window_start,
            data_config.train_length,
            data_config.min_active,
            data_config.min_pkts_avg,
            data_config.location,
            data_config.iprange_dst,
        )
    })?;

    match dbresults {
        Some(dbresults) => Ok(dbresults.into_iter().map(|x| (x, ())).collect()),
        None => {
            #[allow(clippy::type_complexity)]
            static WARN_ONCE: once_cell::sync::Lazy<
                Mutex<BTreeSet<(&'static str, IpNetwork, u32)>>,
            > = once_cell::sync::Lazy::new(Mutex::default);
            if WARN_ONCE.lock().await.insert((
                data_config.location.into(),
                data_config.iprange_dst,
                data_config.window_start,
            )) {
                log::warn!(
                    "No Allowlist found for time_start {}, train_window {}, active_min {}, \
                     pkts_min {}, location {}, iprange_dst {}",
                    data_config.window_start,
                    data_config.train_length,
                    data_config.min_active,
                    data_config.min_pkts_avg,
                    data_config.location,
                    data_config.iprange_dst,
                );
            };

            Ok(BTreeMap::new())
        }
    }
}

/// Fetch data from the pre-aggregated `traffic_interval` table.
async fn fetch_traffic_interval(
    time_start: u32,
    window: u8,
    location: &'static str,
    iprange_dst: IpNetwork,
    pool: PgPool,
) -> Result<BTreeMap<IpNetwork, f64>> {
    // time_start   │ integer
    // train_window │ integer
    // location     │ text
    // iprange_dst  │ inet
    // iprange_srcs │ cidr[]
    // pkts_avgs    │ double precision[]

    struct Record {
        iprange_srcs: Vec<IpNetwork>,
        pkts_avgs: Vec<f64>,
    }

    let record = sqlx::query_as!(
        Record,
        r#"SELECT
        iprange_srcs as "iprange_srcs!",
        pkts_avgs as "pkts_avgs!"
    FROM traffic_interval
    WHERE
        time_start = $1
        AND train_window = $2
        AND location = $3
        AND iprange_dst = $4"#,
        time_start as i32,
        window as i32,
        &*location,
        iprange_dst
    )
    .fetch_one(&pool)
    .await
    .with_context(|| {
        format!(
            "Traffic interval for time_start {time_start}, train_window {window}, location \
             {location}, iprange_dst {iprange_dst}"
        )
    })?;

    let traffic: BTreeMap<IpNetwork, f64> =
        iter::zip(record.iprange_srcs, record.pkts_avgs).collect();
    Ok(traffic)
}

/// Merge multiple data source into a single iterator while synchronizing them.
///
/// The function takes multiple maps, all keyed on a [`IpNetwork`], and returns an iterator the joined data.
/// If the data is not available in one of the maps, `None` is returned.
fn giant_merge_join<'a, A, B, C, D>(
    attack_traffic: &'a BTreeMap<IpNetwork, A>,
    allowlist: &'a BTreeMap<IpNetwork, B>,
    train_traffic: &'a BTreeMap<IpNetwork, C>,
    test_traffic: &'a BTreeMap<IpNetwork, D>,
) -> impl Iterator<
    Item = (
        &'a IpNetwork,
        (Option<&'a A>, Option<&'a B>, Option<&'a C>, Option<&'a D>),
    ),
> {
    use itertools::Itertools as _;

    // Sanity check the multiple inputs, to ensure that merging them is actually possible correctly
    // The IpNetwork type can be unequal, if the underlying IP address from which it was created is unequal.
    // This can lead to a situation there two networks, which should match, are not equal.
    for net in attack_traffic.keys() {
        assert_eq!(
            net.ip(),
            net.network(),
            "Attack traffic network is not normalized {net:?}"
        );
    }
    for net in allowlist.keys() {
        assert_eq!(
            net.ip(),
            net.network(),
            "Allowlist network is not normalized {net:?}"
        );
    }
    for net in train_traffic.keys() {
        assert_eq!(
            net.ip(),
            net.network(),
            "Train traffic network is not normalized {net:?}"
        );
    }
    for net in test_traffic.keys() {
        assert_eq!(
            net.ip(),
            net.network(),
            "Test traffic network is not normalized {net:?}"
        );
    }

    trait FlattenTuple {
        type Output;
        fn into_flattened(self) -> Self::Output;
    }

    impl<A, B, C> FlattenTuple for (Option<(Option<A>, Option<B>)>, Option<C>) {
        type Output = (Option<A>, Option<B>, Option<C>);

        fn into_flattened(self) -> Self::Output {
            match self {
                (None, c) => (None, None, c),
                (Some((a, b)), c) => (a, b, c),
            }
        }
    }

    impl<A, B, C, D> FlattenTuple for (Option<(Option<A>, Option<B>, Option<C>)>, Option<D>) {
        type Output = (Option<A>, Option<B>, Option<C>, Option<D>);

        fn into_flattened(self) -> Self::Output {
            match self {
                (None, d) => (None, None, None, d),
                (Some((a, b, c)), d) => (a, b, c, d),
            }
        }
    }

    fn merge_by<Key, ValueLeft, ValueRight>(
        (left_key, _): &(Key, ValueLeft),
        (right_key, _): &(Key, ValueRight),
    ) -> Ordering
    where
        Key: Ord,
    {
        left_key.cmp(right_key)
    }

    fn merge_item<Key, ValueLeft, ValueRight>(
        item: itertools::EitherOrBoth<(Key, ValueLeft), (Key, ValueRight)>,
    ) -> (Key, (Option<ValueLeft>, Option<ValueRight>)) {
        match item {
            itertools::EitherOrBoth::Both((kl, vl), (_, vr)) => (kl, (Some(vl), Some(vr))),
            itertools::EitherOrBoth::Left((kl, vl)) => (kl, (Some(vl), None)),
            itertools::EitherOrBoth::Right((kr, vr)) => (kr, (None, Some(vr))),
        }
    }

    itertools::merge_join_by(attack_traffic, allowlist, merge_by)
        .map(merge_item)
        .merge_join_by(train_traffic, merge_by)
        .map(merge_item)
        .map(|(k, v)| (k, v.into_flattened()))
        .merge_join_by(test_traffic, merge_by)
        .map(merge_item)
        .map(|(k, v)| (k, v.into_flattened()))
}
