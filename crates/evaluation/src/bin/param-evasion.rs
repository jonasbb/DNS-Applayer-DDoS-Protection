//! Evaluate a set of evasion configurations.
//!
//! This consumes the `eval_results_*.json` files produced by `param-grid-search`.
//! It produces a new file `./results_evasion_{configuration}{extra}.json`.

#![deny(unused_import_braces, unused_qualifications)]

use color_eyre::eyre::Result;
use evaluation::{DataConfiguration, EvaluationResults, Location};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
struct CliArgs {
    /// Identifier to select input files and name output files
    ///
    /// This identifier must occur in the path of the input files.
    /// This allows filtering a subset of all available files.
    /// The value is also embedded in the output file names.
    #[clap(long)]
    configuration: String,
    /// Extra value added to the output filename
    #[clap(long)]
    extra: Option<String>,
    /// Folder which contains the `eval_results_*.json` files in a suitable structure
    ///
    /// The `-0ips` in the folder name is importand.
    /// It specifies how many of the attacker IP addresses were used in the evasion simulation.
    ///
    /// ```text
    /// .
    /// ├── name-0ips
    /// │   ├── eval_results_xxx_198.51.100.1_109951162777600bps.json
    /// │   └── eval_results_xxy_203.0.113.1_109951162777600bps.json
    /// └── name-10000ips
    ///     ├── eval_results_xxx_198.51.100.1_109951162777600bps.json
    ///     └── eval_results_xxy_203.0.113.1_109951162777600bps.json
    /// ```
    #[arg(num_args(1))]
    basedir: PathBuf,
}

impl CliArgs {
    /// Return batches of files which need to be processed together.
    fn files(&self) -> Vec<PathBuf> {
        Location::logical_dsts()
            .into_iter()
            .flat_map(|logical_dst| -> Vec<PathBuf> {
                let belongs_to_dst = |entry: &walkdir::DirEntry| -> bool {
                    entry.file_name().to_string_lossy().contains(logical_dst)
                };

                let walker =
                    walkdir::WalkDir::new(self.basedir.join(&self.configuration)).into_iter();
                walker
                    .filter_map(|e| match e {
                        Ok(e) => {
                            if belongs_to_dst(&e) {
                                Some(e.path().to_owned())
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    })
                    .collect()
            })
            .collect()
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();
    let args: CliArgs = clap::Parser::parse();

    evasion_eval(&args)?;

    Ok(())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct AlgorithmParameters {
    pub location: Location,
    pub iprange_dst: ipnetwork::IpNetwork,
    pub train_length: u8,
    pub test_length: u8,
    pub min_active: u8,
    pub min_pkts_avg: u32,
    pub low_pass: u32,
    pub above_train_limit: u8,
    pub attack_bandwidth: u64,
}

fn evasion_eval(args: &CliArgs) -> Result<()> {
    #[allow(clippy::type_complexity)]
    let mut precomputed: BTreeMap<
        /* Number of evasion IPs */ u64,
        BTreeMap<AlgorithmParameters, Vec<EvaluationResults>>,
    > = Default::default();

    for file in args.files() {
        // Get the number of evasion IPs
        let parent_dir = file
            .parent()
            .expect("Parent dir with evasion IP number must exist")
            .file_name()
            .expect("Parent dir with evasion IP number must exist")
            .to_string_lossy();
        let parent_dir = parent_dir
            .strip_suffix("ips")
            .expect("Parent dir must end with 'ips'");
        let evasion_ips: u64 = parent_dir
            .split('-')
            .last()
            .expect("Parent dir must end with 'ips'")
            .parse()?;

        let eval_results: BTreeMap<AlgorithmParameters, Vec<EvaluationResults>> =
            load_filebatch(&[file])?;
        precomputed
            .entry(evasion_ips)
            .or_default()
            .extend(eval_results);
    }
    let precomputed = &precomputed;

    let evasions: Vec<serde_json::Value> = precomputed
        .iter()
        .flat_map(|(&evasion_ips, evasion_data)| {
            evasion_data.iter().map(move |(params, eval_results)| {
                let mut fprs = Vec::new();
                let mut attack_traffic = Vec::new();

                for eval_result in eval_results {
                    fprs.push(eval_result.fpr());
                    attack_traffic.push(eval_result.false_negatives);
                }

                let avg_fpr = fprs.iter().cloned().sum::<f64>() / fprs.len() as f64;
                let avg_attack_traffic = attack_traffic.iter().cloned().sum::<f64>() as f64
                    / attack_traffic.len() as f64;

                serde_json::json!({
                    "location": params.location,
                    "iprange_dst": params.iprange_dst,

                    "evasion_ips": evasion_ips,

                    "fpr": avg_fpr,
                    "attack_traffic": avg_attack_traffic,

                    "params": params,
                })
            })
        })
        .collect();

    let extra = match &args.extra {
        Some(extra) => format!("_{}", extra),
        None => String::new(),
    };
    std::fs::write(
        format!(
            "./results_evasion_{configuration}{extra}.json",
            configuration = args.configuration
        ),
        serde_json::to_string(&evasions)?,
    )?;

    Ok(())
}

fn load_filebatch(
    filebatch: &[PathBuf],
) -> Result<BTreeMap<AlgorithmParameters, Vec<EvaluationResults>>, color_eyre::Report> {
    let mut eval_results: BTreeMap<AlgorithmParameters, Vec<Option<EvaluationResults>>> =
        BTreeMap::new();

    for file in filebatch {
        let attack_bandwidth = file
            .to_string_lossy()
            .split("bps")
            .next()
            .unwrap()
            .rsplit('_')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        let res: Vec<(DataConfiguration<()>, EvaluationResults)> = {
            let data = std::fs::read_to_string(file)?;
            serde_json::from_str(&data)?
        };

        // Extract logical destination
        let location;
        let iprange_dst;
        {
            let dc = &res.first().unwrap().0;
            location = dc.location;
            iprange_dst = dc.iprange_dst;
        }

        for (config, result) in res {
            let params = AlgorithmParameters {
                location,
                iprange_dst,
                train_length: config.train_length,
                test_length: config.test_length,
                min_active: config.min_active,
                min_pkts_avg: config.min_pkts_avg,
                low_pass: config.low_pass,
                above_train_limit: config.above_train_limit.round() as u8,
                attack_bandwidth,
            };
            let results = eval_results.entry(params).or_default();
            if results.len() < config.window_start as usize {
                results.resize(config.window_start as usize, None);
            }
            results[config.window_start as usize - 1] = Some(result);
        }
    }

    Ok(eval_results
        .into_iter()
        .map(|(k, v)| {
            let v: Vec<EvaluationResults> = v.into_iter().map(Option::unwrap).collect();
            (k, v)
        })
        .collect())
}
