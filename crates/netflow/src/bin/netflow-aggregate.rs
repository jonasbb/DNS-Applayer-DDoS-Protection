//! Calculate different aggregates on nfcap NetFlow files.

#![deny(unused_import_braces, unused_qualifications)]

use color_eyre::eyre::{bail, Context as _, Result};
use netflow::aggregate::{FullAggregate, IpAggregate};
use netflow::is_for_target_cctld;
use rayon::prelude::*;
use std::io::{BufRead, BufReader};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Stdio;

/// Calculate different aggregates on NetFlow files
///
/// The `AggregateType` determines the aggregate to be calculated and can have further arguments, such as an aggregation interval.
#[derive(Debug, clap::Parser)]
struct CliArgs {
    #[clap(long = "output")]
    output: PathBuf,
    #[clap(subcommand)]
    agg: AggregateType,

    files: Vec<PathBuf>,
}

#[derive(Debug, clap::Subcommand)]
enum AggregateType {
    /// Traffic volume statistics about the packets per IP and distinct IPs per time
    TrafficVolume {
        /// Discard all data before this timestamp. Usefull to limit the aggregation in size.
        #[clap(long = "time-start")]
        time_start: Option<u32>,
        /// Discard all data after this timestamp. Usefull to limit the aggregation in size.
        #[clap(long = "time-end")]
        time_end: Option<u32>,

        /// Aggregation interval: All timestamps are grouped into groups of this many seconds.
        #[clap(long = "agg-interval")]
        agg_interval: u32,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();
    let args: CliArgs = clap::Parser::parse();

    match args.agg {
        AggregateType::TrafficVolume {
            time_start,
            time_end,
            agg_interval,
        } => {
            let time_start = time_start.unwrap_or(0);
            let time_end = time_end.unwrap_or(u32::MAX);

            log::info!("Start aggregating input files.");
            log::info!(
                "Each aggregation entry consumes at least {} bytes",
                mem::size_of::<IpAggregate>()
            );
            let aggregate: FullAggregate =
                aggregate_query_responses(&args.files, time_start, time_end, agg_interval)?;
            log::info!(
                "Found {} IPv4 and {} IPV6 entries.",
                aggregate.ipv4.len(),
                aggregate.ipv6.len()
            );
            log::info!("Finished aggregating, start writing output file.");
            serialize_to_file(args.output, &aggregate)?;
            log::info!("Finished writing the output file.");
        }
    }

    Ok(())
}

fn serialize_to_file(file: PathBuf, value: impl serde::Serialize) -> Result<()> {
    std::fs::write(file, serde_json::to_string(&value)?)?;
    Ok(())
}

fn aggregate_query_responses(
    files: &[PathBuf],
    time_start: u32,
    time_end: u32,
    agg_interval: u32,
) -> Result<FullAggregate> {
    assert!(
        time_start < time_end,
        "time_start always needs to be smaller than time_end"
    );

    let aggregate = files
        .par_iter()
        .with_min_len(1)
        .map(|path| -> Result<FullAggregate> {
            let unpack_pgrm = if path.extension().unwrap_or_default() == "gz" {
                "zcat"
            } else {
                "cat"
            };
            let mut unpack_file = std::process::Command::new(unpack_pgrm)
                .arg(path)
                .stdout(Stdio::piped())
                .spawn()?;

            let mut nfdump = std::process::Command::new("nfdump")
                .args(["-o", "json", "-r", "-"])
                .stdin(unpack_file.stdout.take().expect("Must exist"))
                .stdout(Stdio::piped())
                .spawn()?;

            let mut aggregate = FullAggregate::default();
            let mut nfdump_json = BufReader::new(nfdump.stdout.take().expect("Must exist"));
            // Temporary buffer, holds up to one JSON object
            let mut object = String::with_capacity(1024 * 10);

            'outer: loop {
                object.clear();
                // Read garbage, either "[" or ","
                nfdump_json.read_line(&mut object)?;
                if object.starts_with(']') {
                    // reached the end of the JSON array
                    break 'outer;
                }
                object.clear();
                while !object.ends_with("}\n") {
                    let nbytes = nfdump_json.read_line(&mut object)?;
                    if nbytes == 0 {
                        bail!("Reached EOF instead of properly detecting the closing `]`.")
                    }
                }

                let netflow: netflow::NfdumpOutput = serde_json::from_str(&object)
                    .with_context(|| format!("Original JSON: {object}"))?;
                if !is_for_target_cctld(&netflow) {
                    continue;
                }

                for packet in netflow::split_flow(netflow) {
                    let src_ip = ip_to_network_address(packet.src_addr, 24, 48);
                    let dst_ip = packet.dst_addr;
                    let seconds = packet.time.timestamp() as u32;
                    // Round to aggregation interval
                    let timestamp = seconds - (seconds % agg_interval);
                    if !(time_start..time_end).contains(&timestamp) {
                        // Abort early if the timestamp is outside of the range we care about
                        continue;
                    }
                    let ipaggregate = match src_ip {
                        IpAddr::V4(ipv4) => {
                            let dst_v4 = if let IpAddr::V4(dst_v4) = dst_ip {
                                dst_v4
                            } else {
                                panic!("Destination IP must be of same type as source ip.");
                            };
                            aggregate
                                .ipv4
                                .entry((timestamp, packet.proto, ipv4, dst_v4))
                                .or_default()
                        }
                        IpAddr::V6(ipv6) => {
                            let dst_v6 = if let IpAddr::V6(dst_v6) = dst_ip {
                                dst_v6
                            } else {
                                panic!("Destination IP must be of same type as source ip.");
                            };
                            aggregate
                                .ipv6
                                .entry((timestamp, packet.proto, ipv6, dst_v6))
                                .or_default()
                        }
                    };

                    ipaggregate.total_packets += 1;
                }
            }

            // Wait for processes to exit
            nfdump.wait()?;
            unpack_file.wait()?;

            Ok(aggregate)
        })
        .try_reduce(Default::default, |result, aggregate| Ok(result + aggregate))?;

    Ok(aggregate)
}

pub fn ip_to_network_address(ip: IpAddr, cidrv4: u8, cidrv6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4_to_network_address(ipv4, cidrv4)),
        IpAddr::V6(ipv6) => IpAddr::V6(ipv6_to_network_address(ipv6, cidrv6)),
    }
}

pub fn ipv4_to_network_address(ip: Ipv4Addr, cidr: u8) -> Ipv4Addr {
    const NULL_V4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

    // Shifting by 32 bits is illegal
    if cidr == 0 {
        return NULL_V4;
    }

    assert!(cidr <= 32, "CIDR for IPv4 must be <= 32");
    let mask = !((1 << (32 - cidr)) - 1);
    let ip = u32::from_be_bytes(ip.octets());
    Ipv4Addr::from(ip & mask)
}

pub fn ipv6_to_network_address(ip: Ipv6Addr, cidr: u8) -> Ipv6Addr {
    const NULL_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

    // Shifting by 128 bits is illegal
    if cidr == 0 {
        return NULL_V6;
    }

    assert!(cidr <= 128, "CIDR for IPv6 must be <= 128");
    let mask = !((1 << (128 - cidr)) - 1);
    let ip = u128::from_be_bytes(ip.octets());
    Ipv6Addr::from(ip & mask)
}
