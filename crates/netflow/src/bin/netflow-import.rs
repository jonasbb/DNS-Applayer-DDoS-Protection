#![recursion_limit = "512"]
#![deny(unused_import_braces, unused_qualifications)]

use color_eyre::eyre::{Context as _, Result};
use futures::stream;
use futures::stream::{StreamExt, TryStreamExt};
use netflow::aggregate::IpAggregate;
use netflow::Proto;
use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, clap::Parser)]
struct CliArgs {
    agg_interval: i32,
    location: String,
    // Aggregate files to import
    files: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();
    let args: CliArgs = clap::Parser::parse();

    let mut pgoptions =
        PgConnectOptions::from_str("postgres:///cctld")?.application_name("netflow-import");
    pgoptions
        .log_statements(log::LevelFilter::Debug)
        .log_slow_statements(log::LevelFilter::Info, Duration::new(60, 0));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::new(60, 0))
        .idle_timeout(Duration::new(30, 0))
        .test_before_acquire(true)
        .connect_with(pgoptions)
        .await?;

    let pool = pool.clone();
    let location = Arc::new(args.location.clone());
    stream::iter(args.files.clone())
        .map(|file| process_file(pool.clone(), file, location.clone(), args.agg_interval))
        .buffer_unordered(1)
        .try_collect()
        .await?;

    Ok(())
}

async fn process_file(
    pool: sqlx::postgres::PgPool,
    file: PathBuf,
    location: Arc<String>,
    agg_interval: i32,
) -> Result<()> {
    let content = std::fs::read_to_string(file)?;
    let mut deserializer = serde_json::Deserializer::from_str(&content);
    let full_aggregate: netflow::aggregate::FullAggregate =
        serde_path_to_error::deserialize(&mut deserializer)?;

    #[allow(clippy::too_many_arguments)]
    async fn insert_entry(
        pool: &sqlx::postgres::PgPool,
        location: &str,
        agg_interval: i32,
        time: u32,
        network_prefix: u8,
        ip: IpAddr,
        proto: Proto,
        ipnetwork_dst: IpAddr,
        data: IpAggregate,
    ) -> Result<()> {
        let ipnetwork_src = sqlx::types::ipnetwork::IpNetwork::new(ip, network_prefix)?;
        let dst_prefix = match ipnetwork_dst {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let ipnetwork_dst = sqlx::types::ipnetwork::IpNetwork::new(ipnetwork_dst, dst_prefix)?;
        sqlx::query_unchecked!(
            "INSERT INTO nfaggregates VALUES ($1, $2, $3, $4, $5, $6, $7);",
            location,
            ipnetwork_src,
            time as i32,
            agg_interval,
            proto.0 as i16,
            ipnetwork_dst,
            // general fields
            data.total_packets as i32,
        )
        .execute(pool)
        .await
        .wrap_err_with(|| {
            format!(
                "Key: {}, {}, {}, {}, {}, {}",
                location, ipnetwork_src, time, agg_interval, proto.0, ipnetwork_dst
            )
        })?;
        Ok(())
    }

    stream::iter(full_aggregate.ipv4.into_iter())
        .map(Ok)
        .try_for_each_concurrent(10, |((time, proto, ip_src, ipnetwork_dst), data)| {
            insert_entry(
                &pool,
                &location,
                agg_interval,
                time,
                24,
                ip_src.into(),
                proto,
                ipnetwork_dst.into(),
                data,
            )
        })
        .await?;

    stream::iter(full_aggregate.ipv6.into_iter())
        .map(Ok)
        .try_for_each_concurrent(10, |((time, proto, ip_src, ipnetwork_dst), data)| {
            insert_entry(
                &pool,
                &location,
                agg_interval,
                time,
                48,
                ip_src.into(),
                proto,
                ipnetwork_dst.into(),
                data,
            )
        })
        .await?;
    Ok(())
}
