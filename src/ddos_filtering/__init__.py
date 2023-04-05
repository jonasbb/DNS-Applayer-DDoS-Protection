import argparse
import csv
import dataclasses
import json
import multiprocessing
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from typing import IO, Any, Generator, cast, overload

import dataclasses_json


def ipnetwork(nets: list[str]) -> list[IPv4Network | IPv6Network]:
    res: list[IPv4Network | IPv6Network] = []
    for net in nets:
        if ":" in net:
            res.append(IPv6Network(net))
        else:
            res.append(IPv4Network(net))
    return res


@dataclasses_json.dataclass_json
@dataclasses.dataclass
class Configuration:
    destination_addresses: list[IPv4Network | IPv6Network] = dataclasses.field(
        default_factory=lambda: list(
            [
                IPv4Network("0.0.0.0/0"),
                IPv6Network("::/0"),
            ]
        ),
        metadata=dataclasses_json.config(decoder=ipnetwork),
    )
    """Only collect traffic going to these IP networks"""

    aggregation_time: int = 3600
    """Time in seconds"""

    ipv4_aggregation: int = 24
    """Number of bits to aggregate IPv4 addresses"""
    ipv6_aggregation: int = 48
    """Number of bits to aggregate IPv6 addresses"""

    param_w_train: int = 24
    """Training window size (in multiple of aggregation_time)."""
    param_steady: int = 3
    """Minimum number of active hours before an IP network can be added to the allowlist."""
    param_heavy: int = 128
    """Minimum traffic level (in multiple of aggregation time) before an IP network can be added to the allowlist."""


@overload
def optional_ipv4_address(ip: None) -> None:
    ...


@overload
def optional_ipv4_address(ip: str) -> IPv4Address:
    ...


def optional_ipv4_address(ip: str | None) -> IPv4Address | None:
    if ip is None:
        return None
    return IPv4Address(ip)


@overload
def optional_ipv6_address(ip: None) -> None:
    ...


@overload
def optional_ipv6_address(ip: str) -> IPv6Address:
    ...


def optional_ipv6_address(ip: str | None) -> IPv6Address | None:
    if ip is None:
        return None
    return IPv6Address(ip)


@overload
def optional_datetime(dt: None) -> None:
    ...


@overload
def optional_datetime(dt: str) -> datetime:
    ...


def optional_datetime(dt: str | None) -> datetime | None:
    if dt is None:
        return None
    return datetime.fromisoformat(dt).replace(tzinfo=timezone.utc)


@dataclasses.dataclass
class NfFlow:
    in_packets: int
    dst_port: int

    first: datetime
    last: datetime

    src_addr: IPv4Address | IPv6Address
    dst_addr: IPv4Address | IPv6Address

    @classmethod
    def from_dict(cls, d: dict) -> "NfFlow":
        in_packets = d["in_packets"]
        dst_port = d["dst_port"]

        # nfdump 1.6 uses the t_ prefix for timestamps
        # nfdump 1.7 has the same field without prefix
        first = optional_datetime(d.get("first", None))
        if first is None:
            first = optional_datetime(d.get("t_first", None))
        if first is None:
            raise ValueError("A NetFlow must have a first timestamp.")
        last = optional_datetime(d.get("last", None))
        if last is None:
            last = optional_datetime(d.get("t_last", None))
        if last is None:
            raise ValueError("A NetFlow must have a last timestamp.")

        src4_addr = optional_ipv4_address(d.get("src4_addr", None))
        dst4_addr = optional_ipv4_address(d.get("dst4_addr", None))
        src6_addr = optional_ipv6_address(d.get("src6_addr", None))
        dst6_addr = optional_ipv6_address(d.get("dst6_addr", None))

        src_addr: IPv4Address | IPv6Address
        if src4_addr:
            src_addr = src4_addr
        elif src6_addr:
            src_addr = src6_addr
        else:
            raise ValueError(
                "A NetFlow must have a IPv4 or IPv6 source, but both are missing."
            )

        dst_addr: IPv4Address | IPv6Address
        if dst4_addr:
            dst_addr = dst4_addr
        elif dst6_addr:
            dst_addr = dst6_addr
        else:
            raise ValueError(
                "A NetFlow must have a IPv4 or IPv6 destination, but both are missing."
            )

        return NfFlow(in_packets, dst_port, first, last, src_addr, dst_addr)


class JsonWithComments(json.JSONDecoder):
    def __init__(self: "JsonWithComments", **kw: Any) -> None:
        super().__init__(**kw)

    def decode(self: "JsonWithComments", s: str) -> Any:
        s = "\n".join(l for l in s.split("\n") if not l.lstrip(" ").startswith("//"))
        return super().decode(s)


def init_argparse() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        nargs="?",
        type=argparse.FileType("rt", encoding="utf-8"),
        help="Path to the configuration file",
    )
    parser.add_argument(
        "-n",
        "--now",
        type=str,
        help="The current time as RFC3339 string.",
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        type=Path,
        help="Path to write the allowlist as CSV. - for stdout.",
    )
    parser.add_argument(
        "files",
        metavar="FILES",
        nargs="+",
        type=Path,
        help="nfdump files to process",
    )

    return parser


def main() -> None:
    """Main function for ddos-filtering."""

    args = init_argparse().parse_args()

    if args.config is not None:
        config_dict = json.load(args.config, cls=JsonWithComments)
        config = Configuration.from_dict(config_dict)
    else:
        config = Configuration()

    data: dict[IPv4Address | IPv6Address, dict[int, int]] = {}
    with multiprocessing.Pool() as pool:
        results = pool.starmap_async(
            process_netflow_file,
            ((file, config) for file in args.files),
            1,
        )

        for new_data in results.get():
            data = merge_data(data, new_data)

    allowlist: dict[IPv4Address | IPv6Address, int] = build_allowlist(
        data,
        config,
        optional_datetime(args.now).timestamp(),
    )

    if args.output is None:
        print(f"The allowlist contains {len(allowlist)} entries.")
    elif args.output.name == "-":
        write_allowlist_as_csv(sys.stdout, allowlist)
        sys.stdout.flush()
    else:
        with args.output.open("wt") as out:
            write_allowlist_as_csv(out, allowlist)


def process_netflow_file(
    file: Path, config: Configuration
) -> dict[IPv4Address | IPv6Address, dict[int, int]]:
    """
    Process a single nfdump file and return the aggregated data.
    """

    # Map from the source IP
    data: dict[IPv4Address | IPv6Address, dict[int, int]] = {}

    g = stream_filter(nfdump_json(file), config)
    for flow in g:
        aggregate_flows(data, config, flow)

    return data


def merge_data(
    data_a: dict[IPv4Address | IPv6Address, dict[int, int]],
    data_b: dict[IPv4Address | IPv6Address, dict[int, int]],
) -> dict[IPv4Address | IPv6Address, dict[int, int]]:
    """
    Take multiple (partial) data dicts and merge them into one.

    This can be used as the reduce stage for a map-reduce operation.
    """

    # Place the smaller dict into data_a
    if len(data_a) > len(data_b):
        data_a, data_b = data_b, data_a

    for src_addr, data in data_b.items():
        if src_addr not in data_a:
            data_a[src_addr] = data
            continue

        for time, count in data.items():
            data_a[src_addr][time] = data_a[src_addr].get(time, 0) + count

    return data_a


def nfdump_json(file: Path) -> Generator[NfFlow, None, None]:
    """
    Read nfdump file and convert it to json.
    """

    cmd: list[str | Path] = [
        "nfdump",
        "-r",
        file,
        "-o",
        "json",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        bufsize=1024 * 1024,
        pipesize=1024 * 1024,
    )
    yield from stream_read_json(cast(IO[bytes], proc.stdout))


def stream_read_json(f: IO[bytes]) -> Generator[NfFlow, None, None]:
    """
    Read a large JSON array in a streaming fashion.

    The JSON array must be pretty printed.
    This avoids buffering the whole data in memory.
    """

    def readuntil(
        stringio: IO[bytes], chunk: bytes, delim: bytes
    ) -> tuple[bytes, bytes]:
        """
        Read from a StringIO until a delimiter is found.

        `chunk` is the chunk from the previous read.

        Returns a tuple of the data read and the chunk of unprocessed data.
        """
        datalist: list[bytes] = []

        # Process the chunk from the previous read
        i = chunk.find(delim)
        if i == -1:
            datalist.append(chunk)
        else:
            return (chunk[: i + len(delim)], chunk[i + len(delim) :])

        while True:
            chunk = stringio.read(256)
            i = chunk.find(delim)
            if i == -1:
                datalist.append(chunk)
            else:
                datalist.append(chunk[: i + len(delim)])
                chunk = chunk[i + len(delim) :]
                break
            if len(chunk) < 256:
                break
        return (b"".join(datalist), chunk)

    buf: list[bytes] = []
    chunk = b""
    while True:
        line, chunk = readuntil(f, chunk, b"\n")
        if line.startswith(b"]"):
            return
        if line.startswith(b"{"):
            buf.append(line)

        while True:
            obj, chunk = readuntil(f, chunk, b"}")
            buf.append(obj)
            break

        d = json.loads(b"".join(buf))
        yield NfFlow.from_dict(d)
        buf.clear()


def stream_filter(
    stream: Generator[NfFlow, None, None], config: Configuration
) -> Generator[NfFlow, None, None]:
    """
    Filter the flows to only include flows that are destined to the destination addresses and to port 53 (DNS).
    """
    for flow in stream:
        if flow.dst_port == 53 and any(
            flow.dst_addr in net for net in config.destination_addresses
        ):
            yield flow


def aggregate_flows(
    data: dict[IPv4Address | IPv6Address, dict[int, int]],
    config: Configuration,
    flow: NfFlow,
) -> None:
    """
    Aggregate the flows into buckets based on the source IP, the time, and the configuration.
    """

    # Convert the dst IP into a network, but store it as the network address, to not store the netmask multiple times
    src = flow.src_addr
    if isinstance(src, IPv4Address):
        src = IPv4Network((src, config.ipv4_aggregation), strict=False).network_address
    elif isinstance(src, IPv6Address):
        src = IPv6Network((src, config.ipv6_aggregation), strict=False).network_address

    # If both first and last time fall into the same bucket we can simplify a bunch of the computations
    first = flow.first.timestamp()
    last = flow.last.timestamp()
    first_bucket = int(first) - (int(first) % config.aggregation_time)
    last_bucket = int(last) - (int(last) % config.aggregation_time)

    if src not in data:
        data[src] = {}

    if first_bucket == last_bucket:
        data[src][first_bucket] = data[src].get(first_bucket, 0) + flow.in_packets
    else:
        # Compute the spread of packets between the first and last bucket
        time_total = last - first
        # -1 because the first packet is at first and the last packet is at last
        # So there are n-1 gaps in between
        time_delta_between_packets = time_total / (flow.in_packets - 1)
        for i in range(flow.in_packets):
            # Compute the time of the packet
            time = first + i * time_delta_between_packets
            # Compute the bucket
            bucket = int(time - (time % config.aggregation_time))
            data[src][bucket] = data[src].get(bucket, 0) + 1


def build_allowlist(
    data: dict[IPv4Address | IPv6Address, dict[int, int]],
    config: Configuration,
    now: float,
) -> dict[IPv4Address | IPv6Address, int]:
    """
    Build the allowlist from the data.
    """

    now_bucket = int(now) - (int(now) % config.aggregation_time)
    earliest_time = now_bucket - config.aggregation_time * config.param_w_train
    allowlist: dict[IPv4Address | IPv6Address, int] = defaultdict(lambda: 0)

    for ip, buckets in data.items():
        valid_traffic = [
            traffic
            for time, traffic in buckets.items()
            if earliest_time <= time and time < now
        ]
        if len(valid_traffic) < config.param_steady:
            continue
        if max(valid_traffic) < config.param_heavy:
            continue
        allowlist[ip] = max(valid_traffic)

    return allowlist


def write_allowlist_as_csv(
    out: IO[str], allowlist: dict[IPv4Address | IPv6Address, int]
) -> None:
    """
    Write the allowlist as CSV to the given output stream.
    """

    wtr = csv.DictWriter(out, ["ip", "packets"])
    wtr.writeheader()
    wtr.writerows({"ip": ip, "packets": packets} for ip, packets in allowlist.items())


if __name__ == "__main__":
    main()
