//! Parse the output of `nfdump -o json`

#![deny(unused_import_braces, unused_qualifications)]

pub mod aggregate;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IP address can be with all bits.
/// `tcp_flags` contains the TCP flags in string from, like `A` or `P`.
///
/// ```json
/// {
///     "type" : "FLOW",
///     "sampled" : 0,
///     "export_sysid" : 19,
///     "t_first" : "2000-01-01T00:00:00.000",
///     "t_last" : "2000-01-01T00:00:00.000",
///     "proto" : 17,
///
///     "src4_addr" : "198.51.100.1",
///     "dst4_addr" : "198.51.100.1",
///
///     "src6_addr" : "2001:db8::1",
///     "dst6_addr" : "2001:db8::1",
///
///     "fwd_status" : 64,
///     "tcp_flags" : "........",
///     "src_tos" : 0,
///     "in_packets" : 1,
///     "in_bytes" : 100,
///     "input_snmp" : 37,
///     "output_snmp" : 47,
///     "src_as" : 0,
///     "dst_as" : 0,
///     "ip4_router" : "198.51.100.1",
///     "engine_type" : 0,
///     "engine_id" : 0,
///     "t_received" : "2000-01-01T00:00:00.000",
///     "label" : "<none>",
///
///     "src_mask" : 48,
///     "dst_mask" : 128,
///
///     "dst_tos" : 0,
///     "direction" : 0,
///
///     "bgp4_next_hop" : "198.51.100.1",
///     "bgp6_next_hop" : "2001:db8::1",
///
///     "icmp_type" : 135,
///     "icmp_code" : 0,
///
///     "src_port" : 60012,
///     "dst_port" : 443,
///
///     "ip4_next_hop" : "198.51.100.1",
///     "ip6_next_hop" : "2001:db8::1",
///
///     "in_src_mac" : "ff:ff:ff:ff:ff:ff",
///     "out_dst_mac" : "00:00:00:00:00:00",
///
///     "nat_event_id" : "0",
///     "nat_event" : "IGNORE",
///
///     "ingress_vrf" : "1610612736",
///     "egress_vrf" : "1610612736",
/// }
/// ```
#[allow(clippy::type_complexity)]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NfdumpOutput {
    #[serde(rename = "type")]
    pub type_: monostate::MustBe!("FLOW"),
    pub sampled: monostate::MustBe!(0),
    pub export_sysid: u32,
    pub t_first: chrono::NaiveDateTime,
    pub t_last: chrono::NaiveDateTime,
    pub proto: Proto,
    pub src6_addr: Option<Ipv6Addr>,
    pub dst6_addr: Option<Ipv6Addr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub fwd_status: ForwardStatus,
    pub tcp_flags: TcpFlags,
    pub src_tos: u8,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub input_snmp: u32,
    pub output_snmp: u32,
    pub src_as: u32,
    pub dst_as: u32,
    pub ip4_router: Ipv4Addr,
    pub engine_type: u8,
    pub engine_id: u32,
    pub t_received: chrono::NaiveDateTime,
    pub label: monostate::MustBe!("<none>"),

    pub src_mask: Option<u8>,
    pub dst_mask: Option<u8>,

    pub dst_tos: Option<u8>,
    pub direction: Option<Direction>,

    pub bgp4_next_hop: Option<Ipv4Addr>,
    pub bgp6_next_hop: Option<Ipv6Addr>,

    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,

    pub src4_addr: Option<Ipv4Addr>,
    pub dst4_addr: Option<Ipv4Addr>,

    pub ip4_next_hop: Option<Ipv4Addr>,
    pub ip6_next_hop: Option<Ipv6Addr>,

    pub in_src_mac: Option<String>,
    pub out_dst_mac: Option<String>,

    pub nat_event_id: Option<monostate::MustBe!("0")>,
    pub nat_event: Option<monostate::MustBe!("IGNORE")>,

    // TODO string with numeric value
    pub ingress_vrf: Option<monostate::MustBe!("1610612736")>,
    // TODO string with numeric value
    pub egress_vrf: Option<String>,
}

// #[derive(Debug, serde_repr::Deserialize_repr)]
// #[repr(u8)]
// pub enum Proto {
//     /// Internet Control Message
//     ICMP = 1,
//     /// Gateway-to-Gateway
//     GGP = 3,
//     /// Transmission Control
//     TCP = 6,
//     /// Interior Gateway
//     IGP = 9,
//     /// User Datagram
//     UDP = 17,
//     /// Generic Routing Encapsulation
//     GRE = 47,
//     /// Encap Security Payload
//     ESP = 50,
//     /// ICMP for IPv6
//     ICMP6 = 58,
//     /// Open Shortest Path First Internet Gateway Protocol
//     OSPFIGP = 89,
//     /// Protocol Independent Multicast
//     PIM = 103,
//     /// Stream Control Transmission Protocol
//     SCTP = 132,
// }

/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1>
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct Proto(pub u8);

impl Proto {
    /// Internet Control Message
    pub const ICMP: Self = Self(1);
    /// Gateway-to-Gateway
    pub const GGP: Self = Self(3);
    /// Transmission Control
    pub const TCP: Self = Self(6);
    /// Interior Gateway
    pub const IGP: Self = Self(9);
    /// User Datagram
    pub const UDP: Self = Self(17);
    /// Encap Security Payload
    pub const ESP: Self = Self(50);
    /// ICMP for IPv6
    pub const ICMP6: Self = Self(58);
    /// Protocol Independent Multicast
    pub const PIM: Self = Self(103);
    /// Generic Routing Encapsulation
    pub const GRE: Self = Self(47);
    /// Open Shortest Path First Internet Gateway Protocol
    pub const OSPFIGP: Self = Self(89);
    /// Stream Control Transmission Protocol
    pub const SCTP: Self = Self(132);
}

#[derive(Debug, serde::Deserialize)]
#[serde(transparent)]
pub struct ForwardStatus(u8);

#[derive(Debug, serde_with::DeserializeFromStr)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);
}

impl std::str::FromStr for TcpFlags {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 8 {
            return Err(format!("invalid tcp flags: {}", s));
        }
        let value = std::iter::zip(
            s.chars(),
            [
                Self::CWR.0,
                Self::ECE.0,
                Self::URG.0,
                Self::ACK.0,
                Self::PSH.0,
                Self::RST.0,
                Self::SYN.0,
                Self::FIN.0,
            ],
        )
        .map(|(c, val)| if c == '.' { 0 } else { val })
        .sum();
        Ok(Self(value))
    }
}

#[derive(Debug, serde_repr::Deserialize_repr)]
#[repr(u8)]
pub enum Direction {
    Incomming = 0,
    Outgoing = 1,
}

/// Return `true` is the flow targets a nameserver of our ccTLD
pub fn is_for_target_cctld(flow: &NfdumpOutput) -> bool {
    if flow.dst_port != Some(53) {
        return false;
    }
    if !matches!(flow.proto, Proto::TCP | Proto::UDP) {
        return false;
    }
    if let Some(_dst4_addr) = flow.dst4_addr {
        // TODO: Filter here for the IPv4 addresses of the ccTLD
    } else if let Some(_dst6_addr) = flow.dst6_addr {
        // TODO: Filter here for the IPv6 addresses of the ccTLD
    }

    true
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Packet {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub proto: Proto,
    pub bytes: u64,
    pub time: chrono::NaiveDateTime,
}

/// Split one flow into multiple equal spaced packets
///
/// One flow can contain multiple packets.
/// However, we do not know how the packets are spaced timewise or their size distribution.
/// For this simple pass, assume there was one packet at the beginning of the flow and one at the end.
/// All other packets are equally spaced between the two.
/// The size of the packets is also equal, except the first one, which can be larger to have the same byte sum.
#[allow(dead_code)]
pub fn split_flow(flow: NfdumpOutput) -> impl Iterator<Item = Packet> {
    let src_addr: IpAddr = if let Some(src_addr) = flow.src4_addr {
        src_addr.into()
    } else if let Some(src_addr) = flow.src6_addr {
        src_addr.into()
    } else {
        panic!("no src addr");
    };
    let dst_addr: IpAddr = if let Some(dst_addr) = flow.dst4_addr {
        dst_addr.into()
    } else if let Some(dst_addr) = flow.dst6_addr {
        dst_addr.into()
    } else {
        panic!("no dst addr");
    };
    let proto = flow.proto;
    let num_packets = flow.in_packets;
    let total_bytes = flow.in_bytes;
    let mut time_start = flow.t_first;

    if num_packets == 1 {
        vec![Packet {
            src_addr,
            dst_addr,
            proto,
            bytes: total_bytes,
            time: time_start,
        }]
        .into_iter()
    } else {
        let bytes_per_packet = total_bytes / num_packets;
        let extra_bytes = total_bytes % num_packets;
        let time_end = flow.t_last;
        let time_delta = (time_end - time_start) / (i32::try_from(num_packets).unwrap() - 1);

        let first_packet = Packet {
            src_addr,
            dst_addr,
            proto,
            bytes: bytes_per_packet + extra_bytes,
            time: time_start,
        };

        let mut res = Vec::with_capacity(num_packets as usize);
        res.push(first_packet);
        for _ in 1..num_packets {
            time_start += time_delta;
            let packet = Packet {
                src_addr,
                dst_addr,
                proto,
                bytes: bytes_per_packet,
                time: time_start,
            };
            res.push(packet);
        }
        res.into_iter()
    }
}

#[test]
#[ignore = "Requires a pre-processed file"]
fn test_nfdump_output() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let data = std::fs::read_to_string("/tmp/netflow.json")?;
    let jd = &mut serde_json::Deserializer::from_str(&data);
    let _netflow: Vec<NfdumpOutput> = serde_path_to_error::deserialize(jd)?;

    Ok(())
}
