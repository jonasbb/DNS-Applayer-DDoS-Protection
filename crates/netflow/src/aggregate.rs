use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Aggregate for a single IP address
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct IpAggregate {
    pub total_packets: u64,
}

impl std::ops::AddAssign for IpAggregate {
    fn add_assign(&mut self, rhs: Self) {
        self.total_packets += rhs.total_packets;
    }
}

/// Aggregate for all Netflows together
#[serde_with::serde_as]
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FullAggregate {
    /// IPv4 aggregates
    ///
    /// Timestamp, protocol, source IP, destination IP
    #[serde_as(as = "Vec<(_, _)>")]
    pub ipv4: BTreeMap<(u32, super::Proto, Ipv4Addr, Ipv4Addr), IpAggregate>,
    #[serde_as(as = "Vec<(_, _)>")]
    pub ipv6: BTreeMap<(u32, super::Proto, Ipv6Addr, Ipv6Addr), IpAggregate>,
}

impl std::ops::Add for FullAggregate {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        if self.ipv4.is_empty() {
            self.ipv4 = rhs.ipv4;
        } else {
            rhs.ipv4.into_iter().for_each(|(key, value)| {
                *self.ipv4.entry(key).or_default() += value;
            });
        };
        if self.ipv6.is_empty() {
            self.ipv6 = rhs.ipv6;
        } else {
            rhs.ipv6.into_iter().for_each(|(key, value)| {
                *self.ipv6.entry(key).or_default() += value;
            });
        };
        self
    }
}
