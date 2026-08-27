//! CIDR reasoning for the exposure model.
//!
//! Only what the network analysis needs: is this source the whole internet, is
//! it uncomfortably broad, and does it cover a given address. A general IP
//! library would be more than this product uses and one more dependency to
//! audit.
//!
//! IPv6 is recognised but only coarsely: enough to spot `::/0`, which is the
//! case that matters for an exposure warning.

use std::{fmt, net::Ipv4Addr, str::FromStr};

use serde::Serialize;
use thiserror::Error;

/// A source address range from an OCI security rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "family", content = "value")]
pub enum Cidr {
    V4(Ipv4Cidr),
    /// An IPv6 range, kept as text plus its prefix length.
    V6 {
        text: String,
        prefix: u8,
    },
}

impl Cidr {
    /// Whether this range is every address on the internet.
    #[must_use]
    pub fn is_entire_internet(&self) -> bool {
        match self {
            Self::V4(cidr) => cidr.prefix == 0,
            Self::V6 { prefix, .. } => *prefix == 0,
        }
    }

    /// Whether this range is broad enough to be worth warning about.
    ///
    /// For IPv4 that is a /8 or shorter — at least 16 million addresses, which
    /// is far more than any legitimate administrative allow-list. For IPv6 the
    /// equivalent threshold is a /32.
    #[must_use]
    pub fn is_broad(&self) -> bool {
        match self {
            Self::V4(cidr) => cidr.prefix <= 8,
            Self::V6 { prefix, .. } => *prefix <= 32,
        }
    }

    /// Whether this range is a single host.
    #[must_use]
    pub fn is_single_host(&self) -> bool {
        match self {
            Self::V4(cidr) => cidr.prefix == 32,
            Self::V6 { prefix, .. } => *prefix == 128,
        }
    }

    /// Whether this range lies entirely inside RFC 1918 private space.
    ///
    /// A rule sourced from private space cannot be reached from the internet,
    /// which changes how an audit finding should be phrased.
    #[must_use]
    pub fn is_private(&self) -> bool {
        match self {
            Self::V4(cidr) => cidr.is_private(),
            // Unique-local addressing; not analysed further.
            Self::V6 { text, .. } => {
                let lowered = text.to_ascii_lowercase();
                lowered.starts_with("fc") || lowered.starts_with("fd")
            }
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(cidr) => write!(f, "{cidr}"),
            Self::V6 { text, .. } => f.write_str(text),
        }
    }
}

impl FromStr for Cidr {
    type Err = ParseCidrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ParseCidrError::Empty);
        }
        if trimmed.contains(':') {
            let (address, prefix) = trimmed
                .split_once('/')
                .ok_or_else(|| ParseCidrError::Malformed(trimmed.to_owned()))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| ParseCidrError::Malformed(trimmed.to_owned()))?;
            if prefix > 128 || address.is_empty() {
                return Err(ParseCidrError::Malformed(trimmed.to_owned()));
            }
            return Ok(Self::V6 {
                text: trimmed.to_owned(),
                prefix,
            });
        }
        Ok(Self::V4(trimmed.parse()?))
    }
}

/// An IPv4 address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv4Cidr {
    /// Network address with the host bits cleared.
    pub base: u32,
    pub prefix: u8,
}

impl Ipv4Cidr {
    /// Whether `address` falls inside this range.
    #[must_use]
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = Self::mask(self.prefix);
        (u32::from(address) & mask) == self.base
    }

    /// Number of addresses covered.
    #[must_use]
    pub fn address_count(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// Whether the whole range is RFC 1918 private space.
    #[must_use]
    pub fn is_private(&self) -> bool {
        const PRIVATE: [(&str, u8); 3] = [("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16)];
        PRIVATE.iter().any(|(network, prefix)| {
            let Ok(address) = network.parse::<Ipv4Addr>() else {
                return false;
            };
            let block = Self {
                base: u32::from(address) & Self::mask(*prefix),
                prefix: *prefix,
            };
            // Contained means at least as specific, and inside the block.
            self.prefix >= block.prefix && (self.base & Self::mask(block.prefix)) == block.base
        })
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        }
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = ParseCidrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        // A bare address is treated as a /32 host route, which is what a user
        // typing `--source 198.51.100.7` means.
        let (address, prefix) = match trimmed.split_once('/') {
            Some((address, prefix)) => (
                address,
                prefix
                    .parse::<u8>()
                    .map_err(|_| ParseCidrError::Malformed(trimmed.to_owned()))?,
            ),
            None => (trimmed, 32),
        };

        if prefix > 32 {
            return Err(ParseCidrError::PrefixTooLong(prefix));
        }
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| ParseCidrError::Malformed(trimmed.to_owned()))?;

        let raw = u32::from(address);
        let base = raw & Self::mask(prefix);
        if base != raw {
            return Err(ParseCidrError::HostBitsSet {
                given: trimmed.to_owned(),
                normalised: format!("{}/{prefix}", Ipv4Addr::from(base)),
            });
        }
        Ok(Self { base, prefix })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseCidrError {
    #[error("the address range is empty")]
    Empty,
    #[error("expected an address or CIDR block such as 198.51.100.7/32; got {0}")]
    Malformed(String),
    #[error("an IPv4 prefix length cannot exceed 32; got /{0}")]
    PrefixTooLong(u8),
    #[error("{given} sets bits below its prefix; did you mean {normalised}?")]
    HostBitsSet { given: String, normalised: String },
}

/// The range meaning "every IPv4 address".
pub const ANY_IPV4: &str = "0.0.0.0/0";

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{ANY_IPV4, Cidr, Ipv4Cidr, ParseCidrError};

    #[test]
    fn parses_an_ipv4_block() {
        let cidr: Ipv4Cidr = "10.0.0.0/24".parse().expect("cidr");
        assert_eq!(cidr.prefix, 24);
        assert_eq!(cidr.to_string(), "10.0.0.0/24");
        assert_eq!(cidr.address_count(), 256);
        assert!(cidr.contains("10.0.0.7".parse::<Ipv4Addr>().expect("ip")));
        assert!(!cidr.contains("10.0.1.7".parse::<Ipv4Addr>().expect("ip")));
    }

    /// A user typing a bare address means that one host.
    #[test]
    fn a_bare_address_is_a_host_route() {
        let cidr: Ipv4Cidr = "198.51.100.7".parse().expect("cidr");
        assert_eq!(cidr.prefix, 32);
        assert_eq!(cidr.to_string(), "198.51.100.7/32");
        assert_eq!(cidr.address_count(), 1);
    }

    /// Silently widening `10.0.0.7/24` to `10.0.0.0/24` would open the rule to
    /// 255 addresses the user did not name, so it is refused with the correct
    /// form spelled out.
    #[test]
    fn host_bits_below_the_prefix_are_refused_with_a_suggestion() {
        let error = "10.0.0.7/24".parse::<Ipv4Cidr>().expect_err("must refuse");
        assert_eq!(
            error,
            ParseCidrError::HostBitsSet {
                given: "10.0.0.7/24".to_owned(),
                normalised: "10.0.0.0/24".to_owned(),
            }
        );
        assert!(error.to_string().contains("10.0.0.0/24"));
    }

    #[test]
    fn rejects_malformed_input() {
        for value in ["", "not-an-ip", "10.0.0.0/33", "10.0.0.0/x", "999.1.1.1/32"] {
            assert!(
                value.parse::<Ipv4Cidr>().is_err(),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn recognises_the_whole_internet() {
        let any: Cidr = ANY_IPV4.parse().expect("cidr");
        assert!(any.is_entire_internet());
        assert!(any.is_broad());
        assert!(!any.is_single_host());

        let v6: Cidr = "::/0".parse().expect("cidr");
        assert!(v6.is_entire_internet());
        assert!(v6.is_broad());
    }

    #[test]
    fn recognises_broad_and_narrow_ranges() {
        let broad: Cidr = "10.0.0.0/8".parse().expect("cidr");
        assert!(broad.is_broad());

        let narrow: Cidr = "198.51.100.0/24".parse().expect("cidr");
        assert!(!narrow.is_broad());
        assert!(!narrow.is_single_host());

        let host: Cidr = "198.51.100.7/32".parse().expect("cidr");
        assert!(host.is_single_host());
    }

    /// A rule sourced from private space is not internet-reachable, and the
    /// audit phrases its findings differently as a result.
    #[test]
    fn recognises_private_space() {
        for value in [
            "10.0.0.0/8",
            "10.1.2.0/24",
            "172.16.5.0/24",
            "192.168.1.0/24",
        ] {
            let cidr: Cidr = value.parse().expect("cidr");
            assert!(cidr.is_private(), "{value} is private");
        }
        for value in ["0.0.0.0/0", "198.51.100.0/24", "172.32.0.0/16"] {
            let cidr: Cidr = value.parse().expect("cidr");
            assert!(!cidr.is_private(), "{value} is not private");
        }
    }

    #[test]
    fn parses_ipv6_coarsely() {
        let cidr: Cidr = "2001:db8::/32".parse().expect("cidr");
        assert!(!cidr.is_entire_internet());
        assert!(cidr.is_broad());
        assert_eq!(cidr.to_string(), "2001:db8::/32");
        assert!("2001:db8::".parse::<Cidr>().is_err());
    }
}
