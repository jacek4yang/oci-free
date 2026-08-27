use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
        }
    }
}

impl FromStr for Protocol {
    type Err = ParsePortRuleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(ParsePortRuleError::UnsupportedProtocol(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    pub protocol: Protocol,
}

impl fmt::Display for PortRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.port, self.protocol)
    }
}

impl FromStr for PortRule {
    type Err = ParsePortRuleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (port, protocol) = value
            .split_once('/')
            .ok_or_else(|| ParsePortRuleError::InvalidFormat(value.to_owned()))?;

        let port = port
            .parse::<u16>()
            .map_err(|_| ParsePortRuleError::InvalidPort(port.to_owned()))?;
        if port == 0 {
            return Err(ParsePortRuleError::InvalidPort("0".to_owned()));
        }

        Ok(Self {
            port,
            protocol: protocol.parse()?,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParsePortRuleError {
    #[error("expected PORT/PROTOCOL, for example 443/tcp; got {0}")]
    InvalidFormat(String),
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}

#[cfg(test)]
mod tests {
    use super::{PortRule, Protocol};

    #[test]
    fn parses_tcp_rule() {
        let rule: PortRule = "443/tcp".parse().expect("rule should parse");
        assert_eq!(rule.port, 443);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.to_string(), "443/tcp");
    }

    #[test]
    fn rejects_port_zero() {
        assert!("0/tcp".parse::<PortRule>().is_err());
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert!("53/sctp".parse::<PortRule>().is_err());
    }
}
