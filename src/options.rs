//! DHCP options as defined in RFC 2132.
//!
//! DHCP uses options to convey configuration parameters between servers and clients.
//! Each option has a code (1 byte), length (1 byte), and variable-length data.
//!
//! This module implements parsing and encoding for commonly used options.
//! Unknown options are preserved as [`DhcpOption::Unknown`] for forwarding.
//!
//! # References
//!
//! - RFC 2132: DHCP Options and BOOTP Vendor Extensions
//! - RFC 3046: DHCP Relay Agent Information Option (Option 82)

use std::net::Ipv4Addr;

use crate::error::{Error, Result};

/// Maximum number of IP addresses in Router (3) or DNS Server (6) options.
///
/// Options have a 1-byte length field, so maximum data is 255 bytes.
/// With 4 bytes per IPv4 address, that's 63 addresses maximum.
const MAX_ADDRESSES_PER_OPTION: usize = 63;

/// DHCP option codes as defined in RFC 2132.
///
/// Only codes used by this implementation are defined; unknown codes
/// are handled via [`DhcpOption::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OptionCode {
    /// Padding (no operation). Used for alignment.
    Pad = 0,
    /// Subnet mask (RFC 2132 §3.3).
    SubnetMask = 1,
    /// Router/gateway addresses (RFC 2132 §3.5).
    Router = 3,
    /// DNS server addresses (RFC 2132 §3.8).
    DnsServer = 6,
    /// Client hostname (RFC 2132 §3.14).
    Hostname = 12,
    /// Domain name for DNS resolution (RFC 2132 §3.17).
    DomainName = 15,
    /// Interface MTU (RFC 2132 §5.1).
    InterfaceMtu = 26,
    /// Broadcast address (RFC 2132 §5.3).
    BroadcastAddress = 28,
    /// Requested IP address (RFC 2132 §9.1).
    RequestedIpAddress = 50,
    /// IP address lease time in seconds (RFC 2132 §9.2).
    LeaseTime = 51,
    /// Option overload - indicates sname/file fields contain options (RFC 2132 §9.3).
    OptionOverload = 52,
    /// DHCP message type (RFC 2132 §9.6).
    MessageType = 53,
    /// Server identifier (RFC 2132 §9.7).
    ServerIdentifier = 54,
    /// Parameter request list (RFC 2132 §9.8).
    ParameterRequestList = 55,
    /// Renewal time T1 (RFC 2132 §9.11).
    RenewalTime = 58,
    /// Rebinding time T2 (RFC 2132 §9.12).
    RebindingTime = 59,
    /// Client identifier (RFC 2132 §9.14).
    ClientIdentifier = 61,
    /// Relay agent information (RFC 3046).
    RelayAgentInfo = 82,
    /// End of options marker.
    End = 255,
}

impl TryFrom<u8> for OptionCode {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Pad),
            1 => Ok(Self::SubnetMask),
            3 => Ok(Self::Router),
            6 => Ok(Self::DnsServer),
            12 => Ok(Self::Hostname),
            15 => Ok(Self::DomainName),
            26 => Ok(Self::InterfaceMtu),
            28 => Ok(Self::BroadcastAddress),
            50 => Ok(Self::RequestedIpAddress),
            51 => Ok(Self::LeaseTime),
            52 => Ok(Self::OptionOverload),
            53 => Ok(Self::MessageType),
            54 => Ok(Self::ServerIdentifier),
            55 => Ok(Self::ParameterRequestList),
            58 => Ok(Self::RenewalTime),
            59 => Ok(Self::RebindingTime),
            61 => Ok(Self::ClientIdentifier),
            82 => Ok(Self::RelayAgentInfo),
            255 => Ok(Self::End),
            other => Err(other),
        }
    }
}

/// DHCP message types (Option 53) as defined in RFC 2132 §9.6.
///
/// These values indicate the purpose of a DHCP message in the protocol exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Client broadcast to locate servers.
    Discover = 1,
    /// Server response to DISCOVER with IP offer.
    Offer = 2,
    /// Client request for offered parameters.
    Request = 3,
    /// Client indicates address is already in use.
    Decline = 4,
    /// Server acknowledgement with configuration.
    Ack = 5,
    /// Server negative acknowledgement.
    Nak = 6,
    /// Client releases IP address.
    Release = 7,
    /// Client requests config without IP allocation.
    Inform = 8,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            other => Err(other),
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discover => write!(f, "DISCOVER"),
            Self::Offer => write!(f, "OFFER"),
            Self::Request => write!(f, "REQUEST"),
            Self::Decline => write!(f, "DECLINE"),
            Self::Ack => write!(f, "ACK"),
            Self::Nak => write!(f, "NAK"),
            Self::Release => write!(f, "RELEASE"),
            Self::Inform => write!(f, "INFORM"),
        }
    }
}

/// Option overload flags (Option 52) as defined in RFC 2132 §9.3.
///
/// Indicates that the `sname` and/or `file` fields in the DHCP packet
/// header contain DHCP options instead of their normal content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OverloadFlag {
    /// The `file` field contains options.
    File = 1,
    /// The `sname` field contains options.
    Sname = 2,
    /// Both `file` and `sname` fields contain options.
    Both = 3,
}

impl TryFrom<u8> for OverloadFlag {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Sname),
            3 => Ok(Self::Both),
            other => Err(other),
        }
    }
}

/// A parsed DHCP option.
///
/// Each variant corresponds to a specific option code from RFC 2132.
/// Unknown options are preserved as [`Unknown`](Self::Unknown) to allow
/// forwarding in relay scenarios.
#[derive(Debug, Clone)]
pub enum DhcpOption {
    /// Subnet mask (Option 1).
    SubnetMask(Ipv4Addr),
    /// Router/gateway addresses (Option 3). First address is the default gateway.
    Router(Vec<Ipv4Addr>),
    /// DNS server addresses (Option 6).
    DnsServer(Vec<Ipv4Addr>),
    /// Client hostname (Option 12).
    Hostname(String),
    /// Domain name for client DNS resolution (Option 15).
    DomainName(String),
    /// Broadcast address (Option 28).
    BroadcastAddress(Ipv4Addr),
    /// Client's requested IP address (Option 50).
    RequestedIpAddress(Ipv4Addr),
    /// Lease time in seconds (Option 51).
    LeaseTime(u32),
    /// Indicates sname/file fields contain options (Option 52).
    OptionOverload(OverloadFlag),
    /// DHCP message type (Option 53).
    MessageType(MessageType),
    /// Server identifier - IP of the DHCP server (Option 54).
    ServerIdentifier(Ipv4Addr),
    /// List of option codes the client wants (Option 55).
    ParameterRequestList(Vec<u8>),
    /// Renewal time T1 in seconds (Option 58).
    RenewalTime(u32),
    /// Rebinding time T2 in seconds (Option 59).
    RebindingTime(u32),
    /// Client identifier for unique identification (Option 61).
    ClientIdentifier(Vec<u8>),
    /// Relay agent information (Option 82, RFC 3046).
    RelayAgentInfo(Vec<u8>),
    /// Interface MTU (Option 26).
    InterfaceMtu(u16),
    /// Unknown option with raw code and data, preserved for forwarding.
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
    /// Returns the RFC 2132 option code for this option.
    pub fn option_code(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => OptionCode::SubnetMask as u8,
            Self::Router(_) => OptionCode::Router as u8,
            Self::DnsServer(_) => OptionCode::DnsServer as u8,
            Self::Hostname(_) => OptionCode::Hostname as u8,
            Self::DomainName(_) => OptionCode::DomainName as u8,
            Self::BroadcastAddress(_) => OptionCode::BroadcastAddress as u8,
            Self::RequestedIpAddress(_) => OptionCode::RequestedIpAddress as u8,
            Self::LeaseTime(_) => OptionCode::LeaseTime as u8,
            Self::OptionOverload(_) => OptionCode::OptionOverload as u8,
            Self::MessageType(_) => OptionCode::MessageType as u8,
            Self::ServerIdentifier(_) => OptionCode::ServerIdentifier as u8,
            Self::ParameterRequestList(_) => OptionCode::ParameterRequestList as u8,
            Self::RenewalTime(_) => OptionCode::RenewalTime as u8,
            Self::RebindingTime(_) => OptionCode::RebindingTime as u8,
            Self::ClientIdentifier(_) => OptionCode::ClientIdentifier as u8,
            Self::RelayAgentInfo(_) => OptionCode::RelayAgentInfo as u8,
            Self::InterfaceMtu(_) => OptionCode::InterfaceMtu as u8,
            Self::Unknown(code, _) => *code,
        }
    }

    /// Parses a DHCP option from its code and raw data.
    ///
    /// # Arguments
    ///
    /// * `code` - The option code (first byte of TLV)
    /// * `data` - The option data (after code and length bytes)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPacket`] if the data length is invalid for
    /// the option type (e.g., subnet mask must be exactly 4 bytes).
    pub fn parse(code: u8, data: &[u8]) -> Result<Self> {
        match OptionCode::try_from(code) {
            Ok(OptionCode::SubnetMask) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid subnet mask length".to_string(),
                    ));
                }
                Ok(Self::SubnetMask(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            Ok(OptionCode::Router) => {
                if !data.len().is_multiple_of(4) || data.is_empty() {
                    return Err(Error::InvalidPacket(
                        "Invalid router option length".to_string(),
                    ));
                }
                let routers: Vec<Ipv4Addr> = data
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
                Ok(Self::Router(routers))
            }
            Ok(OptionCode::DnsServer) => {
                if !data.len().is_multiple_of(4) || data.is_empty() {
                    return Err(Error::InvalidPacket(
                        "Invalid DNS server option length".to_string(),
                    ));
                }
                let servers: Vec<Ipv4Addr> = data
                    .chunks_exact(4)
                    .map(|chunk| Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]))
                    .collect();
                Ok(Self::DnsServer(servers))
            }
            Ok(OptionCode::Hostname) => {
                let name = String::from_utf8_lossy(data).to_string();
                Ok(Self::Hostname(name))
            }
            Ok(OptionCode::DomainName) => {
                let name = String::from_utf8_lossy(data).to_string();
                Ok(Self::DomainName(name))
            }
            Ok(OptionCode::BroadcastAddress) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid broadcast address length".to_string(),
                    ));
                }
                Ok(Self::BroadcastAddress(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            Ok(OptionCode::RequestedIpAddress) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid requested IP address length".to_string(),
                    ));
                }
                Ok(Self::RequestedIpAddress(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            Ok(OptionCode::LeaseTime) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid lease time length".to_string(),
                    ));
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Self::LeaseTime(time))
            }
            Ok(OptionCode::OptionOverload) => {
                if data.len() != 1 {
                    return Err(Error::InvalidPacket(
                        "Invalid option overload length".to_string(),
                    ));
                }
                let flag = OverloadFlag::try_from(data[0]).map_err(|value| {
                    Error::InvalidPacket(format!("Invalid option overload value: {}", value))
                })?;
                Ok(Self::OptionOverload(flag))
            }
            Ok(OptionCode::MessageType) => {
                if data.len() != 1 {
                    return Err(Error::InvalidPacket(
                        "Invalid message type length".to_string(),
                    ));
                }
                let msg_type = MessageType::try_from(data[0]).map_err(|value| {
                    Error::InvalidPacket(format!("Unknown message type: {}", value))
                })?;
                Ok(Self::MessageType(msg_type))
            }
            Ok(OptionCode::ServerIdentifier) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid server identifier length".to_string(),
                    ));
                }
                Ok(Self::ServerIdentifier(Ipv4Addr::new(
                    data[0], data[1], data[2], data[3],
                )))
            }
            Ok(OptionCode::ParameterRequestList) => Ok(Self::ParameterRequestList(data.to_vec())),
            Ok(OptionCode::RenewalTime) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid renewal time length".to_string(),
                    ));
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Self::RenewalTime(time))
            }
            Ok(OptionCode::RebindingTime) => {
                if data.len() != 4 {
                    return Err(Error::InvalidPacket(
                        "Invalid rebinding time length".to_string(),
                    ));
                }
                let time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Self::RebindingTime(time))
            }
            Ok(OptionCode::ClientIdentifier) => Ok(Self::ClientIdentifier(data.to_vec())),
            Ok(OptionCode::RelayAgentInfo) => Ok(Self::RelayAgentInfo(data.to_vec())),
            Ok(OptionCode::InterfaceMtu) => {
                if data.len() != 2 {
                    return Err(Error::InvalidPacket("Invalid MTU length".to_string()));
                }
                let mtu = u16::from_be_bytes([data[0], data[1]]);
                Ok(Self::InterfaceMtu(mtu))
            }
            Ok(OptionCode::Pad) | Ok(OptionCode::End) => Err(Error::InvalidPacket(
                "Pad/End should not be parsed as options".to_string(),
            )),
            Err(unknown_code) => Ok(Self::Unknown(unknown_code, data.to_vec())),
        }
    }

    /// Encodes the option to its wire format (code + length + data).
    ///
    /// The returned bytes can be directly appended to a DHCP packet's
    /// options section.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::SubnetMask(addr) => {
                let mut result = vec![OptionCode::SubnetMask as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::Router(addrs) => {
                let count = addrs.len().min(MAX_ADDRESSES_PER_OPTION);
                let mut result = vec![OptionCode::Router as u8, (count * 4) as u8];
                for addr in addrs.iter().take(count) {
                    result.extend_from_slice(&addr.octets());
                }
                result
            }
            Self::DnsServer(addrs) => {
                let count = addrs.len().min(MAX_ADDRESSES_PER_OPTION);
                let mut result = vec![OptionCode::DnsServer as u8, (count * 4) as u8];
                for addr in addrs.iter().take(count) {
                    result.extend_from_slice(&addr.octets());
                }
                result
            }
            Self::Hostname(name) => {
                let bytes = name.as_bytes();
                let len = bytes.len().min(255);
                let mut result = vec![OptionCode::Hostname as u8, len as u8];
                result.extend_from_slice(&bytes[..len]);
                result
            }
            Self::DomainName(name) => {
                let bytes = name.as_bytes();
                let len = bytes.len().min(255);
                let mut result = vec![OptionCode::DomainName as u8, len as u8];
                result.extend_from_slice(&bytes[..len]);
                result
            }
            Self::BroadcastAddress(addr) => {
                let mut result = vec![OptionCode::BroadcastAddress as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::RequestedIpAddress(addr) => {
                let mut result = vec![OptionCode::RequestedIpAddress as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::LeaseTime(time) => {
                let mut result = vec![OptionCode::LeaseTime as u8, 4];
                result.extend_from_slice(&time.to_be_bytes());
                result
            }
            Self::OptionOverload(flag) => {
                vec![OptionCode::OptionOverload as u8, 1, *flag as u8]
            }
            Self::MessageType(msg_type) => {
                vec![OptionCode::MessageType as u8, 1, *msg_type as u8]
            }
            Self::ServerIdentifier(addr) => {
                let mut result = vec![OptionCode::ServerIdentifier as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::ParameterRequestList(params) => {
                let len = params.len().min(255);
                let mut result = vec![OptionCode::ParameterRequestList as u8, len as u8];
                result.extend_from_slice(&params[..len]);
                result
            }
            Self::RenewalTime(time) => {
                let mut result = vec![OptionCode::RenewalTime as u8, 4];
                result.extend_from_slice(&time.to_be_bytes());
                result
            }
            Self::RebindingTime(time) => {
                let mut result = vec![OptionCode::RebindingTime as u8, 4];
                result.extend_from_slice(&time.to_be_bytes());
                result
            }
            Self::ClientIdentifier(data) => {
                let len = data.len().min(255);
                let mut result = vec![OptionCode::ClientIdentifier as u8, len as u8];
                result.extend_from_slice(&data[..len]);
                result
            }
            Self::RelayAgentInfo(data) => {
                let len = data.len().min(255);
                let mut result = vec![OptionCode::RelayAgentInfo as u8, len as u8];
                result.extend_from_slice(&data[..len]);
                result
            }
            Self::InterfaceMtu(mtu) => {
                let mut result = vec![OptionCode::InterfaceMtu as u8, 2];
                result.extend_from_slice(&mtu.to_be_bytes());
                result
            }
            Self::Unknown(code, data) => {
                let len = data.len().min(255);
                let mut result = vec![*code, len as u8];
                result.extend_from_slice(&data[..len]);
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversions() {
        for value in 1..=8u8 {
            let msg_type = MessageType::try_from(value).unwrap();
            assert_eq!(msg_type as u8, value);
        }
        assert!(MessageType::try_from(0).is_err());
        assert!(MessageType::try_from(9).is_err());
    }

    #[test]
    fn test_option_encode_decode_roundtrip() {
        let options: Vec<DhcpOption> = vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]),
            DhcpOption::DnsServer(vec![Ipv4Addr::new(8, 8, 8, 8)]),
            DhcpOption::Hostname("test-host".to_string()),
            DhcpOption::DomainName("example.local".to_string()),
            DhcpOption::BroadcastAddress(Ipv4Addr::new(192, 168, 1, 255)),
            DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100)),
            DhcpOption::LeaseTime(86400),
            DhcpOption::MessageType(MessageType::Discover),
            DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)),
            DhcpOption::RenewalTime(43200),
            DhcpOption::RebindingTime(75600),
            DhcpOption::InterfaceMtu(1500),
            DhcpOption::ClientIdentifier(vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15]),
        ];

        for original in options {
            let encoded = original.encode();
            let code = encoded[0];
            let decoded = DhcpOption::parse(code, &encoded[2..]).unwrap();
            assert_eq!(encoded, decoded.encode());
        }
    }

    #[test]
    fn test_option_invalid_lengths() {
        assert!(DhcpOption::parse(1, &[255, 255, 255]).is_err());
        assert!(DhcpOption::parse(3, &[]).is_err());
        assert!(DhcpOption::parse(51, &[0, 0, 0]).is_err());
    }

    #[test]
    fn test_unknown_option() {
        let decoded = DhcpOption::parse(100, &[1, 2, 3, 4]).unwrap();
        if let DhcpOption::Unknown(code, data) = decoded {
            assert_eq!(code, 100);
            assert_eq!(data, vec![1, 2, 3, 4]);
        } else {
            panic!("Expected Unknown");
        }
    }

    #[test]
    fn test_dns_server_empty_data_rejected() {
        let result = DhcpOption::parse(OptionCode::DnsServer as u8, &[]);
        assert!(result.is_err(), "Empty DNS server list should be rejected");
    }

    #[test]
    fn test_router_empty_data_rejected() {
        let result = DhcpOption::parse(OptionCode::Router as u8, &[]);
        assert!(result.is_err(), "Empty router list should be rejected");
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", MessageType::Discover), "DISCOVER");
        assert_eq!(format!("{}", MessageType::Offer), "OFFER");
        assert_eq!(format!("{}", MessageType::Request), "REQUEST");
        assert_eq!(format!("{}", MessageType::Decline), "DECLINE");
        assert_eq!(format!("{}", MessageType::Ack), "ACK");
        assert_eq!(format!("{}", MessageType::Nak), "NAK");
        assert_eq!(format!("{}", MessageType::Release), "RELEASE");
        assert_eq!(format!("{}", MessageType::Inform), "INFORM");
    }
}
