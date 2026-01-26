use std::net::Ipv4Addr;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OptionCode {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    DomainName = 15,
    BroadcastAddress = 28,
    RequestedIpAddress = 50,
    LeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    RenewalTime = 58,
    RebindingTime = 59,
    ClientIdentifier = 61,
    InterfaceMtu = 26,
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
            15 => Ok(Self::DomainName),
            26 => Ok(Self::InterfaceMtu),
            28 => Ok(Self::BroadcastAddress),
            50 => Ok(Self::RequestedIpAddress),
            51 => Ok(Self::LeaseTime),
            53 => Ok(Self::MessageType),
            54 => Ok(Self::ServerIdentifier),
            55 => Ok(Self::ParameterRequestList),
            58 => Ok(Self::RenewalTime),
            59 => Ok(Self::RebindingTime),
            61 => Ok(Self::ClientIdentifier),
            255 => Ok(Self::End),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
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

#[derive(Debug, Clone)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    DomainName(String),
    BroadcastAddress(Ipv4Addr),
    RequestedIpAddress(Ipv4Addr),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(Vec<u8>),
    RenewalTime(u32),
    RebindingTime(u32),
    ClientIdentifier(Vec<u8>),
    InterfaceMtu(u16),
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
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
                if data.len() % 4 != 0 || data.is_empty() {
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
                if data.len() % 4 != 0 || data.is_empty() {
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

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::SubnetMask(addr) => {
                let mut result = vec![OptionCode::SubnetMask as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::Router(addrs) => {
                let mut result = vec![OptionCode::Router as u8, (addrs.len() * 4) as u8];
                for addr in addrs {
                    result.extend_from_slice(&addr.octets());
                }
                result
            }
            Self::DnsServer(addrs) => {
                let mut result = vec![OptionCode::DnsServer as u8, (addrs.len() * 4) as u8];
                for addr in addrs {
                    result.extend_from_slice(&addr.octets());
                }
                result
            }
            Self::DomainName(name) => {
                let bytes = name.as_bytes();
                let mut result = vec![OptionCode::DomainName as u8, bytes.len() as u8];
                result.extend_from_slice(bytes);
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
            Self::MessageType(msg_type) => {
                vec![OptionCode::MessageType as u8, 1, *msg_type as u8]
            }
            Self::ServerIdentifier(addr) => {
                let mut result = vec![OptionCode::ServerIdentifier as u8, 4];
                result.extend_from_slice(&addr.octets());
                result
            }
            Self::ParameterRequestList(params) => {
                let mut result = vec![OptionCode::ParameterRequestList as u8, params.len() as u8];
                result.extend_from_slice(params);
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
                let mut result = vec![OptionCode::ClientIdentifier as u8, data.len() as u8];
                result.extend_from_slice(data);
                result
            }
            Self::InterfaceMtu(mtu) => {
                let mut result = vec![OptionCode::InterfaceMtu as u8, 2];
                result.extend_from_slice(&mtu.to_be_bytes());
                result
            }
            Self::Unknown(code, data) => {
                let mut result = vec![*code, data.len() as u8];
                result.extend_from_slice(data);
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        for value in 1..=8u8 {
            let msg_type = MessageType::try_from(value).unwrap();
            assert_eq!(msg_type as u8, value);
        }
    }

    #[test]
    fn test_option_encode_decode() {
        let original = DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0));
        let encoded = original.encode();
        assert_eq!(encoded, vec![1, 4, 255, 255, 255, 0]);

        let decoded = DhcpOption::parse(1, &[255, 255, 255, 0]).unwrap();
        if let DhcpOption::SubnetMask(addr) = decoded {
            assert_eq!(addr, Ipv4Addr::new(255, 255, 255, 0));
        } else {
            panic!("Expected SubnetMask");
        }
    }

    #[test]
    fn test_lease_time_encoding() {
        let option = DhcpOption::LeaseTime(86400);
        let encoded = option.encode();
        assert_eq!(encoded.len(), 6);
        assert_eq!(encoded[0], 51);
        assert_eq!(encoded[1], 4);

        let decoded = DhcpOption::parse(51, &encoded[2..]).unwrap();
        if let DhcpOption::LeaseTime(time) = decoded {
            assert_eq!(time, 86400);
        } else {
            panic!("Expected LeaseTime");
        }
    }
}
