use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::options::{DhcpOption, MessageType, OptionCode};

const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const HTYPE_ETHERNET: u8 = 1;
pub const HLEN_ETHERNET: u8 = 6;

#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<DhcpOption>,
}

impl DhcpPacket {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 240 {
            return Err(Error::InvalidPacket(format!(
                "Packet too short: {} bytes (minimum 240)",
                data.len()
            )));
        }

        let magic_cookie = &data[236..240];
        if magic_cookie != DHCP_MAGIC_COOKIE {
            return Err(Error::InvalidPacket("Invalid magic cookie".to_string()));
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];

        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[28..44]);

        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[44..108]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&data[108..236]);

        let options = Self::parse_options(&data[240..])?;

        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    fn parse_options(data: &[u8]) -> Result<Vec<DhcpOption>> {
        let mut options = Vec::new();
        let mut index = 0;

        while index < data.len() {
            let code = data[index];

            if code == OptionCode::Pad as u8 {
                index += 1;
                continue;
            }

            if code == OptionCode::End as u8 {
                break;
            }

            if index + 1 >= data.len() {
                return Err(Error::InvalidPacket("Option length missing".to_string()));
            }

            let length = data[index + 1] as usize;

            if index + 2 + length > data.len() {
                return Err(Error::InvalidPacket("Option data truncated".to_string()));
            }

            let option_data = &data[index + 2..index + 2 + length];
            let option = DhcpOption::parse(code, option_data)?;
            options.push(option);

            index += 2 + length;
        }

        Ok(options)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(576);

        packet.push(self.op);
        packet.push(self.htype);
        packet.push(self.hlen);
        packet.push(self.hops);

        packet.extend_from_slice(&self.xid.to_be_bytes());
        packet.extend_from_slice(&self.secs.to_be_bytes());
        packet.extend_from_slice(&self.flags.to_be_bytes());

        packet.extend_from_slice(&self.ciaddr.octets());
        packet.extend_from_slice(&self.yiaddr.octets());
        packet.extend_from_slice(&self.siaddr.octets());
        packet.extend_from_slice(&self.giaddr.octets());

        packet.extend_from_slice(&self.chaddr);
        packet.extend_from_slice(&self.sname);
        packet.extend_from_slice(&self.file);

        packet.extend_from_slice(&DHCP_MAGIC_COOKIE);

        for option in &self.options {
            packet.extend_from_slice(&option.encode());
        }

        packet.push(OptionCode::End as u8);

        while packet.len() < 300 {
            packet.push(0);
        }

        packet
    }

    pub fn message_type(&self) -> Option<MessageType> {
        for option in &self.options {
            if let DhcpOption::MessageType(msg_type) = option {
                return Some(*msg_type);
            }
        }
        None
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        for option in &self.options {
            if let DhcpOption::RequestedIpAddress(ip) = option {
                return Some(*ip);
            }
        }
        None
    }

    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        for option in &self.options {
            if let DhcpOption::ServerIdentifier(ip) = option {
                return Some(*ip);
            }
        }
        None
    }

    pub fn client_identifier(&self) -> Option<Vec<u8>> {
        for option in &self.options {
            if let DhcpOption::ClientIdentifier(id) = option {
                return Some(id.clone());
            }
        }
        None
    }

    pub fn mac_address(&self) -> String {
        self.chaddr[..6]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn is_broadcast(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn create_reply(
        request: &DhcpPacket,
        message_type: MessageType,
        your_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Self {
        let mut all_options = vec![DhcpOption::MessageType(message_type)];
        all_options.extend(options);

        Self {
            op: BOOTREPLY,
            htype: HTYPE_ETHERNET,
            hlen: HLEN_ETHERNET,
            hops: 0,
            xid: request.xid,
            secs: 0,
            flags: request.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: your_ip,
            siaddr: server_ip,
            giaddr: request.giaddr,
            chaddr: request.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: all_options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_discover_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[3] = 0;

        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[8..10].copy_from_slice(&0u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());

        packet[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        packet[240] = OptionCode::MessageType as u8;
        packet[241] = 1;
        packet[242] = MessageType::Discover as u8;

        packet[243] = OptionCode::End as u8;

        packet
    }

    #[test]
    fn test_parse_discover_packet() {
        let data = create_test_discover_packet();
        let packet = DhcpPacket::parse(&data).unwrap();

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.htype, HTYPE_ETHERNET);
        assert_eq!(packet.hlen, HLEN_ETHERNET);
        assert_eq!(packet.xid, 0x12345678);
        assert!(packet.is_broadcast());
        assert_eq!(packet.message_type(), Some(MessageType::Discover));
        assert_eq!(packet.mac_address(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_packet_roundtrip() {
        let original_data = create_test_discover_packet();
        let packet = DhcpPacket::parse(&original_data).unwrap();
        let encoded = packet.encode();

        let reparsed = DhcpPacket::parse(&encoded).unwrap();
        assert_eq!(reparsed.op, packet.op);
        assert_eq!(reparsed.xid, packet.xid);
        assert_eq!(reparsed.mac_address(), packet.mac_address());
        assert_eq!(reparsed.message_type(), packet.message_type());
    }

    #[test]
    fn test_create_reply() {
        let discover_data = create_test_discover_packet();
        let discover = DhcpPacket::parse(&discover_data).unwrap();

        let offer = DhcpPacket::create_reply(
            &discover,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            vec![
                DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                DhcpOption::LeaseTime(86400),
            ],
        );

        assert_eq!(offer.op, BOOTREPLY);
        assert_eq!(offer.xid, discover.xid);
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
    }

    #[test]
    fn test_packet_too_short() {
        let data = vec![0u8; 100];
        assert!(DhcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut data = vec![0u8; 300];
        data[236..240].copy_from_slice(&[0, 0, 0, 0]);
        assert!(DhcpPacket::parse(&data).is_err());
    }
}
