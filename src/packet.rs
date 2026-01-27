use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::options::{DhcpOption, MessageType, OptionCode, OverloadFlag};

const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_OP_HTYPE_HLEN_HOPS_SIZE: usize = 4;
const DHCP_XID_SIZE: usize = 4;
const DHCP_SECS_SIZE: usize = 2;
const DHCP_FLAGS_SIZE: usize = 2;
const DHCP_CIADDR_SIZE: usize = 4;
const DHCP_YIADDR_SIZE: usize = 4;
const DHCP_SIADDR_SIZE: usize = 4;
const DHCP_GIADDR_SIZE: usize = 4;
const DHCP_CHADDR_SIZE: usize = 16;
const DHCP_SNAME_SIZE: usize = 64;
const DHCP_FILE_SIZE: usize = 128;

const DHCP_MAGIC_COOKIE_OFFSET: usize = DHCP_OP_HTYPE_HLEN_HOPS_SIZE
    + DHCP_XID_SIZE
    + DHCP_SECS_SIZE
    + DHCP_FLAGS_SIZE
    + DHCP_CIADDR_SIZE
    + DHCP_YIADDR_SIZE
    + DHCP_SIADDR_SIZE
    + DHCP_GIADDR_SIZE
    + DHCP_CHADDR_SIZE
    + DHCP_SNAME_SIZE
    + DHCP_FILE_SIZE;

const DHCP_SNAME_OFFSET: usize = DHCP_OP_HTYPE_HLEN_HOPS_SIZE
    + DHCP_XID_SIZE
    + DHCP_SECS_SIZE
    + DHCP_FLAGS_SIZE
    + DHCP_CIADDR_SIZE
    + DHCP_YIADDR_SIZE
    + DHCP_SIADDR_SIZE
    + DHCP_GIADDR_SIZE
    + DHCP_CHADDR_SIZE;

const DHCP_FILE_OFFSET: usize = DHCP_SNAME_OFFSET + DHCP_SNAME_SIZE;

const DHCP_FIXED_HEADER_SIZE: usize = DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE.len();
const DHCP_MIN_PACKET_SIZE: usize = 300;
const DHCP_ENCODE_CAPACITY: usize = 576;
const MAX_HOPS: u8 = 16;

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
        if data.len() < DHCP_FIXED_HEADER_SIZE {
            return Err(Error::InvalidPacket(format!(
                "Packet too short: {} bytes (minimum {})",
                data.len(),
                DHCP_FIXED_HEADER_SIZE
            )));
        }

        let magic_cookie_end = DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE.len();
        let magic_cookie = &data[DHCP_MAGIC_COOKIE_OFFSET..magic_cookie_end];
        if magic_cookie != DHCP_MAGIC_COOKIE {
            return Err(Error::InvalidPacket("Invalid magic cookie".to_string()));
        }

        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];

        if hops > MAX_HOPS {
            return Err(Error::InvalidPacket(format!(
                "Hop count {} exceeds maximum {}",
                hops, MAX_HOPS
            )));
        }

        if htype == HTYPE_ETHERNET && hlen != HLEN_ETHERNET {
            return Err(Error::InvalidPacket(format!(
                "Invalid hlen {} for Ethernet (expected {})",
                hlen, HLEN_ETHERNET
            )));
        }

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
        sname.copy_from_slice(&data[DHCP_SNAME_OFFSET..DHCP_SNAME_OFFSET + DHCP_SNAME_SIZE]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&data[DHCP_FILE_OFFSET..DHCP_FILE_OFFSET + DHCP_FILE_SIZE]);

        let mut options = Self::parse_options(&data[DHCP_FIXED_HEADER_SIZE..])?;

        let overload = options.iter().find_map(|opt| {
            if let DhcpOption::OptionOverload(flag) = opt {
                Some(*flag)
            } else {
                None
            }
        });

        if let Some(flag) = overload {
            if matches!(flag, OverloadFlag::File | OverloadFlag::Both) {
                let file_options = Self::parse_options(&file)?;
                options.extend(file_options);
            }
            if matches!(flag, OverloadFlag::Sname | OverloadFlag::Both) {
                let sname_options = Self::parse_options(&sname)?;
                options.extend(sname_options);
            }
        }

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
        let mut packet = Vec::with_capacity(DHCP_ENCODE_CAPACITY);

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

        while packet.len() < DHCP_MIN_PACKET_SIZE {
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

    pub fn client_identifier(&self) -> Option<&[u8]> {
        for option in &self.options {
            if let DhcpOption::ClientIdentifier(id) = option {
                return Some(id);
            }
        }
        None
    }

    pub fn relay_agent_info(&self) -> Option<&[u8]> {
        for option in &self.options {
            if let DhcpOption::RelayAgentInfo(info) = option {
                return Some(info);
            }
        }
        None
    }

    pub fn hostname(&self) -> Option<&str> {
        for option in &self.options {
            if let DhcpOption::Hostname(name) = option {
                return Some(name);
            }
        }
        None
    }

    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        for option in &self.options {
            if let DhcpOption::ParameterRequestList(params) = option {
                return Some(params);
            }
        }
        None
    }

    pub fn requested_lease_time(&self) -> Option<u32> {
        for option in &self.options {
            if let DhcpOption::LeaseTime(time) = option {
                return Some(*time);
            }
        }
        None
    }

    pub fn chaddr_bytes(&self) -> &[u8] {
        &self.chaddr[..self.hlen as usize]
    }

    pub fn format_mac(&self) -> String {
        let len = (self.hlen as usize).min(self.chaddr.len());
        self.chaddr[..len]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn client_id(&self) -> Vec<u8> {
        if let Some(id) = self.client_identifier() {
            id.to_vec()
        } else {
            let mut id = vec![self.htype];
            id.extend_from_slice(self.chaddr_bytes());
            id
        }
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
            htype: request.htype,
            hlen: request.hlen,
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

    pub fn create_bootp_reply(
        request: &DhcpPacket,
        your_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Self {
        Self {
            op: BOOTREPLY,
            htype: request.htype,
            hlen: request.hlen,
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
            options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet(message_type: MessageType, with_options: bool) -> Vec<u8> {
        let mut packet = vec![0u8; 350];

        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let mut index = 240;
        packet[index] = OptionCode::MessageType as u8;
        packet[index + 1] = 1;
        packet[index + 2] = message_type as u8;
        index += 3;

        if with_options {
            packet[index] = OptionCode::RequestedIpAddress as u8;
            packet[index + 1] = 4;
            packet[index + 2..index + 6].copy_from_slice(&[192, 168, 1, 100]);
            index += 6;

            packet[index] = OptionCode::Hostname as u8;
            packet[index + 1] = 9;
            packet[index + 2..index + 11].copy_from_slice(b"test-host");
            index += 11;
        }

        packet[index] = OptionCode::End as u8;
        packet
    }

    #[test]
    fn test_parse_and_roundtrip() {
        let data = create_test_packet(MessageType::Discover, false);
        let packet = DhcpPacket::parse(&data).unwrap();

        assert_eq!(packet.op, BOOTREQUEST);
        assert_eq!(packet.xid, 0x12345678);
        assert!(packet.is_broadcast());
        assert_eq!(packet.message_type(), Some(MessageType::Discover));
        assert_eq!(packet.format_mac(), "aa:bb:cc:dd:ee:ff");

        let encoded = packet.encode();
        let reparsed = DhcpPacket::parse(&encoded).unwrap();
        assert_eq!(reparsed.xid, packet.xid);
        assert_eq!(reparsed.message_type(), packet.message_type());
    }

    #[test]
    fn test_parse_with_options() {
        let data = create_test_packet(MessageType::Request, true);
        let packet = DhcpPacket::parse(&data).unwrap();

        assert_eq!(packet.requested_ip(), Some(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(packet.hostname(), Some("test-host"));
    }

    #[test]
    fn test_create_reply() {
        let discover_data = create_test_packet(MessageType::Discover, false);
        let discover = DhcpPacket::parse(&discover_data).unwrap();

        let offer = DhcpPacket::create_reply(
            &discover,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            vec![DhcpOption::LeaseTime(86400)],
        );

        assert_eq!(offer.op, BOOTREPLY);
        assert_eq!(offer.xid, discover.xid);
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(offer.chaddr, discover.chaddr);
    }

    #[test]
    fn test_invalid_packets() {
        assert!(DhcpPacket::parse(&[0u8; 100]).is_err());
        assert!(DhcpPacket::parse(&[0u8; 239]).is_err());

        let mut bad_cookie = [0u8; 300];
        bad_cookie[236..240].copy_from_slice(&[0, 0, 0, 0]);
        assert!(DhcpPacket::parse(&bad_cookie).is_err());
    }

    #[test]
    fn test_hlen_validation() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        packet[1] = HTYPE_ETHERNET;
        packet[2] = 7;
        assert!(DhcpPacket::parse(&packet).is_err());

        packet[2] = HLEN_ETHERNET;
        assert!(DhcpPacket::parse(&packet).is_ok());
    }

    #[test]
    fn test_hops_limit() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        packet[3] = 17;
        assert!(DhcpPacket::parse(&packet).is_err());

        packet[3] = 16;
        assert!(DhcpPacket::parse(&packet).is_ok());
    }

    #[test]
    fn test_create_reply_copies_htype() {
        let mut packet_data = create_test_packet(MessageType::Discover, false);
        packet_data[1] = 6;
        packet_data[2] = 8;

        let request = DhcpPacket::parse(&packet_data).unwrap();
        let reply = DhcpPacket::create_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            vec![],
        );

        assert_eq!(reply.htype, 6);
        assert_eq!(reply.hlen, 8);
    }

    #[test]
    fn test_client_id_with_option() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        let mut index = 243;
        packet[index] = OptionCode::ClientIdentifier as u8;
        packet[index + 1] = 7;
        packet[index + 2..index + 9].copy_from_slice(&[1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        index += 9;
        packet[index] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed.client_id(),
            vec![1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    #[test]
    fn test_client_id_from_chaddr() {
        let packet = create_test_packet(MessageType::Discover, false);
        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed.client_id(),
            vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn test_option_overload_file() {
        let mut packet = create_test_packet(MessageType::Discover, false);

        let mut index = 243;
        packet[index] = OptionCode::OptionOverload as u8;
        packet[index + 1] = 1;
        packet[index + 2] = 1;
        index += 3;
        packet[index] = OptionCode::End as u8;

        packet[108] = OptionCode::Hostname as u8;
        packet[109] = 8;
        packet[110..118].copy_from_slice(b"filehost");
        packet[118] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.hostname(), Some("filehost"));
    }

    #[test]
    fn test_option_overload_sname() {
        let mut packet = create_test_packet(MessageType::Discover, false);

        let mut index = 243;
        packet[index] = OptionCode::OptionOverload as u8;
        packet[index + 1] = 1;
        packet[index + 2] = 2;
        index += 3;
        packet[index] = OptionCode::End as u8;

        packet[44] = OptionCode::Hostname as u8;
        packet[45] = 9;
        packet[46..55].copy_from_slice(b"snamehost");
        packet[55] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.hostname(), Some("snamehost"));
    }

    #[test]
    fn test_option_overload_both() {
        let mut packet = create_test_packet(MessageType::Discover, false);

        let mut index = 243;
        packet[index] = OptionCode::OptionOverload as u8;
        packet[index + 1] = 1;
        packet[index + 2] = 3;
        index += 3;
        packet[index] = OptionCode::End as u8;

        packet[44] = OptionCode::Hostname as u8;
        packet[45] = 5;
        packet[46..51].copy_from_slice(b"sname");
        packet[51] = OptionCode::End as u8;

        packet[108] = OptionCode::DomainName as u8;
        packet[109] = 10;
        packet[110..120].copy_from_slice(b"file.local");
        packet[120] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.hostname(), Some("sname"));

        let has_domain = parsed
            .options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::DomainName(name) if name == "file.local"));
        assert!(has_domain);
    }

    #[test]
    fn test_chaddr_bytes_respects_hlen() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        packet[1] = 6;
        packet[2] = 4;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.chaddr_bytes().len(), 4);
        assert_eq!(parsed.chaddr_bytes(), &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_relay_agent_info_parsing() {
        let mut packet = create_test_packet(MessageType::Discover, false);

        let mut index = 243;
        packet[index] = OptionCode::RelayAgentInfo as u8;
        packet[index + 1] = 5;
        packet[index + 2..index + 7].copy_from_slice(&[1, 2, 3, 4, 5]);
        index += 7;
        packet[index] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.relay_agent_info(), Some(&[1u8, 2, 3, 4, 5][..]));
    }

    #[test]
    fn test_server_identifier_parsing() {
        let mut packet = create_test_packet(MessageType::Request, false);

        let mut index = 243;
        packet[index] = OptionCode::ServerIdentifier as u8;
        packet[index + 1] = 4;
        packet[index + 2..index + 6].copy_from_slice(&[192, 168, 1, 1]);
        index += 6;
        packet[index] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(
            parsed.server_identifier(),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn test_unicast_flag() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        packet[10..12].copy_from_slice(&0x0000u16.to_be_bytes());

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert!(!parsed.is_broadcast());
    }

    #[test]
    fn test_giaddr_preserved_in_reply() {
        let mut packet_data = create_test_packet(MessageType::Discover, false);
        let giaddr = Ipv4Addr::new(192, 168, 2, 1);
        packet_data[24..28].copy_from_slice(&giaddr.octets());

        let request = DhcpPacket::parse(&packet_data).unwrap();
        let reply = DhcpPacket::create_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            vec![],
        );

        assert_eq!(reply.giaddr, giaddr);
    }

    #[test]
    fn test_min_packet_size_on_encode() {
        let packet = DhcpPacket {
            op: BOOTREPLY,
            htype: HTYPE_ETHERNET,
            hlen: HLEN_ETHERNET,
            hops: 0,
            xid: 0x12345678,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::new(192, 168, 1, 100),
            siaddr: Ipv4Addr::new(192, 168, 1, 1),
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: vec![DhcpOption::MessageType(MessageType::Offer)],
        };

        let encoded = packet.encode();
        assert!(encoded.len() >= DHCP_MIN_PACKET_SIZE);
    }

    #[test]
    fn test_flags_preserved_in_reply() {
        let mut packet_data = create_test_packet(MessageType::Discover, false);
        packet_data[10..12].copy_from_slice(&0x8000u16.to_be_bytes());

        let request = DhcpPacket::parse(&packet_data).unwrap();
        let reply = DhcpPacket::create_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            vec![],
        );

        assert_eq!(reply.flags, 0x8000);
        assert!(reply.is_broadcast());
    }

    #[test]
    fn test_create_bootp_reply() {
        let request_data = create_test_packet(MessageType::Discover, false);
        let request = DhcpPacket::parse(&request_data).unwrap();

        let options = vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]),
        ];

        let reply = DhcpPacket::create_bootp_reply(
            &request,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            options,
        );

        assert_eq!(reply.op, BOOTREPLY);
        assert_eq!(reply.xid, request.xid);
        assert_eq!(reply.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(reply.siaddr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(reply.chaddr, request.chaddr);
        assert_eq!(reply.htype, request.htype);
        assert_eq!(reply.hlen, request.hlen);

        assert!(reply.message_type().is_none());

        assert!(
            reply
                .options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::SubnetMask(_)))
        );
        assert!(
            reply
                .options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::Router(_)))
        );
    }
}
