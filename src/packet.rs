//! DHCP packet parsing and encoding per RFC 2131.
//!
//! A DHCP packet consists of a fixed 236-byte header followed by a 4-byte
//! magic cookie and variable-length options. This module handles parsing
//! incoming packets and constructing replies.
//!
//! # Packet Structure
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
//! +---------------+---------------+---------------+---------------+
//! |                            xid (4)                            |
//! +-------------------------------+-------------------------------+
//! |           secs (2)            |           flags (2)           |
//! +-------------------------------+-------------------------------+
//! |                          ciaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          yiaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          siaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          giaddr (4)                           |
//! +---------------------------------------------------------------+
//! |                          chaddr (16)                          |
//! +---------------------------------------------------------------+
//! |                          sname (64)                           |
//! +---------------------------------------------------------------+
//! |                          file (128)                           |
//! +---------------------------------------------------------------+
//! |                    magic cookie (4) = 99.130.83.99            |
//! +---------------------------------------------------------------+
//! |                          options (variable)                   |
//! +---------------------------------------------------------------+
//! ```
//!
//! # References
//!
//! - RFC 2131: Dynamic Host Configuration Protocol

use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::options::{DhcpOption, MessageType, OptionCode, OverloadFlag};

/// DHCP magic cookie that identifies DHCP packets (vs BOOTP).
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

/// Size of the fixed header portion including magic cookie.
const DHCP_FIXED_HEADER_SIZE: usize = DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE.len();

/// Minimum DHCP packet size per RFC 2131 §2.
///
/// DHCP requires packets to be at least 300 bytes for compatibility
/// with BOOTP relay agents.
const DHCP_MIN_PACKET_SIZE: usize = 300;

/// Initial capacity for packet encoding buffer.
///
/// 576 bytes is the minimum MTU that all hosts must accept per RFC 791.
const DHCP_ENCODE_CAPACITY: usize = 576;

/// Maximum hop count before dropping the packet.
///
/// Prevents infinite relay loops. Per RFC 2131 §4.1, relay agents
/// increment hops and should discard packets with excessive counts.
const MAX_HOPS: u8 = 16;

/// BOOTP/DHCP operation code for client requests.
pub const BOOTREQUEST: u8 = 1;

/// BOOTP/DHCP operation code for server replies.
pub const BOOTREPLY: u8 = 2;

/// Hardware type for Ethernet (most common).
pub const HTYPE_ETHERNET: u8 = 1;

/// Hardware address length for Ethernet (6 bytes).
pub const HLEN_ETHERNET: u8 = 6;

/// A parsed DHCP packet.
///
/// This struct represents both client requests and server replies.
/// Use [`parse`](Self::parse) to parse incoming packets and
/// [`create_reply`](Self::create_reply) to construct responses.
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    /// Operation code: [`BOOTREQUEST`] (1) or [`BOOTREPLY`] (2).
    pub op: u8,

    /// Hardware address type. [`HTYPE_ETHERNET`] (1) for Ethernet.
    pub htype: u8,

    /// Hardware address length. [`HLEN_ETHERNET`] (6) for Ethernet.
    pub hlen: u8,

    /// Hop count, incremented by relay agents.
    pub hops: u8,

    /// Transaction ID chosen by client, echoed in replies.
    pub xid: u32,

    /// Seconds elapsed since client began address acquisition.
    pub secs: u16,

    /// Flags. Bit 15 (0x8000) = broadcast flag.
    pub flags: u16,

    /// Client IP address (set by client in RENEWING/REBINDING states).
    pub ciaddr: Ipv4Addr,

    /// "Your" IP address - the address being assigned to the client.
    pub yiaddr: Ipv4Addr,

    /// Server IP address (next server in BOOTP, or DHCP server).
    pub siaddr: Ipv4Addr,

    /// Gateway IP address - set by relay agents.
    pub giaddr: Ipv4Addr,

    /// Client hardware address (MAC for Ethernet).
    pub chaddr: [u8; 16],

    /// Server host name (or option overflow area if Option 52 is set).
    pub sname: [u8; 64],

    /// Boot file name (or option overflow area if Option 52 is set).
    pub file: [u8; 128],

    /// DHCP options parsed from the packet.
    pub options: Vec<DhcpOption>,
}

impl DhcpPacket {
    /// Parses a DHCP packet from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet bytes received from the network
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPacket`] if:
    /// - Packet is shorter than 240 bytes (fixed header + magic cookie)
    /// - Magic cookie is invalid (not 99.130.83.99)
    /// - Hop count exceeds 16 (relay loop protection)
    /// - Hardware length doesn't match type (e.g., Ethernet must be 6)
    /// - Options are malformed (truncated length or data)
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

    /// Encodes the packet to bytes for transmission.
    ///
    /// The returned buffer is at least 300 bytes (padded per RFC 2131).
    /// Options are encoded in TLV format with an End marker.
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

    /// Returns the DHCP message type (Option 53) if present.
    ///
    /// Returns `None` for BOOTP packets which don't have this option.
    pub fn message_type(&self) -> Option<MessageType> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::MessageType(t) => Some(*t),
            _ => None,
        })
    }

    /// Returns the requested IP address (Option 50) if present.
    ///
    /// Clients include this in DISCOVER to request a specific IP,
    /// and in REQUEST to confirm the offered IP.
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::RequestedIpAddress(ip) => Some(*ip),
            _ => None,
        })
    }

    /// Returns the server identifier (Option 54) if present.
    ///
    /// Clients include this in REQUEST to indicate which server's
    /// offer they are accepting.
    pub fn server_identifier(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::ServerIdentifier(ip) => Some(*ip),
            _ => None,
        })
    }

    /// Returns the client identifier (Option 61) if present.
    ///
    /// This option allows clients to identify themselves with a value
    /// other than their hardware address.
    pub fn client_identifier(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::ClientIdentifier(id) => Some(id.as_slice()),
            _ => None,
        })
    }

    /// Returns the relay agent information (Option 82) if present.
    ///
    /// This is added by DHCP relay agents and must be echoed in replies.
    pub fn relay_agent_info(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::RelayAgentInfo(info) => Some(info.as_slice()),
            _ => None,
        })
    }

    /// Returns the client hostname (Option 12) if present.
    pub fn hostname(&self) -> Option<&str> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::Hostname(name) => Some(name.as_str()),
            _ => None,
        })
    }

    /// Returns the parameter request list (Option 55) if present.
    ///
    /// This is a list of option codes the client wants in the response.
    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::ParameterRequestList(params) => Some(params.as_slice()),
            _ => None,
        })
    }

    /// Returns the requested lease time (Option 51) if present.
    ///
    /// Clients may request a specific lease duration. The server may
    /// honor this request or provide a different duration.
    pub fn requested_lease_time(&self) -> Option<u32> {
        self.options.iter().find_map(|opt| match opt {
            DhcpOption::LeaseTime(time) => Some(*time),
            _ => None,
        })
    }

    /// Returns the client hardware address bytes (respecting hlen).
    pub fn chaddr_bytes(&self) -> &[u8] {
        &self.chaddr[..self.hlen as usize]
    }

    /// Formats the client hardware address as a colon-separated string.
    ///
    /// For Ethernet, returns format like "aa:bb:cc:dd:ee:ff".
    pub fn format_mac(&self) -> String {
        use std::fmt::Write;
        let len = (self.hlen as usize).min(self.chaddr.len());
        let mut result = String::with_capacity(len * 3);
        for (index, byte) in self.chaddr[..len].iter().enumerate() {
            if index > 0 {
                result.push(':');
            }
            let _ = write!(result, "{:02x}", byte);
        }
        result
    }

    /// Returns a unique client identifier for lease tracking.
    ///
    /// Uses Option 61 (Client Identifier) if present, otherwise
    /// constructs an identifier from hardware type + hardware address.
    pub fn client_id(&self) -> Vec<u8> {
        if let Some(id) = self.client_identifier() {
            id.to_vec()
        } else {
            let mut id = vec![self.htype];
            id.extend_from_slice(self.chaddr_bytes());
            id
        }
    }

    /// Returns true if the broadcast flag (bit 15) is set.
    ///
    /// When set, servers must broadcast replies instead of unicasting.
    pub fn is_broadcast(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    /// Creates a DHCP reply packet from a request.
    ///
    /// This handles OFFER, ACK, and NAK responses. The message type is
    /// automatically added as the first option.
    ///
    /// # Arguments
    ///
    /// * `request` - The client's request packet
    /// * `message_type` - Type of reply (Offer, Ack, Nak)
    /// * `your_ip` - IP address being assigned (yiaddr)
    /// * `server_ip` - This server's IP (siaddr)
    /// * `options` - Additional options to include
    ///
    /// # Preserved Fields
    ///
    /// The following fields are copied from the request:
    /// - `xid` (transaction ID)
    /// - `flags` (broadcast flag)
    /// - `giaddr` (relay agent address)
    /// - `chaddr` (client hardware address)
    /// - `htype` and `hlen` (hardware type/length)
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

    /// Creates a BOOTP reply packet (no message type option).
    ///
    /// Used for legacy BOOTP clients that don't send a message type.
    /// The response includes options but not the Message Type option.
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

    #[test]
    fn test_minimum_valid_packet() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.op, BOOTREQUEST);
        assert!(parsed.options.is_empty());
    }

    #[test]
    fn test_packet_with_only_end_option() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 1];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert!(parsed.options.is_empty());
    }

    #[test]
    fn test_packet_with_pad_options() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 15];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240..248].fill(OptionCode::Pad as u8);
        packet[248] = OptionCode::MessageType as u8;
        packet[249] = 1;
        packet[250] = MessageType::Discover as u8;
        packet[251] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn test_option_with_zero_length() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 10];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::ParameterRequestList as u8;
        packet[241] = 0;
        packet[242] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        let prl = parsed.parameter_request_list();
        assert_eq!(prl, Some(&[][..]));
    }

    #[test]
    fn test_option_with_max_length() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 260];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::ParameterRequestList as u8;
        packet[241] = 255;
        for index in 0..255 {
            packet[242 + index] = index as u8;
        }
        packet[497] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        let prl = parsed.parameter_request_list().unwrap();
        assert_eq!(prl.len(), 255);
    }

    #[test]
    fn test_hostname_max_length_truncation() {
        let long_hostname = "a".repeat(300);
        let option = DhcpOption::Hostname(long_hostname);
        let encoded = option.encode();
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded.len(), 257);
    }

    #[test]
    fn test_duplicate_message_type_options() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 10];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::MessageType as u8;
        packet[241] = 1;
        packet[242] = MessageType::Discover as u8;
        packet[243] = OptionCode::MessageType as u8;
        packet[244] = 1;
        packet[245] = MessageType::Request as u8;
        packet[246] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.message_type(), Some(MessageType::Discover));
        assert_eq!(parsed.options.len(), 2);
    }

    #[test]
    fn test_truncated_option_length() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 2];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::LeaseTime as u8;

        let result = DhcpPacket::parse(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_option_data() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 4];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::LeaseTime as u8;
        packet[241] = 4;
        packet[242] = 0;
        packet[243] = 0;

        let result = DhcpPacket::parse(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_option_preserved() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 10];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = 200;
        packet[241] = 4;
        packet[242..246].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        packet[246] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert!(parsed.options.iter().any(
            |opt| matches!(opt, DhcpOption::Unknown(200, data) if data == &[0xDE, 0xAD, 0xBE, 0xEF])
        ));
    }

    #[test]
    fn test_all_zero_chaddr() {
        let mut packet = create_test_packet(MessageType::Discover, false);
        packet[28..44].copy_from_slice(&[0u8; 16]);

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.format_mac(), "00:00:00:00:00:00");
    }

    #[test]
    fn test_packet_field_offsets_correct() {
        let mut packet = vec![0u8; DHCP_FIXED_HEADER_SIZE + 5];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[3] = 5;
        packet[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        packet[8..10].copy_from_slice(&1234u16.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..24].copy_from_slice(&[10, 0, 0, 3]);
        packet[24..28].copy_from_slice(&[10, 0, 0, 4]);
        packet[28..34].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        packet[44..52].copy_from_slice(b"testname");
        packet[108..116].copy_from_slice(b"bootfile");
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet[240] = OptionCode::End as u8;

        let parsed = DhcpPacket::parse(&packet).unwrap();
        assert_eq!(parsed.op, BOOTREQUEST);
        assert_eq!(parsed.htype, HTYPE_ETHERNET);
        assert_eq!(parsed.hlen, HLEN_ETHERNET);
        assert_eq!(parsed.hops, 5);
        assert_eq!(parsed.xid, 0xDEADBEEF);
        assert_eq!(parsed.secs, 1234);
        assert_eq!(parsed.flags, 0x8000);
        assert_eq!(parsed.ciaddr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.yiaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.siaddr, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(parsed.giaddr, Ipv4Addr::new(10, 0, 0, 4));
        assert_eq!(&parsed.chaddr[..6], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_encode_produces_correct_offsets() {
        let packet = DhcpPacket {
            op: BOOTREPLY,
            htype: HTYPE_ETHERNET,
            hlen: HLEN_ETHERNET,
            hops: 3,
            xid: 0x12345678,
            secs: 999,
            flags: 0x8000,
            ciaddr: Ipv4Addr::new(192, 168, 1, 10),
            yiaddr: Ipv4Addr::new(192, 168, 1, 20),
            siaddr: Ipv4Addr::new(192, 168, 1, 1),
            giaddr: Ipv4Addr::new(192, 168, 2, 1),
            chaddr: [
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![DhcpOption::MessageType(MessageType::Offer)],
        };

        let encoded = packet.encode();

        assert_eq!(encoded[0], BOOTREPLY);
        assert_eq!(encoded[1], HTYPE_ETHERNET);
        assert_eq!(encoded[2], HLEN_ETHERNET);
        assert_eq!(encoded[3], 3);
        assert_eq!(&encoded[4..8], &0x12345678u32.to_be_bytes());
        assert_eq!(&encoded[8..10], &999u16.to_be_bytes());
        assert_eq!(&encoded[10..12], &0x8000u16.to_be_bytes());
        assert_eq!(&encoded[12..16], &[192, 168, 1, 10]);
        assert_eq!(&encoded[16..20], &[192, 168, 1, 20]);
        assert_eq!(&encoded[20..24], &[192, 168, 1, 1]);
        assert_eq!(&encoded[24..28], &[192, 168, 2, 1]);
        assert_eq!(&encoded[28..34], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(&encoded[236..240], &DHCP_MAGIC_COOKIE);
    }
}
