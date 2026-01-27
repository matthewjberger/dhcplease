use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::{Config, sanitize_hostname};
use crate::error::{Error, Result};
use crate::lease::Leases;
use crate::options::{DhcpOption, MessageType};
use crate::packet::{BOOTREQUEST, DhcpPacket};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const RATE_LIMIT_WINDOW_SECS: u64 = 1;
const RATE_LIMIT_MAX_REQUESTS: usize = 10;
const RATE_LIMIT_CLEANUP_THRESHOLD: usize = 1000;
const RECV_BUFFER_SIZE: usize = 1500;

pub struct DhcpServer {
    config: Arc<Config>,
    leases: Arc<Leases>,
    socket: Arc<UdpSocket>,
    rate_limiter: Arc<Mutex<HashMap<[u8; 6], Vec<Instant>>>>,
}

impl DhcpServer {
    pub async fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let leases = Arc::new(Leases::new(Arc::clone(&config)).await?);

        let socket = Arc::new(Self::create_socket(&config)?);

        info!(
            "DHCP server starting on {}:{}",
            config.server_ip, DHCP_SERVER_PORT
        );
        info!(
            "IP pool: {} - {} ({} addresses)",
            config.pool_start,
            config.pool_end,
            config.pool_size()
        );

        Ok(Self {
            config,
            leases,
            socket,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn create_socket(config: &Config) -> Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|error| Error::Socket(format!("Failed to create socket: {}", error)))?;

        socket
            .set_reuse_address(true)
            .map_err(|error| Error::Socket(format!("Failed to set SO_REUSEADDR: {}", error)))?;

        socket
            .set_broadcast(true)
            .map_err(|error| Error::Socket(format!("Failed to set SO_BROADCAST: {}", error)))?;

        socket
            .set_nonblocking(true)
            .map_err(|error| Error::Socket(format!("Failed to set non-blocking: {}", error)))?;

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_SERVER_PORT);
        socket.bind(&bind_addr.into()).map_err(|error| {
            Error::Socket(format!("Failed to bind to {}: {}", bind_addr, error))
        })?;

        if let Some(interface_index) = config.interface_index {
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawSocket;
                let raw_socket = socket.as_raw_socket();

                let result = set_interface_index(raw_socket, interface_index);
                if let Err(error) = result {
                    warn!(
                        "Failed to set interface index {}: {}",
                        interface_index, error
                    );
                }
            }
            #[cfg(not(windows))]
            {
                warn!(
                    "interface_index ({}) is only supported on Windows and will be ignored",
                    interface_index
                );
            }
        }

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(|error| {
            Error::Socket(format!("Failed to convert to tokio socket: {}", error))
        })?;

        Ok(tokio_socket)
    }

    pub async fn run(&self) -> Result<()> {
        let mut buffer = [0u8; RECV_BUFFER_SIZE];

        info!("DHCP server ready and listening");

        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, source)) => {
                    let data = buffer[..size].to_vec();
                    let config = Arc::clone(&self.config);
                    let leases = Arc::clone(&self.leases);
                    let socket = Arc::clone(&self.socket);
                    let rate_limiter = Arc::clone(&self.rate_limiter);

                    tokio::spawn(async move {
                        let handler = PacketHandler {
                            config,
                            leases,
                            socket,
                            rate_limiter,
                        };
                        if let Err(error) = handler.handle_packet(&data, source).await {
                            warn!("Error handling packet from {}: {}", source, error);
                        }
                    });
                }
                Err(error) => {
                    error!("Error receiving packet: {}", error);
                }
            }
        }
    }

    pub async fn save_leases(&self) -> Result<()> {
        self.leases.save().await
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn leases(&self) -> &Leases {
        &self.leases
    }
}

struct PacketHandler {
    config: Arc<Config>,
    leases: Arc<Leases>,
    socket: Arc<UdpSocket>,
    rate_limiter: Arc<Mutex<HashMap<[u8; 6], Vec<Instant>>>>,
}

impl PacketHandler {
    async fn is_rate_limited(&self, mac: [u8; 6]) -> bool {
        let mut limiter = self.rate_limiter.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        if limiter.len() > RATE_LIMIT_CLEANUP_THRESHOLD {
            limiter.retain(|_, timestamps| {
                timestamps.retain(|t| now.duration_since(*t) < window);
                !timestamps.is_empty()
            });
        }

        let timestamps = limiter.entry(mac).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= RATE_LIMIT_MAX_REQUESTS {
            return true;
        }

        timestamps.push(now);
        false
    }

    async fn handle_packet(&self, data: &[u8], source: SocketAddr) -> Result<()> {
        let packet = DhcpPacket::parse(data)?;

        if packet.op != BOOTREQUEST {
            return Err(Error::InvalidPacket("Expected BOOTREQUEST".to_string()));
        }

        let mac_bytes: [u8; 6] = packet.chaddr[..6].try_into().unwrap_or([0; 6]);
        let mac = packet.format_mac();

        if self.is_rate_limited(mac_bytes).await {
            warn!("Rate limited: {} from {}", mac, source);
            return Ok(());
        }

        match packet.message_type() {
            Some(message_type) => {
                info!("{} from {} ({})", message_type, mac, source);

                match message_type {
                    MessageType::Discover => self.handle_discover(&packet).await,
                    MessageType::Request => self.handle_request(&packet).await,
                    MessageType::Release => self.handle_release(&packet).await,
                    MessageType::Decline => self.handle_decline(&packet).await,
                    MessageType::Inform => self.handle_inform(&packet).await,
                    _ => {
                        warn!("Ignoring {} message", message_type);
                        Ok(())
                    }
                }
            }
            None => {
                info!("BOOTP from {} ({})", mac, source);
                self.handle_bootp(&packet).await
            }
        }
    }

    async fn handle_bootp(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        let assigned_ip = if packet.ciaddr != Ipv4Addr::UNSPECIFIED {
            packet.ciaddr
        } else {
            match self.leases.allocate_ip(&client_id).await {
                Ok(ip) => ip,
                Err(Error::PoolExhausted) => {
                    warn!("Pool exhausted, cannot assign IP to BOOTP client {}", mac);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        };

        let hostname = packet.hostname().map(crate::config::sanitize_hostname);
        self.leases
            .create_lease(&client_id, assigned_ip, hostname, Some(u32::MAX))
            .await?;

        let mut options = Vec::new();
        options.push(DhcpOption::SubnetMask(self.config.subnet_mask));
        if let Some(gateway) = self.config.gateway {
            options.push(DhcpOption::Router(vec![gateway]));
        }
        if !self.config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(self.config.dns_servers.clone()));
        }

        let reply =
            DhcpPacket::create_bootp_reply(packet, assigned_ip, self.config.server_ip, options);

        self.send_reply(&reply, packet).await?;

        info!("BOOTP reply {} to {}", assigned_ip, mac);

        Ok(())
    }

    async fn handle_discover(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        let offered_ip = match packet.requested_ip() {
            Some(requested_ip)
                if self.config.ip_in_pool(requested_ip)
                    && self.leases.is_ip_available(requested_ip, &client_id).await =>
            {
                self.leases
                    .track_pending_offer(&client_id, requested_ip)
                    .await;
                requested_ip
            }
            _ => match self.leases.allocate_ip(&client_id).await {
                Ok(ip) => ip,
                Err(Error::PoolExhausted) => {
                    warn!("Pool exhausted, cannot offer IP to {}", mac);
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
        };

        let options = self.build_offer_options();
        let mut options = self.filter_options_by_prl(options, packet.parameter_request_list());
        if let Some(relay_info) = packet.relay_agent_info() {
            options.push(DhcpOption::RelayAgentInfo(relay_info.to_vec()));
        }

        let offer = DhcpPacket::create_reply(
            packet,
            MessageType::Offer,
            offered_ip,
            self.config.server_ip,
            options,
        );

        self.send_reply(&offer, packet).await?;

        info!("OFFER {} to {}", offered_ip, mac);

        Ok(())
    }

    async fn handle_request(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        if let Some(server_id) = packet.server_identifier()
            && server_id != self.config.server_ip
        {
            info!("REQUEST from {} is for different server {}", mac, server_id);
            return Ok(());
        }

        let requested_ip = packet
            .requested_ip()
            .or(if packet.ciaddr != Ipv4Addr::UNSPECIFIED {
                Some(packet.ciaddr)
            } else {
                None
            })
            .ok_or_else(|| Error::InvalidPacket("No IP address in REQUEST".to_string()))?;

        if !self.config.ip_in_pool(requested_ip)
            && !self.is_static_binding(&client_id, requested_ip)
        {
            return self.send_nak(packet, "Requested IP not in pool").await;
        }

        let lease_duration = self.negotiate_lease_time(packet);

        let existing_lease = self.leases.get_lease(&client_id).await;
        let is_renewal = existing_lease
            .as_ref()
            .is_some_and(|lease| lease.ip_address == requested_ip && !lease.is_expired());

        let hostname = packet.hostname().map(sanitize_hostname);
        let lease = if is_renewal {
            match self.leases.renew_lease(&client_id, Some(lease_duration)).await {
                Ok(lease) => lease,
                Err(Error::LeaseNotFound(_)) => {
                    match self
                        .leases
                        .create_lease(&client_id, requested_ip, hostname, Some(lease_duration))
                        .await
                    {
                        Ok(lease) => lease,
                        Err(Error::InvalidPacket(msg)) => {
                            return self.send_nak(packet, &msg).await;
                        }
                        Err(Error::AddressOutOfRange(_)) => {
                            return self.send_nak(packet, "Requested IP not in pool").await;
                        }
                        Err(Error::PoolExhausted) => {
                            return self.send_nak(packet, "Address pool exhausted").await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        } else {
            match self
                .leases
                .create_lease(&client_id, requested_ip, hostname, Some(lease_duration))
                .await
            {
                Ok(lease) => lease,
                Err(Error::InvalidPacket(msg)) => {
                    return self.send_nak(packet, &msg).await;
                }
                Err(Error::AddressOutOfRange(_)) => {
                    return self.send_nak(packet, "Requested IP not in pool").await;
                }
                Err(Error::PoolExhausted) => {
                    return self.send_nak(packet, "Address pool exhausted").await;
                }
                Err(error) => return Err(error),
            }
        };

        let options = self.build_offer_options();
        let mut options = self.filter_options_by_prl(options, packet.parameter_request_list());
        if let Some(relay_info) = packet.relay_agent_info() {
            options.push(DhcpOption::RelayAgentInfo(relay_info.to_vec()));
        }

        let ack = DhcpPacket::create_reply(
            packet,
            MessageType::Ack,
            requested_ip,
            self.config.server_ip,
            options,
        );

        self.send_reply(&ack, packet).await?;

        info!(
            "ACK {} to {} (lease: {} seconds)",
            requested_ip,
            mac,
            lease.remaining_seconds()
        );

        Ok(())
    }

    fn is_static_binding(&self, client_id: &[u8], ip: Ipv4Addr) -> bool {
        self.leases.is_static_binding(client_id, ip)
    }

    fn negotiate_lease_time(&self, packet: &DhcpPacket) -> u32 {
        const MIN_LEASE_SECONDS: u32 = 60;
        let max_lease = self.config.lease_duration_seconds;
        match packet.requested_lease_time() {
            Some(requested) => requested.clamp(MIN_LEASE_SECONDS, max_lease),
            None => max_lease,
        }
    }

    async fn handle_release(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        if packet.ciaddr == Ipv4Addr::UNSPECIFIED {
            warn!("RELEASE from {} with no ciaddr", mac);
            return Ok(());
        }

        self.leases.release_lease(&client_id, packet.ciaddr).await?;

        info!("RELEASE from {} for {}", mac, packet.ciaddr);

        Ok(())
    }

    async fn handle_decline(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        if let Some(declined_ip) = packet.requested_ip() {
            let accepted = self.leases.decline_ip(declined_ip, &client_id).await?;

            if accepted {
                warn!(
                    "DECLINE from {} for {} - marked IP as unavailable",
                    mac, declined_ip
                );
            } else {
                warn!(
                    "DECLINE from {} for {} rejected - IP not associated with this client",
                    mac, declined_ip
                );
            }
        }

        Ok(())
    }

    async fn handle_inform(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();

        let options = self.build_inform_options();
        let mut options = self.filter_options_by_prl(options, packet.parameter_request_list());
        if let Some(relay_info) = packet.relay_agent_info() {
            options.push(DhcpOption::RelayAgentInfo(relay_info.to_vec()));
        }

        let ack = DhcpPacket::create_reply(
            packet,
            MessageType::Ack,
            packet.ciaddr,
            self.config.server_ip,
            options,
        );

        self.send_reply(&ack, packet).await?;

        info!("INFORM response to {}", mac);

        Ok(())
    }

    async fn send_nak(&self, packet: &DhcpPacket, reason: &str) -> Result<()> {
        let mac = packet.format_mac();

        let mut options = vec![DhcpOption::ServerIdentifier(self.config.server_ip)];
        if let Some(relay_info) = packet.relay_agent_info() {
            options.push(DhcpOption::RelayAgentInfo(relay_info.to_vec()));
        }

        let nak = DhcpPacket::create_reply(
            packet,
            MessageType::Nak,
            Ipv4Addr::UNSPECIFIED,
            self.config.server_ip,
            options,
        );

        self.send_reply(&nak, packet).await?;

        warn!("NAK to {}: {}", mac, reason);

        Ok(())
    }

    async fn send_reply(&self, reply: &DhcpPacket, request: &DhcpPacket) -> Result<()> {
        let encoded = reply.encode();

        let is_nak = reply.message_type() == Some(MessageType::Nak);

        let destination = if request.giaddr != Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(std::net::IpAddr::V4(request.giaddr), DHCP_SERVER_PORT)
        } else if is_nak || request.is_broadcast() || request.ciaddr == Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_CLIENT_PORT)
        } else {
            SocketAddr::new(std::net::IpAddr::V4(request.ciaddr), DHCP_CLIENT_PORT)
        };

        self.socket.send_to(&encoded, destination).await?;

        Ok(())
    }

    fn build_common_options(&self, options: &mut Vec<DhcpOption>) {
        options.push(DhcpOption::SubnetMask(self.config.subnet_mask));

        if let Some(gateway) = self.config.gateway {
            options.push(DhcpOption::Router(vec![gateway]));
        }

        if !self.config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(self.config.dns_servers.clone()));
        }

        if let Some(ref domain) = self.config.domain_name {
            options.push(DhcpOption::DomainName(domain.clone()));
        }
    }

    fn build_offer_options(&self) -> Vec<DhcpOption> {
        let mut options = vec![
            DhcpOption::ServerIdentifier(self.config.server_ip),
            DhcpOption::LeaseTime(self.config.lease_duration_seconds),
        ];

        self.build_common_options(&mut options);

        options.push(DhcpOption::BroadcastAddress(
            self.config.calculate_broadcast(),
        ));

        if let Some(renewal) = self.config.renewal_time_seconds {
            options.push(DhcpOption::RenewalTime(renewal));
        } else {
            options.push(DhcpOption::RenewalTime(
                self.config.lease_duration_seconds / 2,
            ));
        }

        if let Some(rebinding) = self.config.rebinding_time_seconds {
            options.push(DhcpOption::RebindingTime(rebinding));
        } else {
            options.push(DhcpOption::RebindingTime(
                (self.config.lease_duration_seconds * 7) / 8,
            ));
        }

        if let Some(mtu) = self.config.mtu {
            options.push(DhcpOption::InterfaceMtu(mtu));
        }

        options
    }

    fn build_inform_options(&self) -> Vec<DhcpOption> {
        let mut options = vec![DhcpOption::ServerIdentifier(self.config.server_ip)];

        self.build_common_options(&mut options);

        options
    }

    fn filter_options_by_prl(
        &self,
        options: Vec<DhcpOption>,
        parameter_request_list: Option<&[u8]>,
    ) -> Vec<DhcpOption> {
        let Some(prl) = parameter_request_list else {
            return options;
        };

        options
            .into_iter()
            .filter(|opt| {
                let code = opt.option_code();
                matches!(code, 53 | 54 | 51 | 58 | 59) || prl.contains(&code)
            })
            .collect()
    }
}

#[cfg(windows)]
fn set_interface_index(raw_socket: std::os::windows::io::RawSocket, index: u32) -> Result<()> {
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_IP, SOCKET, setsockopt};

    const IP_UNICAST_IF: i32 = 31;

    let index_bytes = index.to_be_bytes();
    let result = unsafe {
        setsockopt(
            raw_socket as SOCKET,
            IPPROTO_IP,
            IP_UNICAST_IF,
            index_bytes.as_ptr(),
            std::mem::size_of::<u32>() as i32,
        )
    };

    if result != 0 {
        return Err(Error::Socket(format!(
            "setsockopt IP_UNICAST_IF failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticBinding;
    use crate::options::OptionCode;
    use crate::packet::{BOOTREQUEST, DhcpPacket, HLEN_ETHERNET, HTYPE_ETHERNET};
    use std::net::SocketAddr;

    const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

    #[test]
    fn test_constants() {
        assert_eq!(DHCP_SERVER_PORT, 67);
        assert_eq!(DHCP_CLIENT_PORT, 68);
        assert_eq!(RECV_BUFFER_SIZE, 1500);
        assert_eq!(RATE_LIMIT_MAX_REQUESTS, 10);
        assert_eq!(RATE_LIMIT_WINDOW_SECS, 1);
    }

    fn test_config() -> Config {
        Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain_name: Some("test.local".to_string()),
            lease_duration_seconds: 3600,
            renewal_time_seconds: Some(1800),
            rebinding_time_seconds: Some(3150),
            broadcast_address: None,
            mtu: Some(1500),
            static_bindings: vec![],
            leases_file: "test_server_leases.json".to_string(),
            interface_index: None,
        }
    }

    fn test_config_with_path(name: &str) -> (Config, TestGuard) {
        let path = format!("test_server_{}.json", name);
        (
            Config {
                leases_file: path.clone(),
                ..test_config()
            },
            TestGuard(path),
        )
    }

    struct TestGuard(String);
    impl Drop for TestGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn create_dhcp_packet(
        message_type: MessageType,
        mac: [u8; 6],
        xid: u32,
        options: Vec<DhcpOption>,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 300];

        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = HLEN_ETHERNET;
        packet[3] = 0;
        packet[4..8].copy_from_slice(&xid.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[28..34].copy_from_slice(&mac);
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        let mut index = 240;
        packet[index] = OptionCode::MessageType as u8;
        packet[index + 1] = 1;
        packet[index + 2] = message_type as u8;
        index += 3;

        for option in options {
            let encoded = option.encode();
            packet[index..index + encoded.len()].copy_from_slice(&encoded);
            index += encoded.len();
        }

        packet[index] = OptionCode::End as u8;
        packet
    }

    fn create_packet_with_ciaddr(
        message_type: MessageType,
        mac: [u8; 6],
        xid: u32,
        ciaddr: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Vec<u8> {
        let mut packet = create_dhcp_packet(message_type, mac, xid, options);
        packet[12..16].copy_from_slice(&ciaddr.octets());
        packet
    }

    fn create_packet_with_giaddr(
        message_type: MessageType,
        mac: [u8; 6],
        xid: u32,
        giaddr: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Vec<u8> {
        let mut packet = create_dhcp_packet(message_type, mac, xid, options);
        packet[24..28].copy_from_slice(&giaddr.octets());
        packet
    }

    fn create_unicast_packet(
        message_type: MessageType,
        mac: [u8; 6],
        xid: u32,
        ciaddr: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Vec<u8> {
        let mut packet = create_packet_with_ciaddr(message_type, mac, xid, ciaddr, options);
        packet[10..12].copy_from_slice(&0x0000u16.to_be_bytes());
        packet
    }

    async fn create_test_handler(name: &str) -> (PacketHandler, TestGuard, Arc<UdpSocket>) {
        let (config, guard) = test_config_with_path(name);
        let config = Arc::new(config);
        let leases = Arc::new(Leases::new(Arc::clone(&config)).await.unwrap());

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(socket);

        let handler = PacketHandler {
            config,
            leases,
            socket: Arc::clone(&socket),
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        };

        (handler, guard, socket)
    }

    fn is_network_error(err: &Error) -> bool {
        matches!(err, Error::Io(_))
    }

    #[test]
    fn test_renewal_time_calculations() {
        let config_default = Config {
            lease_duration_seconds: 3600,
            renewal_time_seconds: None,
            rebinding_time_seconds: None,
            ..test_config()
        };

        let expected_renewal = config_default.lease_duration_seconds / 2;
        let expected_rebinding = (config_default.lease_duration_seconds * 7) / 8;

        assert_eq!(expected_renewal, 1800);
        assert_eq!(expected_rebinding, 3150);

        let config_explicit = Config {
            renewal_time_seconds: Some(1000),
            rebinding_time_seconds: Some(2000),
            ..test_config()
        };

        assert_eq!(config_explicit.renewal_time_seconds, Some(1000));
        assert_eq!(config_explicit.rebinding_time_seconds, Some(2000));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let (handler, _guard, _socket) = create_test_handler("rate_limit").await;

        let mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        for _ in 0..RATE_LIMIT_MAX_REQUESTS {
            assert!(!handler.is_rate_limited(mac).await);
        }

        assert!(handler.is_rate_limited(mac).await);

        let other_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert!(!handler.is_rate_limited(other_mac).await);
    }

    #[tokio::test]
    async fn test_rate_limit_cleanup() {
        let (handler, _guard, _socket) = create_test_handler("rate_cleanup").await;

        let total_macs = RATE_LIMIT_CLEANUP_THRESHOLD + 10;
        for index in 0..total_macs {
            let mac: [u8; 6] = [
                0xaa,
                0xbb,
                0xcc,
                0xdd,
                (index / 256) as u8,
                (index % 256) as u8,
            ];
            handler.is_rate_limited(mac).await;
        }

        let limiter = handler.rate_limiter.lock().await;
        assert_eq!(limiter.len(), total_macs);
    }

    #[tokio::test]
    async fn test_handle_discover_allocates_ip() {
        let (handler, _guard, _socket) = create_test_handler("discover").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let packet_data = create_dhcp_packet(MessageType::Discover, mac, 0x12345678, vec![]);
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_discover(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));

        let client_id = packet.client_id();
        let allocated = handler.leases.allocate_ip(&client_id).await.unwrap();
        assert!(handler.config.ip_in_pool(allocated));
    }

    #[tokio::test]
    async fn test_handle_discover_with_requested_ip() {
        let (handler, _guard, _socket) = create_test_handler("discover_req").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
        let requested_ip = Ipv4Addr::new(192, 168, 1, 150);
        let packet_data = create_dhcp_packet(
            MessageType::Discover,
            mac,
            0x12345678,
            vec![DhcpOption::RequestedIpAddress(requested_ip)],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_discover(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));

        let client_id = packet.client_id();
        let allocated = handler.leases.allocate_ip(&client_id).await.unwrap();
        assert_eq!(allocated, requested_ip);
    }

    #[tokio::test]
    async fn test_handle_request_creates_lease() {
        let (handler, _guard, _socket) = create_test_handler("request").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];
        let client_id = {
            let mut id = vec![HTYPE_ETHERNET];
            id.extend_from_slice(&mac);
            id
        };

        let ip = handler.leases.allocate_ip(&client_id).await.unwrap();

        let packet_data = create_dhcp_packet(
            MessageType::Request,
            mac,
            0x12345678,
            vec![
                DhcpOption::RequestedIpAddress(ip),
                DhcpOption::ServerIdentifier(handler.config.server_ip),
            ],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_request(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));

        let lease = handler.leases.get_lease(&client_id).await;
        assert!(lease.is_some());
        assert_eq!(lease.unwrap().ip_address, ip);
    }

    #[tokio::test]
    async fn test_handle_request_with_ciaddr() {
        let (handler, _guard, _socket) = create_test_handler("request_ciaddr").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04];
        let client_id = {
            let mut id = vec![HTYPE_ETHERNET];
            id.extend_from_slice(&mac);
            id
        };

        let ip = handler.leases.allocate_ip(&client_id).await.unwrap();
        handler
            .leases
            .create_lease(&client_id, ip, None, None)
            .await
            .unwrap();

        let packet_data = create_unicast_packet(MessageType::Request, mac, 0x12345678, ip, vec![]);
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_request(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));
    }

    #[tokio::test]
    async fn test_handle_request_different_server() {
        let (handler, _guard, _socket) = create_test_handler("request_other").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05];
        let other_server = Ipv4Addr::new(192, 168, 1, 2);

        let packet_data = create_dhcp_packet(
            MessageType::Request,
            mac,
            0x12345678,
            vec![
                DhcpOption::RequestedIpAddress(Ipv4Addr::new(192, 168, 1, 100)),
                DhcpOption::ServerIdentifier(other_server),
            ],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_request(&packet).await;
        assert!(result.is_ok());

        let client_id = packet.client_id();
        let lease = handler.leases.get_lease(&client_id).await;
        assert!(lease.is_none());
    }

    #[tokio::test]
    async fn test_handle_request_ip_not_in_pool() {
        let (handler, _guard, _socket) = create_test_handler("request_bad_ip").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x06];
        let bad_ip = Ipv4Addr::new(10, 0, 0, 1);

        let packet_data = create_dhcp_packet(
            MessageType::Request,
            mac,
            0x12345678,
            vec![
                DhcpOption::RequestedIpAddress(bad_ip),
                DhcpOption::ServerIdentifier(handler.config.server_ip),
            ],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_request(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));
    }

    #[tokio::test]
    async fn test_handle_release() {
        let (handler, _guard, _socket) = create_test_handler("release").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x07];
        let client_id = {
            let mut id = vec![HTYPE_ETHERNET];
            id.extend_from_slice(&mac);
            id
        };

        let ip = handler.leases.allocate_ip(&client_id).await.unwrap();
        handler
            .leases
            .create_lease(&client_id, ip, None, None)
            .await
            .unwrap();

        let packet_data = create_packet_with_ciaddr(
            MessageType::Release,
            mac,
            0x12345678,
            ip,
            vec![DhcpOption::ServerIdentifier(handler.config.server_ip)],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_release(&packet).await;
        assert!(result.is_ok());

        let lease = handler.leases.get_lease(&client_id).await;
        assert!(lease.is_none());
    }

    #[tokio::test]
    async fn test_handle_release_no_ciaddr() {
        let (handler, _guard, _socket) = create_test_handler("release_no_ci").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x08];
        let packet_data = create_dhcp_packet(MessageType::Release, mac, 0x12345678, vec![]);
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_release(&packet).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_decline() {
        let (handler, _guard, _socket) = create_test_handler("decline").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x09];
        let client_id = {
            let mut id = vec![HTYPE_ETHERNET];
            id.extend_from_slice(&mac);
            id
        };

        let ip = handler.leases.allocate_ip(&client_id).await.unwrap();
        handler
            .leases
            .create_lease(&client_id, ip, None, None)
            .await
            .unwrap();

        let packet_data = create_dhcp_packet(
            MessageType::Decline,
            mac,
            0x12345678,
            vec![DhcpOption::RequestedIpAddress(ip)],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_decline(&packet).await;
        assert!(result.is_ok());

        assert!(!handler.leases.is_ip_available(ip, &client_id).await);
    }

    #[tokio::test]
    async fn test_handle_inform() {
        let (handler, _guard, _socket) = create_test_handler("inform").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0a];
        let ciaddr = Ipv4Addr::new(192, 168, 1, 50);

        let packet_data =
            create_packet_with_ciaddr(MessageType::Inform, mac, 0x12345678, ciaddr, vec![]);
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_inform(&packet).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));
    }

    #[tokio::test]
    async fn test_relay_agent_info_echoed_in_options() {
        let (handler, _guard, _socket) = create_test_handler("relay_echo").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0b];
        let relay_info = vec![1, 2, 3, 4, 5];

        let packet_data = create_dhcp_packet(
            MessageType::Discover,
            mac,
            0x12345678,
            vec![DhcpOption::RelayAgentInfo(relay_info.clone())],
        );
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        assert_eq!(packet.relay_agent_info(), Some(relay_info.as_slice()));

        let mut options = handler.build_offer_options();
        if let Some(info) = packet.relay_agent_info() {
            options.push(DhcpOption::RelayAgentInfo(info.to_vec()));
        }

        let has_relay_info = options
            .iter()
            .any(|opt| matches!(opt, DhcpOption::RelayAgentInfo(data) if *data == relay_info));
        assert!(has_relay_info);
    }

    #[tokio::test]
    async fn test_reply_destination_broadcast() {
        let (handler, _guard, _socket) = create_test_handler("reply_bcast").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0c];
        let request_data = create_dhcp_packet(MessageType::Discover, mac, 0x12345678, vec![]);
        let request = DhcpPacket::parse(&request_data).unwrap();

        assert!(request.is_broadcast());
        assert_eq!(request.giaddr, Ipv4Addr::UNSPECIFIED);

        let reply = DhcpPacket::create_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            handler.config.server_ip,
            vec![],
        );

        assert!(reply.is_broadcast());
        assert_eq!(reply.giaddr, Ipv4Addr::UNSPECIFIED);
    }

    #[tokio::test]
    async fn test_reply_destination_relay() {
        let (handler, _guard, _socket) = create_test_handler("reply_relay").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0d];
        let giaddr = Ipv4Addr::new(192, 168, 2, 1);
        let request_data =
            create_packet_with_giaddr(MessageType::Discover, mac, 0x12345678, giaddr, vec![]);
        let request = DhcpPacket::parse(&request_data).unwrap();

        assert_eq!(request.giaddr, giaddr);

        let reply = DhcpPacket::create_reply(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(192, 168, 1, 100),
            handler.config.server_ip,
            vec![],
        );

        assert_eq!(reply.giaddr, giaddr);
    }

    #[tokio::test]
    async fn test_full_dora_flow() {
        let (handler, _guard, _socket) = create_test_handler("dora").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0e];
        let xid = 0xDEADBEEF;

        let discover_data = create_dhcp_packet(MessageType::Discover, mac, xid, vec![]);
        let discover = DhcpPacket::parse(&discover_data).unwrap();
        let _ = handler.handle_discover(&discover).await;

        let client_id = discover.client_id();

        let offered_ip = handler.leases.allocate_ip(&client_id).await.unwrap();

        let request_data = create_dhcp_packet(
            MessageType::Request,
            mac,
            xid,
            vec![
                DhcpOption::RequestedIpAddress(offered_ip),
                DhcpOption::ServerIdentifier(handler.config.server_ip),
            ],
        );
        let request = DhcpPacket::parse(&request_data).unwrap();
        let _ = handler.handle_request(&request).await;

        let lease = handler.leases.get_lease(&client_id).await.unwrap();
        assert_eq!(lease.ip_address, offered_ip);
        assert!(lease.remaining_seconds() > 3500);
    }

    #[tokio::test]
    async fn test_renewal_flow() {
        let (handler, _guard, _socket) = create_test_handler("renewal").await;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f];
        let client_id = {
            let mut id = vec![HTYPE_ETHERNET];
            id.extend_from_slice(&mac);
            id
        };

        let ip = handler.leases.allocate_ip(&client_id).await.unwrap();
        handler
            .leases
            .create_lease(&client_id, ip, None, None)
            .await
            .unwrap();

        let request_data = create_unicast_packet(MessageType::Request, mac, 0x12345678, ip, vec![]);
        let request = DhcpPacket::parse(&request_data).unwrap();

        let _ = handler.handle_request(&request).await;

        let lease = handler.leases.get_lease(&client_id).await.unwrap();
        assert_eq!(lease.ip_address, ip);
    }

    #[tokio::test]
    async fn test_static_binding_check() {
        let path = "test_server_static_bind.json".to_string();
        let _guard = TestGuard(path.clone());

        let config = Config {
            static_bindings: vec![StaticBinding {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ip_address: Ipv4Addr::new(192, 168, 1, 50),
                hostname: None,
            }],
            leases_file: path,
            ..test_config()
        };

        let config = Arc::new(config);
        let leases = Arc::new(Leases::new(Arc::clone(&config)).await.unwrap());
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let handler = PacketHandler {
            config,
            leases,
            socket,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        };

        let client_id = vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let static_ip = Ipv4Addr::new(192, 168, 1, 50);

        assert!(handler.is_static_binding(&client_id, static_ip));
        assert!(!handler.is_static_binding(&client_id, Ipv4Addr::new(192, 168, 1, 51)));

        let other_client = vec![1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert!(!handler.is_static_binding(&other_client, static_ip));
    }

    #[tokio::test]
    async fn test_handle_packet_rejects_bootreply() {
        let (handler, _guard, _socket) = create_test_handler("bootreply").await;

        let mut packet_data = create_dhcp_packet(
            MessageType::Discover,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10],
            0x12345678,
            vec![],
        );
        packet_data[0] = 2;

        let source: SocketAddr = "127.0.0.1:68".parse().unwrap();
        let result = handler.handle_packet(&packet_data, source).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_bootp_packet() {
        let (handler, _guard, _socket) = create_test_handler("bootp").await;

        let mut packet_data = vec![0u8; 300];
        packet_data[0] = BOOTREQUEST;
        packet_data[1] = HTYPE_ETHERNET;
        packet_data[2] = HLEN_ETHERNET;
        packet_data[28..34].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11]);
        packet_data[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        packet_data[240] = OptionCode::End as u8;

        let source: SocketAddr = "127.0.0.1:68".parse().unwrap();
        let result = handler.handle_packet(&packet_data, source).await;
        assert!(result.is_ok() || result.as_ref().err().map(is_network_error).unwrap_or(false));

        let client_id = vec![HTYPE_ETHERNET, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11];
        let lease = handler.leases.get_lease(&client_id).await;
        assert!(lease.is_some());
    }

    #[tokio::test]
    async fn test_build_offer_options() {
        let (handler, _guard, _socket) = create_test_handler("offer_opts").await;

        let options = handler.build_offer_options();

        assert!(options.iter().any(|opt| matches!(
            opt,
            DhcpOption::ServerIdentifier(ip) if *ip == handler.config.server_ip
        )));
        assert!(options.iter().any(|opt| matches!(
            opt,
            DhcpOption::LeaseTime(t) if *t == handler.config.lease_duration_seconds
        )));
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::SubnetMask(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::Router(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::DnsServer(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::RenewalTime(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::RebindingTime(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::InterfaceMtu(1500)))
        );
    }

    #[tokio::test]
    async fn test_build_inform_options() {
        let (handler, _guard, _socket) = create_test_handler("inform_opts").await;

        let options = handler.build_inform_options();

        assert!(options.iter().any(|opt| matches!(
            opt,
            DhcpOption::ServerIdentifier(ip) if *ip == handler.config.server_ip
        )));
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::SubnetMask(_)))
        );
        assert!(
            !options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::LeaseTime(_)))
        );
    }

    #[tokio::test]
    async fn test_filter_options_by_prl() {
        let (handler, _guard, _socket) = create_test_handler("prl_filter").await;

        let options = handler.build_offer_options();

        let prl_subnet_only: &[u8] = &[1];
        let filtered = handler.filter_options_by_prl(options.clone(), Some(prl_subnet_only));

        assert!(
            filtered
                .iter()
                .any(|opt| matches!(opt, DhcpOption::SubnetMask(_)))
        );
        assert!(
            filtered
                .iter()
                .any(|opt| matches!(opt, DhcpOption::ServerIdentifier(_)))
        );
        assert!(
            filtered
                .iter()
                .any(|opt| matches!(opt, DhcpOption::LeaseTime(_)))
        );
        assert!(
            !filtered
                .iter()
                .any(|opt| matches!(opt, DhcpOption::Router(_)))
        );
        assert!(
            !filtered
                .iter()
                .any(|opt| matches!(opt, DhcpOption::DnsServer(_)))
        );

        let prl_router_dns: &[u8] = &[3, 6];
        let filtered2 = handler.filter_options_by_prl(options.clone(), Some(prl_router_dns));

        assert!(
            filtered2
                .iter()
                .any(|opt| matches!(opt, DhcpOption::Router(_)))
        );
        assert!(
            filtered2
                .iter()
                .any(|opt| matches!(opt, DhcpOption::DnsServer(_)))
        );
        assert!(
            !filtered2
                .iter()
                .any(|opt| matches!(opt, DhcpOption::SubnetMask(_)))
        );

        let no_filter = handler.filter_options_by_prl(options.clone(), None);
        assert_eq!(no_filter.len(), options.len());
    }

    #[tokio::test]
    async fn test_pool_exhaustion() {
        let path = "test_server_exhaustion.json".to_string();
        let _guard = TestGuard(path.clone());

        let config = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 102),
            leases_file: path,
            ..test_config()
        };

        let config = Arc::new(config);
        let leases = Arc::new(Leases::new(Arc::clone(&config)).await.unwrap());
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let handler = PacketHandler {
            config,
            leases,
            socket,
            rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        };

        for index in 0..3u8 {
            let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, index];
            let client_id = {
                let mut id = vec![HTYPE_ETHERNET];
                id.extend_from_slice(&mac);
                id
            };

            let ip = handler.leases.allocate_ip(&client_id).await.unwrap();
            handler
                .leases
                .create_lease(&client_id, ip, None, None)
                .await
                .unwrap();
        }

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99];
        let packet_data = create_dhcp_packet(MessageType::Discover, mac, 0x12345678, vec![]);
        let packet = DhcpPacket::parse(&packet_data).unwrap();

        let result = handler.handle_discover(&packet).await;
        assert!(result.is_ok());
    }
}
