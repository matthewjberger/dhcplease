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
    rate_limiter: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
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
    rate_limiter: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl PacketHandler {
    async fn is_rate_limited(&self, key: &str) -> bool {
        let mut limiter = self.rate_limiter.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        if limiter.len() > RATE_LIMIT_CLEANUP_THRESHOLD {
            limiter.retain(|_, timestamps| {
                timestamps.retain(|t| now.duration_since(*t) < window);
                !timestamps.is_empty()
            });
        }

        let timestamps = limiter.entry(key.to_string()).or_default();
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

        let mac = packet.format_mac();

        if self.is_rate_limited(&mac).await {
            warn!("Rate limited: {} from {}", mac, source);
            return Ok(());
        }

        let message_type = packet
            .message_type()
            .ok_or_else(|| Error::InvalidPacket("Missing message type option".to_string()))?;

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

    async fn handle_discover(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.format_mac();
        let client_id = packet.client_id();

        let offered_ip = match packet.requested_ip() {
            Some(requested_ip)
                if self.config.ip_in_pool(requested_ip)
                    && self.leases.is_ip_available(requested_ip, &client_id).await =>
            {
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

        let mut options = self.build_offer_options();
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

        let existing_lease = self.leases.get_lease(&client_id).await;
        let is_renewal = existing_lease
            .as_ref()
            .is_some_and(|lease| lease.ip_address == requested_ip && !lease.is_expired());

        let hostname = packet.hostname().map(sanitize_hostname);
        let lease = if is_renewal {
            match self.leases.renew_lease(&client_id).await {
                Ok(lease) => lease,
                Err(Error::LeaseNotFound(_)) => {
                    match self
                        .leases
                        .create_lease(&client_id, requested_ip, hostname)
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
                .create_lease(&client_id, requested_ip, hostname)
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

        let mut options = self.build_offer_options();
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
        if client_id.len() == 7 && client_id[0] == 1 {
            let mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                client_id[1], client_id[2], client_id[3], client_id[4], client_id[5], client_id[6]
            );
            self.config.static_bindings.iter().any(|binding| {
                binding.ip_address == ip && binding.mac_address.to_lowercase() == mac
            })
        } else {
            false
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

        let mut options = self.build_inform_options();
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

    #[test]
    fn test_offer_options_content() {
        let config = test_config();

        let mut options = vec![
            DhcpOption::ServerIdentifier(config.server_ip),
            DhcpOption::LeaseTime(config.lease_duration_seconds),
            DhcpOption::SubnetMask(config.subnet_mask),
        ];

        if let Some(gateway) = config.gateway {
            options.push(DhcpOption::Router(vec![gateway]));
        }

        if !config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(config.dns_servers.clone()));
        }

        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::ServerIdentifier(_)))
        );
        assert!(
            options
                .iter()
                .any(|opt| matches!(opt, DhcpOption::LeaseTime(3600)))
        );
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

    #[test]
    fn test_broadcast_calculation() {
        let config = test_config();
        let broadcast = config.calculate_broadcast();
        assert_eq!(broadcast, Ipv4Addr::new(192, 168, 1, 255));
    }
}
