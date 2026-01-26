use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::lease::LeaseManager;
use crate::options::{DhcpOption, MessageType};
use crate::packet::DhcpPacket;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

pub struct DhcpServer {
    config: Arc<Config>,
    lease_manager: Arc<LeaseManager>,
    socket: UdpSocket,
}

impl DhcpServer {
    pub async fn new(config: Config) -> Result<Self> {
        let lease_manager = LeaseManager::new(config.clone())?;

        let socket = Self::create_socket(&config)?;

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
            config: Arc::new(config),
            lease_manager: Arc::new(lease_manager),
            socket,
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
        }

        let std_socket: std::net::UdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(|error| {
            Error::Socket(format!("Failed to convert to tokio socket: {}", error))
        })?;

        Ok(tokio_socket)
    }

    pub async fn run(&self) -> Result<()> {
        let mut buffer = [0u8; 1500];

        info!("DHCP server ready and listening");

        loop {
            match self.socket.recv_from(&mut buffer).await {
                Ok((size, source)) => {
                    if let Err(error) = self.handle_packet(&buffer[..size], source).await {
                        warn!("Error handling packet from {}: {}", source, error);
                    }
                }
                Err(error) => {
                    error!("Error receiving packet: {}", error);
                }
            }
        }
    }

    async fn handle_packet(&self, data: &[u8], source: SocketAddr) -> Result<()> {
        let packet = DhcpPacket::parse(data)?;

        let message_type = packet
            .message_type()
            .ok_or_else(|| Error::InvalidPacket("Missing message type option".to_string()))?;

        let mac = packet.mac_address();
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
        let mac = packet.mac_address();

        let offered_ip = match packet.requested_ip() {
            Some(requested_ip)
                if self.config.ip_in_pool(requested_ip)
                    && self.lease_manager.is_ip_available(requested_ip, &mac).await =>
            {
                requested_ip
            }
            _ => self.lease_manager.allocate_ip(&mac).await?,
        };

        let options = self.build_offer_options(offered_ip);

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
        let mac = packet.mac_address();

        if let Some(server_id) = packet.server_identifier() {
            if server_id != self.config.server_ip {
                info!("REQUEST from {} is for different server {}", mac, server_id);
                return Ok(());
            }
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
            && !self
                .config
                .static_bindings
                .iter()
                .any(|binding| binding.ip_address == requested_ip)
        {
            return self.send_nak(packet, "Requested IP not in pool").await;
        }

        if !self.lease_manager.is_ip_available(requested_ip, &mac).await {
            return self.send_nak(packet, "IP address already in use").await;
        }

        let lease = self.lease_manager.create_lease(&mac, requested_ip).await?;

        let options = self.build_ack_options(&lease);

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

    async fn handle_release(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.mac_address();

        self.lease_manager.release_lease(&mac).await?;

        info!("RELEASE from {} for {}", mac, packet.ciaddr);

        Ok(())
    }

    async fn handle_decline(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.mac_address();

        if let Some(declined_ip) = packet.requested_ip() {
            warn!(
                "DECLINE from {} for {} - marking IP as unavailable",
                mac, declined_ip
            );
        }

        Ok(())
    }

    async fn handle_inform(&self, packet: &DhcpPacket) -> Result<()> {
        let mac = packet.mac_address();

        let options = self.build_inform_options();

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
        let mac = packet.mac_address();

        let options = vec![DhcpOption::ServerIdentifier(self.config.server_ip)];

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

        let destination = if request.is_broadcast() || request.ciaddr == Ipv4Addr::UNSPECIFIED {
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::BROADCAST), DHCP_CLIENT_PORT)
        } else {
            SocketAddr::new(std::net::IpAddr::V4(request.ciaddr), DHCP_CLIENT_PORT)
        };

        self.socket.send_to(&encoded, destination).await?;

        Ok(())
    }

    fn build_offer_options(&self, _offered_ip: Ipv4Addr) -> Vec<DhcpOption> {
        let mut options = vec![
            DhcpOption::ServerIdentifier(self.config.server_ip),
            DhcpOption::LeaseTime(self.config.lease_duration_seconds),
            DhcpOption::SubnetMask(self.config.subnet_mask),
        ];

        if let Some(gateway) = self.config.gateway {
            options.push(DhcpOption::Router(vec![gateway]));
        }

        if !self.config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(self.config.dns_servers.clone()));
        }

        if let Some(ref domain) = self.config.domain_name {
            options.push(DhcpOption::DomainName(domain.clone()));
        }

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

    fn build_ack_options(&self, lease: &crate::lease::Lease) -> Vec<DhcpOption> {
        self.build_offer_options(lease.ip_address)
    }

    fn build_inform_options(&self) -> Vec<DhcpOption> {
        let mut options = vec![
            DhcpOption::ServerIdentifier(self.config.server_ip),
            DhcpOption::SubnetMask(self.config.subnet_mask),
        ];

        if let Some(gateway) = self.config.gateway {
            options.push(DhcpOption::Router(vec![gateway]));
        }

        if !self.config.dns_servers.is_empty() {
            options.push(DhcpOption::DnsServer(self.config.dns_servers.clone()));
        }

        if let Some(ref domain) = self.config.domain_name {
            options.push(DhcpOption::DomainName(domain.clone()));
        }

        options
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn lease_manager(&self) -> &LeaseManager {
        &self.lease_manager
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

    fn test_config() -> Config {
        Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            domain_name: Some("test.local".to_string()),
            lease_duration_seconds: 86400,
            renewal_time_seconds: None,
            rebinding_time_seconds: None,
            broadcast_address: None,
            mtu: Some(1500),
            static_bindings: vec![],
            leases_file: "test_server_leases.json".to_string(),
            interface_index: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let config = test_config();
        assert!(config.validate().is_ok());
    }
}
