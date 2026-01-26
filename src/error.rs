use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid DHCP packet: {0}")]
    InvalidPacket(String),

    #[error("No available IP addresses in pool")]
    PoolExhausted,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Socket error: {0}")]
    Socket(String),

    #[error("Address {0} is outside the configured pool range")]
    AddressOutOfRange(Ipv4Addr),

    #[error("MAC address {0} not found in leases")]
    LeaseNotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;
