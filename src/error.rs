//! Error types for the DHCP server.
//!
//! All fallible operations in this crate return [`Result<T>`], which uses
//! the [`Error`] enum for error variants.

use std::net::Ipv4Addr;

/// Errors that can occur during DHCP server operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// File system or network I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error (config or lease files).
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Malformed DHCP packet received.
    ///
    /// This includes packets that are too short, have invalid magic cookies,
    /// invalid option lengths, or other protocol violations.
    #[error("Invalid DHCP packet: {0}")]
    InvalidPacket(String),

    /// The IP address pool is exhausted.
    ///
    /// All addresses in the configured pool are either leased, pending offer,
    /// or marked as declined. Consider expanding the pool or reducing lease duration.
    #[error("No available IP addresses in pool")]
    PoolExhausted,

    /// Invalid server configuration.
    ///
    /// Returned by [`Config::validate`](crate::Config::validate) when the
    /// configuration contains invalid values (e.g., pool_start > pool_end).
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Socket creation or configuration error.
    ///
    /// Typically occurs when binding to port 67 without administrator privileges,
    /// or when the specified network interface doesn't exist.
    #[error("Socket error: {0}")]
    Socket(String),

    /// Requested IP address is outside the configured pool.
    ///
    /// A client requested an IP that is not within pool_start..=pool_end
    /// and is not a static binding.
    #[error("Address {0} is outside the configured pool range")]
    AddressOutOfRange(Ipv4Addr),

    /// No lease exists for the specified client.
    ///
    /// Returned when attempting to renew or release a lease that doesn't exist.
    #[error("Client {0} not found in leases")]
    LeaseNotFound(String),
}

/// A specialized Result type for DHCP operations.
pub type Result<T> = std::result::Result<T, Error>;
