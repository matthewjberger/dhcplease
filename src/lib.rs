//! # dhcplease
//!
//! A DHCP server library implementing RFC 2131 (DHCP) and RFC 2132 (DHCP Options).
//!
//! ## Features
//!
//! - Full DHCP protocol: DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, DECLINE, INFORM
//! - BOOTP compatibility for legacy clients
//! - Static MAC-to-IP bindings
//! - Lease persistence across restarts
//! - Relay agent support (Option 82)
//! - Rate limiting per client
//! - Async/await with Tokio
//!
//! ## Quick Start
//!
//! ```no_run
//! use dhcplease::{Config, DhcpServer};
//!
//! #[tokio::main]
//! async fn main() -> dhcplease::Result<()> {
//!     let config = Config::load_or_create("config.json").await?;
//!     let server = DhcpServer::new(config).await?;
//!     server.run().await
//! }
//! ```
//!
//! ## Architecture
//!
//! - [`Config`] - Server configuration (IP pool, lease duration, DNS, etc.)
//! - [`DhcpServer`] - Main server that listens on UDP port 67
//! - [`Leases`] - Thread-safe lease manager with persistence
//! - [`DhcpPacket`] - DHCP packet parsing and encoding
//! - [`DhcpOption`] - DHCP option types per RFC 2132

pub mod config;
pub mod error;
pub mod lease;
pub mod options;
pub mod packet;
pub mod server;

pub use config::Config;
pub use error::{Error, Result};
pub use lease::{Lease, Leases};
pub use options::{DhcpOption, MessageType};
pub use packet::DhcpPacket;
pub use server::DhcpServer;
