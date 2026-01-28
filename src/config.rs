//! DHCP server configuration.
//!
//! The [`Config`] struct defines all server parameters including the IP pool,
//! lease duration, network options, and static bindings. Configuration is
//! loaded from and saved to JSON files.
//!
//! # Example Configuration
//!
//! ```json
//! {
//!   "server_ip": "192.168.1.1",
//!   "subnet_mask": "255.255.255.0",
//!   "pool_start": "192.168.1.100",
//!   "pool_end": "192.168.1.200",
//!   "gateway": "192.168.1.1",
//!   "dns_servers": ["8.8.8.8"],
//!   "lease_duration_seconds": 86400,
//!   "leases_file": "leases.json"
//! }
//! ```

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// DHCP server configuration.
///
/// All network-related options that clients receive (subnet mask, gateway, DNS)
/// are configured here, along with the IP pool range and lease parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// IP address of this DHCP server.
    ///
    /// Sent to clients as the Server Identifier (Option 54). Must not be
    /// within the pool range.
    pub server_ip: Ipv4Addr,

    /// Subnet mask to provide to clients (Option 1).
    ///
    /// Must be a valid contiguous mask (e.g., 255.255.255.0).
    pub subnet_mask: Ipv4Addr,

    /// First IP address in the dynamic allocation pool (inclusive).
    pub pool_start: Ipv4Addr,

    /// Last IP address in the dynamic allocation pool (inclusive).
    pub pool_end: Ipv4Addr,

    /// Default gateway to provide to clients (Option 3).
    ///
    /// Must not be within the pool range if set.
    pub gateway: Option<Ipv4Addr>,

    /// DNS servers to provide to clients (Option 6).
    pub dns_servers: Vec<Ipv4Addr>,

    /// Domain name to provide to clients (Option 15).
    pub domain_name: Option<String>,

    /// Default lease duration in seconds (Option 51).
    ///
    /// Clients may request shorter leases, which will be honored down to
    /// a minimum of 60 seconds.
    pub lease_duration_seconds: u32,

    /// Renewal time T1 in seconds (Option 58).
    ///
    /// When clients should start attempting to renew their lease with
    /// the original server. Defaults to 50% of lease_duration_seconds.
    pub renewal_time_seconds: Option<u32>,

    /// Rebinding time T2 in seconds (Option 59).
    ///
    /// When clients should start broadcasting renewal requests to any
    /// server. Defaults to 87.5% of lease_duration_seconds.
    pub rebinding_time_seconds: Option<u32>,

    /// Broadcast address to provide to clients (Option 28).
    ///
    /// If not set, calculated from server_ip and subnet_mask.
    pub broadcast_address: Option<Ipv4Addr>,

    /// Interface MTU to provide to clients (Option 26).
    pub mtu: Option<u16>,

    /// Static MAC-to-IP bindings.
    ///
    /// These clients always receive the same IP address regardless of
    /// the dynamic pool.
    pub static_bindings: Vec<StaticBinding>,

    /// Path to the lease persistence file.
    ///
    /// Leases are saved to this JSON file and restored on server restart.
    pub leases_file: String,

    /// Windows network interface index to bind to.
    ///
    /// Use `Get-NetAdapter | Format-Table InterfaceIndex` in PowerShell
    /// to find interface indices. Only used on Windows; ignored on other platforms.
    pub interface_index: Option<u32>,
}

/// A static MAC-to-IP binding.
///
/// Clients with this MAC address always receive the specified IP address,
/// bypassing the dynamic pool allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBinding {
    /// MAC address in colon or hyphen-separated format (e.g., "aa:bb:cc:dd:ee:ff").
    pub mac_address: String,

    /// IP address to always assign to this MAC.
    ///
    /// Does not need to be within the pool range.
    pub ip_address: Ipv4Addr,

    /// Optional hostname to associate with this binding.
    pub hostname: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            domain_name: None,
            lease_duration_seconds: 86400,
            renewal_time_seconds: None,
            rebinding_time_seconds: None,
            broadcast_address: None,
            mtu: None,
            static_bindings: Vec::new(),
            leases_file: "leases.json".to_string(),
            interface_index: None,
        }
    }
}

impl Config {
    /// Loads configuration from a file, or creates a default config if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file exists but cannot be read or parsed
    /// - The configuration fails validation
    /// - A new default config cannot be written
    pub async fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            let config: Config = serde_json::from_str(&content)?;
            config.validate()?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save(path).await?;
            Ok(config)
        }
    }

    /// Saves the configuration to a JSON file.
    ///
    /// The file is written with pretty-printing for human readability.
    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }

    /// Validates the configuration for correctness.
    ///
    /// # Checks Performed
    ///
    /// - `pool_start` <= `pool_end`
    /// - `server_ip` is not within the pool range
    /// - `gateway` (if set) is not within the pool range
    /// - `subnet_mask` is a valid contiguous mask
    /// - Static bindings have valid MAC formats
    /// - No duplicate MACs or IPs in static bindings
    /// - `domain_name` contains only valid characters
    /// - `lease_duration_seconds` > 0
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] with a description of the first
    /// validation failure encountered.
    pub fn validate(&self) -> Result<()> {
        let start = u32::from(self.pool_start);
        let end = u32::from(self.pool_end);

        if start > end {
            return Err(Error::InvalidConfig(
                "pool_start must be less than or equal to pool_end".to_string(),
            ));
        }

        let server = u32::from(self.server_ip);
        if server >= start && server <= end {
            return Err(Error::InvalidConfig(
                "server_ip must not be within the pool range".to_string(),
            ));
        }

        if let Some(gateway) = self.gateway {
            let gw = u32::from(gateway);
            if gw >= start && gw <= end {
                return Err(Error::InvalidConfig(
                    "gateway must not be within the pool range".to_string(),
                ));
            }
        }

        if !Self::is_valid_subnet_mask(self.subnet_mask) {
            return Err(Error::InvalidConfig(format!(
                "invalid subnet mask: {} (must be contiguous)",
                self.subnet_mask
            )));
        }

        let mut seen_ips: HashSet<Ipv4Addr> = HashSet::new();
        let mut seen_macs: HashSet<String> = HashSet::new();

        for binding in &self.static_bindings {
            if !Self::is_valid_mac(&binding.mac_address) {
                return Err(Error::InvalidConfig(format!(
                    "invalid MAC address format: {}",
                    binding.mac_address
                )));
            }

            let normalized_mac = normalize_mac(&binding.mac_address);
            if !seen_macs.insert(normalized_mac.clone()) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate MAC address in static bindings: {}",
                    binding.mac_address
                )));
            }

            if !seen_ips.insert(binding.ip_address) {
                return Err(Error::InvalidConfig(format!(
                    "duplicate IP address in static bindings: {}",
                    binding.ip_address
                )));
            }
        }

        if let Some(ref domain) = self.domain_name {
            let sanitized = sanitize_domain_name(domain);
            if sanitized != *domain {
                return Err(Error::InvalidConfig(format!(
                    "invalid domain name: {} (contains invalid characters)",
                    domain
                )));
            }
        }

        if self.lease_duration_seconds == 0 {
            return Err(Error::InvalidConfig(
                "lease_duration_seconds must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    fn is_valid_subnet_mask(mask: Ipv4Addr) -> bool {
        let mask_bits = u32::from(mask);
        if mask_bits == 0 {
            return false;
        }
        let inverted = !mask_bits;
        inverted.count_ones() == inverted.trailing_ones()
    }

    /// Checks if an IP address is within the configured pool range.
    ///
    /// Returns `true` if `pool_start <= ip <= pool_end`.
    pub fn ip_in_pool(&self, ip: Ipv4Addr) -> bool {
        let addr = u32::from(ip);
        let start = u32::from(self.pool_start);
        let end = u32::from(self.pool_end);
        addr >= start && addr <= end
    }

    /// Returns the total number of addresses in the pool.
    pub fn pool_size(&self) -> u32 {
        u32::from(self.pool_end) - u32::from(self.pool_start) + 1
    }

    /// Returns the broadcast address for the configured network.
    ///
    /// If `broadcast_address` is explicitly configured, returns that value.
    /// Otherwise, calculates it from `server_ip` and `subnet_mask`.
    pub fn calculate_broadcast(&self) -> Ipv4Addr {
        if let Some(broadcast) = self.broadcast_address {
            return broadcast;
        }

        let ip = u32::from(self.server_ip);
        let mask = u32::from(self.subnet_mask);
        let broadcast = ip | !mask;
        Ipv4Addr::from(broadcast)
    }

    /// Validates a MAC address string format.
    ///
    /// Accepts colon-separated (aa:bb:cc:dd:ee:ff) or hyphen-separated
    /// (aa-bb-cc-dd-ee-ff) formats, case-insensitive.
    pub fn is_valid_mac(mac: &str) -> bool {
        let normalized = normalize_mac(mac);
        let parts: Vec<&str> = normalized.split(':').collect();
        parts.len() == 6
            && parts
                .iter()
                .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
    }
}

/// Normalizes a MAC address to lowercase colon-separated format.
///
/// Converts "AA-BB-CC-DD-EE-FF" to "aa:bb:cc:dd:ee:ff".
pub fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace('-', ":")
}

/// Sanitizes a hostname by removing invalid characters.
///
/// Keeps only ASCII alphanumeric characters, hyphens, and dots.
/// Truncates to 255 characters maximum per RFC 1035.
pub fn sanitize_hostname(hostname: &str) -> String {
    hostname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(255)
        .collect()
}

/// Sanitizes a domain name by removing invalid characters.
///
/// Keeps only ASCII alphanumeric characters, hyphens, and dots.
/// Truncates to 255 characters maximum per RFC 1035.
pub fn sanitize_domain_name(domain: &str) -> String {
    domain
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(255)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        assert!(Config::default().validate().is_ok());

        let invalid_configs = [
            Config {
                pool_start: Ipv4Addr::new(192, 168, 1, 200),
                pool_end: Ipv4Addr::new(192, 168, 1, 100),
                ..Default::default()
            },
            Config {
                server_ip: Ipv4Addr::new(192, 168, 1, 150),
                ..Default::default()
            },
            Config {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 150)),
                ..Default::default()
            },
            Config {
                lease_duration_seconds: 0,
                ..Default::default()
            },
            Config {
                static_bindings: vec![StaticBinding {
                    mac_address: "invalid".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                }],
                ..Default::default()
            },
        ];
        for config in invalid_configs {
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn test_subnet_mask_validation() {
        assert!(Config::is_valid_subnet_mask(Ipv4Addr::new(
            255, 255, 255, 0
        )));
        assert!(Config::is_valid_subnet_mask(Ipv4Addr::new(
            255, 255, 240, 0
        )));
        assert!(Config::is_valid_subnet_mask(Ipv4Addr::new(255, 0, 0, 0)));
        assert!(!Config::is_valid_subnet_mask(Ipv4Addr::new(255, 0, 255, 0)));
        assert!(!Config::is_valid_subnet_mask(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!Config::is_valid_subnet_mask(Ipv4Addr::new(
            255, 255, 0, 255
        )));
    }

    #[test]
    fn test_static_binding_conflicts() {
        let config_duplicate_ip = Config {
            static_bindings: vec![
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:02".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
            ],
            ..Default::default()
        };
        assert!(config_duplicate_ip.validate().is_err());

        let config_duplicate_mac = Config {
            static_bindings: vec![
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "AA-BB-CC-DD-EE-FF".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 51),
                    hostname: None,
                },
            ],
            ..Default::default()
        };
        assert!(config_duplicate_mac.validate().is_err());
    }

    #[test]
    fn test_domain_name_validation() {
        let valid = Config {
            domain_name: Some("example.local".to_string()),
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid = Config {
            domain_name: Some("bad domain\x00name".to_string()),
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_pool_functions() {
        let config = Config::default();

        assert!(config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!config.ip_in_pool(Ipv4Addr::new(10, 0, 0, 1)));

        assert_eq!(config.pool_size(), 101);
        assert_eq!(
            config.calculate_broadcast(),
            Ipv4Addr::new(192, 168, 1, 255)
        );
    }

    #[test]
    fn test_mac_functions() {
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff");

        assert!(Config::is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(Config::is_valid_mac("AA-BB-CC-DD-EE-FF"));
        assert!(!Config::is_valid_mac("invalid"));
        assert!(!Config::is_valid_mac(""));
    }

    #[test]
    fn test_sanitize_hostname() {
        assert_eq!(sanitize_hostname("valid-host.local"), "valid-host.local");
        assert_eq!(sanitize_hostname("bad\x00host"), "badhost");
        assert_eq!(sanitize_hostname("has spaces"), "hasspaces");
    }

    #[test]
    fn test_sanitize_domain_name() {
        assert_eq!(sanitize_domain_name("example.local"), "example.local");
        assert_eq!(sanitize_domain_name("bad\x00domain"), "baddomain");
    }

    #[test]
    fn test_pool_boundary_validation() {
        let equal_boundaries = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 100),
            ..Default::default()
        };
        assert!(
            equal_boundaries.validate().is_ok(),
            "Pool with start == end should be valid (single IP pool)"
        );

        let start_greater = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 101),
            pool_end: Ipv4Addr::new(192, 168, 1, 100),
            ..Default::default()
        };
        assert!(
            start_greater.validate().is_err(),
            "Pool with start > end should be invalid"
        );
    }

    #[test]
    fn test_server_ip_pool_boundary() {
        let server_at_start = Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 100),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            server_at_start.validate().is_err(),
            "Server IP at pool start should be invalid"
        );

        let server_at_end = Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 200),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            server_at_end.validate().is_err(),
            "Server IP at pool end should be invalid"
        );

        let server_just_before = Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 99),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            server_just_before.validate().is_ok(),
            "Server IP just before pool should be valid"
        );

        let server_just_after = Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 201),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            server_just_after.validate().is_ok(),
            "Server IP just after pool should be valid"
        );
    }

    #[test]
    fn test_gateway_pool_boundary() {
        let gateway_at_start = Config {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 100)),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            gateway_at_start.validate().is_err(),
            "Gateway at pool start should be invalid"
        );

        let gateway_at_end = Config {
            gateway: Some(Ipv4Addr::new(192, 168, 1, 200)),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };
        assert!(
            gateway_at_end.validate().is_err(),
            "Gateway at pool end should be invalid"
        );
    }

    #[test]
    fn test_is_valid_mac_detailed() {
        assert!(Config::is_valid_mac("00:00:00:00:00:00"));
        assert!(Config::is_valid_mac("ff:ff:ff:ff:ff:ff"));
        assert!(Config::is_valid_mac("aA:bB:cC:dD:eE:fF"));

        assert!(
            !Config::is_valid_mac("aa:bb:cc:dd:ee"),
            "MAC with only 5 octets should be invalid"
        );
        assert!(
            !Config::is_valid_mac("aa:bb:cc:dd:ee:ff:00"),
            "MAC with 7 octets should be invalid"
        );
        assert!(
            !Config::is_valid_mac("ag:bb:cc:dd:ee:ff"),
            "MAC with non-hex character should be invalid"
        );
        assert!(
            !Config::is_valid_mac("a:bb:cc:dd:ee:ff"),
            "MAC with single-digit octet should be invalid"
        );
        assert!(
            !Config::is_valid_mac("aaa:bb:cc:dd:ee:ff"),
            "MAC with triple-digit octet should be invalid"
        );
    }

    #[test]
    fn test_ip_in_pool_boundaries() {
        let config = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            ..Default::default()
        };

        assert!(
            config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 100)),
            "Pool start should be in pool"
        );
        assert!(
            config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 200)),
            "Pool end should be in pool"
        );
        assert!(
            config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 150)),
            "Middle of pool should be in pool"
        );

        assert!(
            !config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 99)),
            "Just before pool should not be in pool"
        );
        assert!(
            !config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 201)),
            "Just after pool should not be in pool"
        );
    }

    #[test]
    fn test_pool_size_calculation() {
        let single_ip = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 100),
            ..Default::default()
        };
        assert_eq!(single_ip.pool_size(), 1);

        let two_ips = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 101),
            ..Default::default()
        };
        assert_eq!(two_ips.pool_size(), 2);
    }

    #[test]
    fn test_static_binding_duplicate_detection() {
        let duplicate_mac = Config {
            static_bindings: vec![
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 51),
                    hostname: None,
                },
            ],
            ..Default::default()
        };
        assert!(
            duplicate_mac.validate().is_err(),
            "Duplicate MAC addresses should be rejected"
        );

        let duplicate_ip = Config {
            static_bindings: vec![
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:02".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
            ],
            ..Default::default()
        };
        assert!(
            duplicate_ip.validate().is_err(),
            "Duplicate IP addresses should be rejected"
        );
    }

    #[test]
    fn test_single_static_binding_valid() {
        let single_binding = Config {
            static_bindings: vec![StaticBinding {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ip_address: Ipv4Addr::new(192, 168, 1, 50),
                hostname: None,
            }],
            ..Default::default()
        };
        assert!(
            single_binding.validate().is_ok(),
            "Single static binding should be valid"
        );
    }

    #[test]
    fn test_multiple_unique_static_bindings_valid() {
        let multiple_bindings = Config {
            static_bindings: vec![
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 50),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:02".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 51),
                    hostname: None,
                },
                StaticBinding {
                    mac_address: "aa:bb:cc:dd:ee:03".to_string(),
                    ip_address: Ipv4Addr::new(192, 168, 1, 52),
                    hostname: None,
                },
            ],
            ..Default::default()
        };
        assert!(
            multiple_bindings.validate().is_ok(),
            "Multiple unique static bindings should be valid"
        );
    }

    #[tokio::test]
    async fn test_config_save_and_load() {
        let path = "test_config_save_load.toml";
        let _guard = TestGuard(path.to_string());

        let config = Config {
            server_ip: Ipv4Addr::new(10, 0, 0, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 0, 0),
            pool_start: Ipv4Addr::new(10, 0, 1, 1),
            pool_end: Ipv4Addr::new(10, 0, 1, 100),
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            domain_name: Some("test.local".to_string()),
            lease_duration_seconds: 7200,
            renewal_time_seconds: Some(3600),
            rebinding_time_seconds: Some(6300),
            broadcast_address: None,
            mtu: Some(1400),
            static_bindings: vec![StaticBinding {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ip_address: Ipv4Addr::new(10, 0, 0, 100),
                hostname: Some("static-host".to_string()),
            }],
            leases_file: "leases.json".to_string(),
            interface_index: Some(1),
        };

        config.save(path).await.unwrap();

        assert!(
            std::path::Path::new(path).exists(),
            "Config file should be created"
        );

        let loaded = Config::load_or_create(path).await.unwrap();

        assert_eq!(loaded.server_ip, config.server_ip);
        assert_eq!(loaded.subnet_mask, config.subnet_mask);
        assert_eq!(loaded.pool_start, config.pool_start);
        assert_eq!(loaded.pool_end, config.pool_end);
        assert_eq!(loaded.gateway, config.gateway);
        assert_eq!(loaded.dns_servers, config.dns_servers);
        assert_eq!(loaded.domain_name, config.domain_name);
        assert_eq!(loaded.lease_duration_seconds, config.lease_duration_seconds);
        assert_eq!(loaded.static_bindings.len(), 1);
        assert_eq!(loaded.static_bindings[0].mac_address, "aa:bb:cc:dd:ee:ff");
    }

    #[tokio::test]
    async fn test_config_load_creates_default_when_missing() {
        let path = "test_config_nonexistent_12345.toml";
        let _ = std::fs::remove_file(path);

        let result = Config::load_or_create(path).await;

        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.server_ip, Ipv4Addr::new(192, 168, 1, 1));

        let _ = std::fs::remove_file(path);
    }

    struct TestGuard(String);
    impl Drop for TestGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
