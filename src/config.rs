use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub lease_duration_seconds: u32,
    pub renewal_time_seconds: Option<u32>,
    pub rebinding_time_seconds: Option<u32>,
    pub broadcast_address: Option<Ipv4Addr>,
    pub mtu: Option<u16>,
    pub static_bindings: Vec<StaticBinding>,
    pub leases_file: String,
    pub interface_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBinding {
    pub mac_address: String,
    pub ip_address: Ipv4Addr,
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

    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }

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

    pub fn ip_in_pool(&self, ip: Ipv4Addr) -> bool {
        let addr = u32::from(ip);
        let start = u32::from(self.pool_start);
        let end = u32::from(self.pool_end);
        addr >= start && addr <= end
    }

    pub fn pool_size(&self) -> u32 {
        u32::from(self.pool_end) - u32::from(self.pool_start) + 1
    }

    pub fn calculate_broadcast(&self) -> Ipv4Addr {
        if let Some(broadcast) = self.broadcast_address {
            return broadcast;
        }

        let ip = u32::from(self.server_ip);
        let mask = u32::from(self.subnet_mask);
        let broadcast = ip | !mask;
        Ipv4Addr::from(broadcast)
    }

    pub fn is_valid_mac(mac: &str) -> bool {
        let normalized = normalize_mac(mac);
        let parts: Vec<&str> = normalized.split(':').collect();
        parts.len() == 6
            && parts
                .iter()
                .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
    }
}

pub fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace('-', ":")
}

pub fn sanitize_hostname(hostname: &str) -> String {
    hostname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(255)
        .collect()
}

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
}
