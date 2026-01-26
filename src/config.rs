use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

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
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = serde_json::from_str(&content)?;
            config.validate()?;
            Ok(config)
        } else {
            let config = Config::default();
            config.save(path)?;
            Ok(config)
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
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

        for binding in &self.static_bindings {
            let ip = u32::from(binding.ip_address);
            if ip < start || ip > end {
                return Err(Error::InvalidConfig(format!(
                    "static binding {} for MAC {} is outside the pool range",
                    binding.ip_address, binding.mac_address
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pool_start_greater_than_end() {
        let config = Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 200),
            pool_end: Ipv4Addr::new(192, 168, 1, 100),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_server_ip_in_pool() {
        let config = Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 150),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ip_in_pool() {
        let config = Config::default();
        assert!(config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 150)));
        assert!(!config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!config.ip_in_pool(Ipv4Addr::new(192, 168, 1, 250)));
    }

    #[test]
    fn test_pool_size() {
        let config = Config::default();
        assert_eq!(config.pool_size(), 101);
    }

    #[test]
    fn test_calculate_broadcast() {
        let config = Config::default();
        assert_eq!(
            config.calculate_broadcast(),
            Ipv4Addr::new(192, 168, 1, 255)
        );
    }
}
