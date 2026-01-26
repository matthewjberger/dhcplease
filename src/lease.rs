use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub ip_address: Ipv4Addr,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Lease {
    pub fn new(ip_address: Ipv4Addr, mac_address: String, duration_seconds: u32) -> Self {
        let now = Utc::now();
        Self {
            ip_address,
            mac_address,
            hostname: None,
            expires_at: now + chrono::Duration::seconds(duration_seconds as i64),
            created_at: now,
            last_seen: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn renew(&mut self, duration_seconds: u32) {
        let now = Utc::now();
        self.expires_at = now + chrono::Duration::seconds(duration_seconds as i64);
        self.last_seen = now;
    }

    pub fn remaining_seconds(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseStore {
    pub leases: HashMap<String, Lease>,
    pub ip_to_mac: HashMap<Ipv4Addr, String>,
}

impl LeaseStore {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let store: LeaseStore = serde_json::from_str(&content)?;
            Ok(store)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct LeaseManager {
    store: Arc<RwLock<LeaseStore>>,
    config: Config,
    leases_path: String,
}

impl LeaseManager {
    pub fn new(config: Config) -> Result<Self> {
        let leases_path = config.leases_file.clone();
        let store = LeaseStore::load(&leases_path)?;

        Ok(Self {
            store: Arc::new(RwLock::new(store)),
            config,
            leases_path,
        })
    }

    pub async fn get_lease(&self, mac_address: &str) -> Option<Lease> {
        let store = self.store.read().await;
        store.leases.get(mac_address).cloned()
    }

    pub async fn get_lease_by_ip(&self, ip: Ipv4Addr) -> Option<Lease> {
        let store = self.store.read().await;
        store
            .ip_to_mac
            .get(&ip)
            .and_then(|mac| store.leases.get(mac).cloned())
    }

    pub async fn allocate_ip(&self, mac_address: &str) -> Result<Ipv4Addr> {
        for binding in &self.config.static_bindings {
            if binding.mac_address.to_lowercase() == mac_address.to_lowercase() {
                return Ok(binding.ip_address);
            }
        }

        {
            let store = self.store.read().await;
            if let Some(lease) = store.leases.get(mac_address) {
                if !lease.is_expired() && self.config.ip_in_pool(lease.ip_address) {
                    return Ok(lease.ip_address);
                }
            }
        }

        let mut store = self.store.write().await;

        self.cleanup_expired_leases_internal(&mut store);

        let start = u32::from(self.config.pool_start);
        let end = u32::from(self.config.pool_end);

        for ip_num in start..=end {
            let ip = Ipv4Addr::from(ip_num);

            let is_static = self
                .config
                .static_bindings
                .iter()
                .any(|binding| binding.ip_address == ip);
            if is_static {
                continue;
            }

            if !store.ip_to_mac.contains_key(&ip) {
                return Ok(ip);
            }
        }

        Err(Error::PoolExhausted)
    }

    pub async fn create_lease(&self, mac_address: &str, ip_address: Ipv4Addr) -> Result<Lease> {
        if !self.config.ip_in_pool(ip_address) {
            let is_static = self
                .config
                .static_bindings
                .iter()
                .any(|binding| binding.ip_address == ip_address);
            if !is_static {
                return Err(Error::AddressOutOfRange(ip_address));
            }
        }

        let lease = Lease::new(
            ip_address,
            mac_address.to_string(),
            self.config.lease_duration_seconds,
        );

        let mut store = self.store.write().await;

        let old_ip_to_remove = store
            .leases
            .get(mac_address)
            .filter(|old_lease| old_lease.ip_address != ip_address)
            .map(|old_lease| old_lease.ip_address);

        if let Some(old_ip) = old_ip_to_remove {
            store.ip_to_mac.remove(&old_ip);
        }

        store.leases.insert(mac_address.to_string(), lease.clone());
        store.ip_to_mac.insert(ip_address, mac_address.to_string());

        drop(store);
        self.save().await?;

        Ok(lease)
    }

    pub async fn renew_lease(&self, mac_address: &str) -> Result<Lease> {
        let mut store = self.store.write().await;

        let lease = store
            .leases
            .get_mut(mac_address)
            .ok_or_else(|| Error::LeaseNotFound(mac_address.to_string()))?;

        lease.renew(self.config.lease_duration_seconds);
        let lease = lease.clone();

        drop(store);
        self.save().await?;

        Ok(lease)
    }

    pub async fn release_lease(&self, mac_address: &str) -> Result<()> {
        let mut store = self.store.write().await;

        if let Some(lease) = store.leases.remove(mac_address) {
            store.ip_to_mac.remove(&lease.ip_address);
        }

        drop(store);
        self.save().await?;

        Ok(())
    }

    pub async fn is_ip_available(&self, ip: Ipv4Addr, requesting_mac: &str) -> bool {
        let store = self.store.read().await;

        match store.ip_to_mac.get(&ip) {
            None => true,
            Some(mac) => mac.to_lowercase() == requesting_mac.to_lowercase(),
        }
    }

    pub async fn cleanup_expired_leases(&self) -> Result<usize> {
        let mut store = self.store.write().await;
        let count = self.cleanup_expired_leases_internal(&mut store);

        drop(store);
        self.save().await?;

        Ok(count)
    }

    fn cleanup_expired_leases_internal(&self, store: &mut LeaseStore) -> usize {
        let expired_macs: Vec<String> = store
            .leases
            .iter()
            .filter(|(_, lease)| lease.is_expired())
            .map(|(mac, _)| mac.clone())
            .collect();

        let count = expired_macs.len();

        for mac in expired_macs {
            if let Some(lease) = store.leases.remove(&mac) {
                store.ip_to_mac.remove(&lease.ip_address);
            }
        }

        count
    }

    pub async fn save(&self) -> Result<()> {
        let store = self.store.read().await;
        store.save(&self.leases_path)?;
        Ok(())
    }

    pub async fn list_leases(&self) -> Vec<Lease> {
        let store = self.store.read().await;
        store.leases.values().cloned().collect()
    }

    pub async fn active_lease_count(&self) -> usize {
        let store = self.store.read().await;
        store
            .leases
            .values()
            .filter(|lease| !lease.is_expired())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(test_name: &str) -> Config {
        Config {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 110),
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain_name: None,
            lease_duration_seconds: 3600,
            renewal_time_seconds: None,
            rebinding_time_seconds: None,
            broadcast_address: None,
            mtu: None,
            static_bindings: vec![],
            leases_file: format!("test_leases_{}.json", test_name),
            interface_index: None,
        }
    }

    #[test]
    fn test_lease_creation() {
        let lease = Lease::new(
            Ipv4Addr::new(192, 168, 1, 100),
            "aa:bb:cc:dd:ee:ff".to_string(),
            3600,
        );

        assert!(!lease.is_expired());
        assert!(lease.remaining_seconds() > 3500);
    }

    #[test]
    fn test_lease_expiration() {
        let mut lease = Lease::new(
            Ipv4Addr::new(192, 168, 1, 100),
            "aa:bb:cc:dd:ee:ff".to_string(),
            0,
        );

        lease.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(lease.is_expired());
    }

    #[tokio::test]
    async fn test_lease_manager_allocate() {
        let leases_file = "test_leases_allocate.json";
        let config = test_config("allocate");
        let manager = LeaseManager::new(config).unwrap();

        let ip1 = manager.allocate_ip("aa:bb:cc:dd:ee:01").await.unwrap();
        assert_eq!(ip1, Ipv4Addr::new(192, 168, 1, 100));

        manager
            .create_lease("aa:bb:cc:dd:ee:01", ip1)
            .await
            .unwrap();

        let ip2 = manager.allocate_ip("aa:bb:cc:dd:ee:02").await.unwrap();
        assert_eq!(ip2, Ipv4Addr::new(192, 168, 1, 101));

        let ip1_again = manager.allocate_ip("aa:bb:cc:dd:ee:01").await.unwrap();
        assert_eq!(ip1_again, ip1);

        let _ = std::fs::remove_file(leases_file);
    }

    #[tokio::test]
    async fn test_lease_manager_release() {
        let leases_file = "test_leases_release.json";
        let config = test_config("release");
        let manager = LeaseManager::new(config).unwrap();

        let ip = manager.allocate_ip("aa:bb:cc:dd:ee:ff").await.unwrap();
        manager.create_lease("aa:bb:cc:dd:ee:ff", ip).await.unwrap();

        assert!(manager.get_lease("aa:bb:cc:dd:ee:ff").await.is_some());

        manager.release_lease("aa:bb:cc:dd:ee:ff").await.unwrap();

        assert!(manager.get_lease("aa:bb:cc:dd:ee:ff").await.is_none());

        let _ = std::fs::remove_file(leases_file);
    }
}
