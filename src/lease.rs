//! DHCP lease management and persistence.
//!
//! This module handles IP address allocation, lease tracking, and persistence.
//! It implements the server-side lease state machine including:
//!
//! - IP allocation from the dynamic pool
//! - Static MAC-to-IP bindings
//! - Pending offer tracking (pre-lease reservations)
//! - Lease creation, renewal, and release
//! - Declined IP tracking
//! - Persistence to JSON files
//!
//! # Thread Safety
//!
//! All operations are thread-safe. The [`Leases`] struct uses:
//! - [`RwLock`] for the main state (allows concurrent reads)
//! - [`Mutex`] for file save operations (prevents corruption)

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::error::{Error, Result};

/// How long declined IPs remain unavailable (1 hour).
///
/// When a client sends DECLINE (indicating IP conflict), the IP is removed
/// from the pool for this duration to avoid repeatedly offering conflicting IPs.
const DECLINE_EXPIRATION_SECONDS: i64 = 3600;

/// How long a pending offer reserves an IP (60 seconds).
///
/// After DISCOVER, the server reserves an IP for this duration waiting for
/// the client's REQUEST. If no REQUEST arrives, the IP returns to the pool.
const OFFER_TIMEOUT_SECONDS: u64 = 60;

/// Minimum interval between lease file saves (5 seconds).
///
/// Prevents excessive disk I/O when handling many requests. The dirty flag
/// is checked and cleared on each save.
const SAVE_INTERVAL_MILLIS: u64 = 5000;

/// Encodes a client ID as a colon-separated hex string for storage.
fn encode_client_id(client_id: &[u8]) -> String {
    client_id
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(":")
}

/// An active DHCP lease.
///
/// Represents a binding between a client identifier and an IP address
/// with an expiration time. Leases are persisted to disk and restored
/// on server restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// The IP address assigned to this client.
    pub ip_address: Ipv4Addr,

    /// Unique client identifier (hex-encoded).
    ///
    /// Derived from DHCP Option 61 if present, otherwise from
    /// hardware type + hardware address.
    pub client_id: String,

    /// Client-provided hostname (Option 12), sanitized.
    pub hostname: Option<String>,

    /// When this lease expires (UTC).
    pub expires_at: DateTime<Utc>,

    /// When this lease was originally created (UTC).
    pub created_at: DateTime<Utc>,

    /// When the client last renewed or used this lease (UTC).
    pub last_seen: DateTime<Utc>,
}

impl Lease {
    /// Creates a new lease with the specified duration.
    ///
    /// Sets `created_at`, `last_seen`, and `expires_at` based on current time.
    pub fn new(ip_address: Ipv4Addr, client_id: String, duration_seconds: u32) -> Self {
        let now = Utc::now();
        Self {
            ip_address,
            client_id,
            hostname: None,
            expires_at: now + TimeDelta::seconds(duration_seconds as i64),
            created_at: now,
            last_seen: now,
        }
    }

    /// Returns true if the lease has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Renews the lease for the specified duration from now.
    ///
    /// Updates `expires_at` and `last_seen` to current time.
    pub fn renew(&mut self, duration_seconds: u32) {
        let now = Utc::now();
        self.expires_at = now + TimeDelta::seconds(duration_seconds as i64);
        self.last_seen = now;
    }

    /// Returns seconds remaining until expiration, or 0 if expired.
    pub fn remaining_seconds(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }
}

/// A pending IP offer awaiting client REQUEST.
#[derive(Debug, Clone)]
struct PendingOffer {
    ip: Ipv4Addr,
    expires_at: Instant,
}

/// Persistent lease storage format (serialized to JSON).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseStore {
    /// Active leases indexed by client ID.
    pub leases: HashMap<String, Lease>,
    /// Reverse lookup: IP address → client ID.
    pub ip_to_client: HashMap<Ipv4Addr, String>,
    /// IPs that were declined, with timestamp of decline.
    #[serde(default)]
    pub declined_ips: HashMap<Ipv4Addr, DateTime<Utc>>,
}

/// Internal mutable state protected by RwLock.
#[derive(Debug)]
struct InternalState {
    store: LeaseStore,
    /// Available IPs in the pool (sorted for deterministic allocation).
    free_ips: BTreeSet<Ipv4Addr>,
    /// Pending offers by client ID (not yet committed leases).
    pending_offers: HashMap<String, PendingOffer>,
    /// IPs currently in pending offers (for quick lookup).
    pending_ips: HashSet<Ipv4Addr>,
    /// Whether state has changed since last save.
    dirty: bool,
    /// When state was last saved to disk.
    last_save: Instant,
}

/// Thread-safe lease manager with persistence.
///
/// Handles all lease operations including allocation, creation, renewal,
/// release, and decline. State is automatically persisted to a JSON file.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use dhcplease::{Config, Leases};
///
/// # async fn example() -> dhcplease::Result<()> {
/// let config = Arc::new(Config::default());
/// let leases = Leases::new(config).await?;
///
/// let client_id = vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
/// let ip = leases.allocate_ip(&client_id).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Leases {
    state: Arc<RwLock<InternalState>>,
    config: Arc<Config>,
    leases_path: String,
    /// Static bindings: normalized client ID → IP.
    static_mac_to_ip: HashMap<String, Ipv4Addr>,
    /// Static bindings: IP → normalized client ID.
    static_ip_to_mac: HashMap<Ipv4Addr, String>,
    /// Mutex to prevent concurrent file writes.
    save_lock: Arc<Mutex<()>>,
}

impl Leases {
    /// Creates a new lease manager from the given configuration.
    ///
    /// Loads existing leases from the configured `leases_file` if it exists.
    /// Initializes the free IP pool by excluding leased and static-bound IPs.
    ///
    /// # Errors
    ///
    /// Returns an error if the lease file exists but cannot be read or parsed.
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let leases_path = config.leases_file.clone();
        let store = Self::load_store(&leases_path).await?;

        let mut static_mac_to_ip = HashMap::new();
        let mut static_ip_to_mac = HashMap::new();
        for binding in &config.static_bindings {
            let normalized = Self::normalize_static_mac(&binding.mac_address);
            static_mac_to_ip.insert(normalized.clone(), binding.ip_address);
            static_ip_to_mac.insert(binding.ip_address, normalized);
        }

        let mut free_ips = BTreeSet::new();
        let start = u32::from(config.pool_start);
        let end = u32::from(config.pool_end);
        for ip_num in start..=end {
            let ip = Ipv4Addr::from(ip_num);
            if !store.ip_to_client.contains_key(&ip) && !static_ip_to_mac.contains_key(&ip) {
                free_ips.insert(ip);
            }
        }

        let state = InternalState {
            store,
            free_ips,
            pending_offers: HashMap::new(),
            pending_ips: HashSet::new(),
            dirty: false,
            last_save: Instant::now(),
        };

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            config,
            leases_path,
            static_mac_to_ip,
            static_ip_to_mac,
            save_lock: Arc::new(Mutex::new(())),
        })
    }

    async fn load_store<P: AsRef<Path>>(path: P) -> Result<LeaseStore> {
        let path = path.as_ref();
        if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            let store: LeaseStore = serde_json::from_str(&content)?;
            Ok(store)
        } else {
            Ok(LeaseStore::default())
        }
    }

    fn normalize_static_mac(mac: &str) -> String {
        let mut id = vec![1u8];
        let normalized = mac.to_lowercase().replace('-', ":");
        for part in normalized.split(':') {
            if let Ok(byte) = u8::from_str_radix(part, 16) {
                id.push(byte);
            }
        }
        encode_client_id(&id)
    }

    fn client_id_to_static_key(client_id: &[u8]) -> Option<String> {
        if client_id.len() == 7 && client_id[0] == 1 {
            Some(encode_client_id(client_id))
        } else {
            None
        }
    }

    /// Returns the lease for a client, if one exists.
    pub async fn get_lease(&self, client_id: &[u8]) -> Option<Lease> {
        let key = encode_client_id(client_id);
        let state = self.state.read().await;
        state.store.leases.get(&key).cloned()
    }

    /// Returns the lease for an IP address, if one exists.
    pub async fn get_lease_by_ip(&self, ip: Ipv4Addr) -> Option<Lease> {
        let state = self.state.read().await;
        state
            .store
            .ip_to_client
            .get(&ip)
            .and_then(|client| state.store.leases.get(client).cloned())
    }

    /// Allocates an IP address for a client (DISCOVER handling).
    ///
    /// # Allocation Priority
    ///
    /// 1. Static binding for this client's MAC
    /// 2. Existing non-expired lease for this client
    /// 3. Existing pending offer for this client
    /// 4. First available IP from the free pool
    ///
    /// The returned IP is tracked as a pending offer for 60 seconds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PoolExhausted`] if no IPs are available.
    pub async fn allocate_ip(&self, client_id: &[u8]) -> Result<Ipv4Addr> {
        let key = encode_client_id(client_id);

        if let Some(static_key) = Self::client_id_to_static_key(client_id)
            && let Some(&ip) = self.static_mac_to_ip.get(&static_key)
        {
            return Ok(ip);
        }

        let mut state = self.state.write().await;

        self.cleanup_pending_offers(&mut state);

        if let Some(lease) = state.store.leases.get(&key)
            && !lease.is_expired()
            && self.config.ip_in_pool(lease.ip_address)
        {
            return Ok(lease.ip_address);
        }

        if let Some(offer) = state.pending_offers.get(&key)
            && offer.expires_at > Instant::now()
        {
            return Ok(offer.ip);
        }

        self.cleanup_expired_internal(&mut state);

        let now = Utc::now();
        let expired_declined: Vec<Ipv4Addr> = state
            .store
            .declined_ips
            .iter()
            .filter(|(_, declined_at)| {
                now.signed_duration_since(**declined_at).num_seconds() >= DECLINE_EXPIRATION_SECONDS
            })
            .map(|(ip, _)| *ip)
            .collect();

        for ip in expired_declined {
            state.store.declined_ips.remove(&ip);
            if self.config.ip_in_pool(ip) && !self.static_ip_to_mac.contains_key(&ip) {
                state.free_ips.insert(ip);
            }
        }

        for ip in state.free_ips.iter().copied() {
            if !state.store.declined_ips.contains_key(&ip) && !state.pending_ips.contains(&ip) {
                state.pending_offers.insert(
                    key,
                    PendingOffer {
                        ip,
                        expires_at: Instant::now() + Duration::from_secs(OFFER_TIMEOUT_SECONDS),
                    },
                );
                state.pending_ips.insert(ip);
                return Ok(ip);
            }
        }

        Err(Error::PoolExhausted)
    }

    fn cleanup_pending_offers(&self, state: &mut InternalState) {
        let now = Instant::now();
        let expired_ips: Vec<Ipv4Addr> = state
            .pending_offers
            .iter()
            .filter(|(_, offer)| offer.expires_at <= now)
            .map(|(_, offer)| offer.ip)
            .collect();
        for ip in expired_ips {
            state.pending_ips.remove(&ip);
        }
        state
            .pending_offers
            .retain(|_, offer| offer.expires_at > now);
    }

    /// Tracks a pending offer for a client (used when client requests specific IP).
    ///
    /// Replaces any existing pending offer for this client.
    pub async fn track_pending_offer(&self, client_id: &[u8], ip: Ipv4Addr) {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;
        if let Some(old_offer) = state.pending_offers.get(&key) {
            let old_ip = old_offer.ip;
            state.pending_ips.remove(&old_ip);
        }
        state.pending_offers.insert(
            key,
            PendingOffer {
                ip,
                expires_at: Instant::now() + Duration::from_secs(OFFER_TIMEOUT_SECONDS),
            },
        );
        state.pending_ips.insert(ip);
    }

    /// Creates or updates a lease (REQUEST/ACK handling).
    ///
    /// # Arguments
    ///
    /// * `client_id` - Unique client identifier
    /// * `ip_address` - IP address to lease
    /// * `hostname` - Optional client hostname
    /// * `duration_seconds` - Lease duration (uses config default if None)
    ///
    /// # Behavior
    ///
    /// - Validates IP is in pool or is a static binding for this client
    /// - Removes any pending offer for this client
    /// - If client had a different IP, releases the old one
    /// - Creates the lease and marks state dirty for persistence
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - IP is outside pool and not a static binding for this client
    /// - IP is already leased to a different client
    pub async fn create_lease(
        &self,
        client_id: &[u8],
        ip_address: Ipv4Addr,
        hostname: Option<String>,
        duration_seconds: Option<u32>,
    ) -> Result<Lease> {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;

        if !self.config.ip_in_pool(ip_address) {
            if let Some(static_key) = Self::client_id_to_static_key(client_id) {
                match self.static_ip_to_mac.get(&ip_address) {
                    Some(bound_key) if *bound_key == static_key => {}
                    Some(_) => {
                        return Err(Error::InvalidPacket(
                            "Static IP belongs to different MAC".to_string(),
                        ));
                    }
                    None => {
                        return Err(Error::AddressOutOfRange(ip_address));
                    }
                }
            } else {
                return Err(Error::AddressOutOfRange(ip_address));
            }
        }

        if let Some(existing_client) = state.store.ip_to_client.get(&ip_address)
            && *existing_client != key
            && let Some(existing_lease) = state.store.leases.get(existing_client)
            && !existing_lease.is_expired()
        {
            return Err(Error::InvalidPacket("IP already leased".to_string()));
        }

        if let Some(old_offer) = state.pending_offers.remove(&key) {
            state.pending_ips.remove(&old_offer.ip);
        }

        let duration = duration_seconds.unwrap_or(self.config.lease_duration_seconds);
        let mut lease = Lease::new(ip_address, key.clone(), duration);
        lease.hostname = hostname;

        let old_ip = state
            .store
            .leases
            .get(&key)
            .filter(|old| old.ip_address != ip_address)
            .map(|old| old.ip_address);

        if let Some(old_ip) = old_ip {
            state.store.ip_to_client.remove(&old_ip);
            if self.config.ip_in_pool(old_ip) && !self.static_ip_to_mac.contains_key(&old_ip) {
                state.free_ips.insert(old_ip);
            }
        }

        state.store.leases.insert(key.clone(), lease.clone());
        state.store.ip_to_client.insert(ip_address, key);
        state.free_ips.remove(&ip_address);
        state.dirty = true;

        self.maybe_save(&mut state).await?;

        Ok(lease)
    }

    /// Renews an existing lease.
    ///
    /// Updates the expiration time without changing the IP assignment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeaseNotFound`] if the client has no lease.
    pub async fn renew_lease(
        &self,
        client_id: &[u8],
        duration_seconds: Option<u32>,
    ) -> Result<Lease> {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;

        let lease = state
            .store
            .leases
            .get_mut(&key)
            .ok_or_else(|| Error::LeaseNotFound(key.clone()))?;

        let duration = duration_seconds.unwrap_or(self.config.lease_duration_seconds);
        lease.renew(duration);
        let lease = lease.clone();
        state.dirty = true;

        self.maybe_save(&mut state).await?;

        Ok(lease)
    }

    /// Releases a lease (RELEASE handling).
    ///
    /// The IP is returned to the free pool for reallocation.
    ///
    /// # Errors
    ///
    /// Returns an error if `ciaddr` doesn't match the client's leased IP.
    pub async fn release_lease(&self, client_id: &[u8], ciaddr: Ipv4Addr) -> Result<()> {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;

        if let Some(lease) = state.store.leases.get(&key)
            && lease.ip_address != ciaddr
        {
            return Err(Error::InvalidPacket(
                "RELEASE ciaddr does not match lease".to_string(),
            ));
        }

        if let Some(lease) = state.store.leases.remove(&key) {
            state.store.ip_to_client.remove(&lease.ip_address);
            if self.config.ip_in_pool(lease.ip_address)
                && !self.static_ip_to_mac.contains_key(&lease.ip_address)
            {
                state.free_ips.insert(lease.ip_address);
            }
            state.dirty = true;
        }

        self.maybe_save(&mut state).await?;

        Ok(())
    }

    /// Checks if an IP is available for a specific client.
    ///
    /// An IP is available if:
    /// - It's not declined (or decline has expired)
    /// - It's not pending for a different client
    /// - It's not leased to a different client (or is leased to this client)
    pub async fn is_ip_available(&self, ip: Ipv4Addr, client_id: &[u8]) -> bool {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;

        if let Some(declined_at) = state.store.declined_ips.get(&ip) {
            let now = Utc::now();
            if now.signed_duration_since(*declined_at).num_seconds() < DECLINE_EXPIRATION_SECONDS {
                return false;
            }
            state.store.declined_ips.remove(&ip);
            if self.config.ip_in_pool(ip) && !self.static_ip_to_mac.contains_key(&ip) {
                state.free_ips.insert(ip);
            }
        }

        let is_pending = state.pending_offers.iter().any(|(pending_key, offer)| {
            offer.ip == ip && *pending_key != key && offer.expires_at > Instant::now()
        });

        if is_pending {
            return false;
        }

        match state.store.ip_to_client.get(&ip) {
            None => true,
            Some(client) => *client == key,
        }
    }

    /// Marks an IP as declined (DECLINE handling).
    ///
    /// The IP is removed from the pool for 1 hour to avoid repeatedly
    /// offering an IP that may be in conflict.
    ///
    /// # Returns
    ///
    /// Returns `true` if the decline was accepted (IP was in pool or
    /// leased to this client), `false` otherwise.
    pub async fn decline_ip(&self, ip: Ipv4Addr, client_id: &[u8]) -> Result<bool> {
        let key = encode_client_id(client_id);
        let mut state = self.state.write().await;

        let can_decline = match state.store.ip_to_client.get(&ip) {
            None => self.config.ip_in_pool(ip),
            Some(leased_client) => *leased_client == key,
        };

        if !can_decline {
            return Ok(false);
        }

        state.store.declined_ips.insert(ip, Utc::now());
        state.free_ips.remove(&ip);

        let should_remove = state
            .store
            .leases
            .get(&key)
            .is_some_and(|lease| lease.ip_address == ip);

        if should_remove {
            state.store.leases.remove(&key);
            state.store.ip_to_client.remove(&ip);
        }

        state.dirty = true;
        self.maybe_save(&mut state).await?;

        Ok(true)
    }

    /// Removes all expired leases and returns their IPs to the pool.
    ///
    /// Returns the number of leases cleaned up.
    pub async fn cleanup_expired_leases(&self) -> Result<usize> {
        let mut state = self.state.write().await;
        let count = self.cleanup_expired_internal(&mut state);

        if count > 0 {
            state.dirty = true;
            drop(state);
            self.save().await?;
        }

        Ok(count)
    }

    fn cleanup_expired_internal(&self, state: &mut InternalState) -> usize {
        let expired_clients: Vec<String> = state
            .store
            .leases
            .iter()
            .filter(|(_, lease)| lease.is_expired())
            .map(|(client, _)| client.clone())
            .collect();

        let count = expired_clients.len();

        for client in expired_clients {
            if let Some(lease) = state.store.leases.remove(&client) {
                state.store.ip_to_client.remove(&lease.ip_address);
                if self.config.ip_in_pool(lease.ip_address)
                    && !self.static_ip_to_mac.contains_key(&lease.ip_address)
                {
                    state.free_ips.insert(lease.ip_address);
                }
            }
        }

        count
    }

    async fn maybe_save(&self, state: &mut InternalState) -> Result<()> {
        if state.dirty && state.last_save.elapsed().as_millis() >= SAVE_INTERVAL_MILLIS as u128 {
            let store_clone = state.store.clone();
            state.dirty = false;
            state.last_save = Instant::now();

            let _lock = self.save_lock.lock().await;
            let content = serde_json::to_string_pretty(&store_clone)?;
            tokio::fs::write(&self.leases_path, content).await?;
        }
        Ok(())
    }

    /// Forces an immediate save of the lease state to disk.
    pub async fn save(&self) -> Result<()> {
        let state = self.state.read().await;
        let store_clone = state.store.clone();
        drop(state);

        let _lock = self.save_lock.lock().await;
        let content = serde_json::to_string_pretty(&store_clone)?;
        tokio::fs::write(&self.leases_path, content).await?;

        let mut state = self.state.write().await;
        state.dirty = false;
        state.last_save = Instant::now();

        Ok(())
    }

    /// Returns all leases (including expired ones).
    pub async fn list_leases(&self) -> Vec<Lease> {
        let state = self.state.read().await;
        state.store.leases.values().cloned().collect()
    }

    /// Returns the count of non-expired leases.
    pub async fn active_lease_count(&self) -> usize {
        let state = self.state.read().await;
        state
            .store
            .leases
            .values()
            .filter(|lease| !lease.is_expired())
            .count()
    }

    /// Returns the count of available IPs in the pool.
    pub async fn free_ip_count(&self) -> usize {
        let state = self.state.read().await;
        state.free_ips.len()
    }

    /// Checks if a client has a static binding for the given IP.
    pub fn is_static_binding(&self, client_id: &[u8], ip: Ipv4Addr) -> bool {
        if let Some(static_key) = Self::client_id_to_static_key(client_id)
            && let Some(&bound_ip) = self.static_mac_to_ip.get(&static_key)
        {
            return bound_ip == ip;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticBinding;

    struct TestGuard(String);
    impl Drop for TestGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn test_config(name: &str) -> (Arc<Config>, TestGuard) {
        let path = format!("test_leases_{}.json", name);
        (
            Arc::new(Config {
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
                leases_file: path.clone(),
                interface_index: None,
            }),
            TestGuard(path),
        )
    }

    fn make_client_id(mac: &[u8; 6]) -> Vec<u8> {
        let mut id = vec![1u8];
        id.extend_from_slice(mac);
        id
    }

    #[test]
    fn test_lease_struct() {
        let lease = Lease::new(Ipv4Addr::new(192, 168, 1, 100), "test".to_string(), 3600);
        assert!(!lease.is_expired());
        assert!(lease.remaining_seconds() > 3500);

        let mut expired = Lease::new(Ipv4Addr::new(192, 168, 1, 100), "test".to_string(), 0);
        expired.expires_at = Utc::now() - TimeDelta::seconds(1);
        assert!(expired.is_expired());

        let mut renewable = Lease::new(Ipv4Addr::new(192, 168, 1, 100), "test".to_string(), 100);
        renewable.renew(7200);
        assert!(renewable.remaining_seconds() > 7100);
    }

    #[tokio::test]
    async fn test_lease_lifecycle() {
        let (config, _guard) = test_config("lifecycle");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));

        let lease = manager
            .create_lease(&client_id, ip, Some("test-host".to_string()), None)
            .await
            .unwrap();
        assert_eq!(lease.hostname, Some("test-host".to_string()));

        assert!(manager.get_lease(&client_id).await.is_some());
        assert!(manager.get_lease_by_ip(ip).await.is_some());
        assert_eq!(manager.active_lease_count().await, 1);

        let renewed = manager.renew_lease(&client_id, None).await.unwrap();
        assert_eq!(renewed.ip_address, ip);

        manager.release_lease(&client_id, ip).await.unwrap();
        assert!(manager.get_lease(&client_id).await.is_none());
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let (config, _guard) = test_config("allocation");
        let manager = Leases::new(config).await.unwrap();
        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

        let ip1 = manager.allocate_ip(&client1).await.unwrap();
        manager.create_lease(&client1, ip1, None, None).await.unwrap();

        let ip2 = manager.allocate_ip(&client2).await.unwrap();
        assert_ne!(ip1, ip2);

        let ip1_again = manager.allocate_ip(&client1).await.unwrap();
        assert_eq!(ip1, ip1_again);
    }

    #[tokio::test]
    async fn test_decline_and_availability() {
        let (config, _guard) = test_config("decline");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert!(manager.is_ip_available(ip, &client_id).await);

        assert!(manager.decline_ip(ip, &client_id).await.unwrap());
        assert!(!manager.is_ip_available(ip, &client_id).await);

        let allocated = manager.allocate_ip(&client_id).await.unwrap();
        assert_eq!(allocated, Ipv4Addr::new(192, 168, 1, 101));
    }

    #[tokio::test]
    async fn test_static_binding() {
        let path = "test_leases_static.json".to_string();
        let _guard = TestGuard(path.clone());
        let config = Arc::new(Config {
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
            static_bindings: vec![StaticBinding {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ip_address: Ipv4Addr::new(192, 168, 1, 50),
                hostname: None,
            }],
            leases_file: path,
            interface_index: None,
        });
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[tokio::test]
    async fn test_offer_tracking() {
        let (config, _guard) = test_config("offers");
        let manager = Leases::new(config).await.unwrap();
        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

        let ip1 = manager.allocate_ip(&client1).await.unwrap();
        let ip2 = manager.allocate_ip(&client2).await.unwrap();

        assert_ne!(ip1, ip2);
    }

    #[tokio::test]
    async fn test_concurrent_allocations() {
        let (config, _guard) = test_config("concurrent");
        let leases = Arc::new(Leases::new(config).await.unwrap());

        let mut handles = vec![];
        for index in 0..5 {
            let leases_clone = Arc::clone(&leases);
            let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, index]);
            handles.push(tokio::spawn(async move {
                let ip = leases_clone.allocate_ip(&client_id).await?;
                leases_clone.create_lease(&client_id, ip, None, None).await?;
                Ok::<_, crate::error::Error>(ip)
            }));
        }

        let mut allocated_ips = std::collections::HashSet::new();
        for handle in handles {
            let ip = handle.await.unwrap().unwrap();
            assert!(allocated_ips.insert(ip), "Duplicate IP allocated: {}", ip);
        }

        assert_eq!(allocated_ips.len(), 5);
    }

    #[tokio::test]
    async fn test_concurrent_create_and_release() {
        let (config, _guard) = test_config("concurrent_cr");
        let leases = Arc::new(Leases::new(config).await.unwrap());
        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

        let ip = leases.allocate_ip(&client1).await.unwrap();
        leases.create_lease(&client1, ip, None, None).await.unwrap();

        let leases_clone = Arc::clone(&leases);
        let client1_clone = client1.clone();
        let release_handle =
            tokio::spawn(async move { leases_clone.release_lease(&client1_clone, ip).await });

        let allocate_handle = {
            let leases_clone = Arc::clone(&leases);
            tokio::spawn(async move { leases_clone.allocate_ip(&client2).await })
        };

        release_handle.await.unwrap().unwrap();
        let ip2 = allocate_handle.await.unwrap().unwrap();
        assert!(ip2 >= Ipv4Addr::new(192, 168, 1, 100) && ip2 <= Ipv4Addr::new(192, 168, 1, 110));
    }

    #[tokio::test]
    async fn test_free_ip_tracking() {
        let (config, _guard) = test_config("free_ips");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert_eq!(manager.free_ip_count().await, 11);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip, None, None).await.unwrap();

        assert_eq!(manager.free_ip_count().await, 10);

        manager.release_lease(&client_id, ip).await.unwrap();

        assert_eq!(manager.free_ip_count().await, 11);
    }

    #[tokio::test]
    async fn test_release_mismatched_ciaddr() {
        let (config, _guard) = test_config("release_mismatch");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip, None, None).await.unwrap();

        let wrong_ip = Ipv4Addr::new(192, 168, 1, 200);
        let result = manager.release_lease(&client_id, wrong_ip).await;
        assert!(result.is_err());

        let lease = manager.get_lease(&client_id).await;
        assert!(lease.is_some());
    }

    #[tokio::test]
    async fn test_static_binding_wrong_mac() {
        let path = "test_leases_static_wrong_mac.json".to_string();
        let _guard = TestGuard(path.clone());

        let config = Arc::new(Config {
            static_bindings: vec![StaticBinding {
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ip_address: Ipv4Addr::new(192, 168, 1, 50),
                hostname: None,
            }],
            leases_file: path,
            ..Config {
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
                leases_file: String::new(),
                interface_index: None,
            }
        });

        let manager = Leases::new(config).await.unwrap();

        let wrong_client = make_client_id(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let static_ip = Ipv4Addr::new(192, 168, 1, 50);

        let result = manager.create_lease(&wrong_client, static_ip, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_lease_persistence() {
        let path = "test_leases_persist.json".to_string();
        let _guard = TestGuard(path.clone());

        let config = Arc::new(Config {
            leases_file: path.clone(),
            ..Config {
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
                leases_file: String::new(),
                interface_index: None,
            }
        });

        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let ip;

        {
            let manager = Leases::new(Arc::clone(&config)).await.unwrap();
            ip = manager.allocate_ip(&client_id).await.unwrap();
            manager
                .create_lease(&client_id, ip, Some("persist-test".to_string()), None)
                .await
                .unwrap();
            manager.save().await.unwrap();
        }

        {
            let manager = Leases::new(Arc::clone(&config)).await.unwrap();
            let lease = manager.get_lease(&client_id).await;
            assert!(lease.is_some());
            let lease = lease.unwrap();
            assert_eq!(lease.ip_address, ip);
            assert_eq!(lease.hostname, Some("persist-test".to_string()));
        }
    }

    #[tokio::test]
    async fn test_expired_lease_cleanup() {
        let (config, _guard) = test_config("cleanup");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip, None, None).await.unwrap();

        {
            let mut state = manager.state.write().await;
            if let Some(lease) = state.store.leases.get_mut(&encode_client_id(&client_id)) {
                lease.expires_at = Utc::now() - TimeDelta::seconds(1);
            }
        }

        let count = manager.cleanup_expired_leases().await.unwrap();
        assert_eq!(count, 1);

        let lease = manager.get_lease(&client_id).await;
        assert!(lease.is_none());

        assert_eq!(manager.free_ip_count().await, 11);
    }

    #[tokio::test]
    async fn test_ip_already_leased_to_different_client() {
        let (config, _guard) = test_config("already_leased");
        let manager = Leases::new(config).await.unwrap();

        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

        let ip = manager.allocate_ip(&client1).await.unwrap();
        manager.create_lease(&client1, ip, None, None).await.unwrap();

        let result = manager.create_lease(&client2, ip, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_can_renew_same_ip() {
        let (config, _guard) = test_config("renew_same");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip, None, None).await.unwrap();

        let result = manager.create_lease(&client_id, ip, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_changes_ip() {
        let (config, _guard) = test_config("change_ip");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip1 = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip1, None, None).await.unwrap();

        let ip2 = Ipv4Addr::new(192, 168, 1, 105);
        manager.create_lease(&client_id, ip2, None, None).await.unwrap();

        let lease = manager.get_lease(&client_id).await.unwrap();
        assert_eq!(lease.ip_address, ip2);

        assert!(manager.is_ip_available(ip1, &client_id).await);
    }

    #[tokio::test]
    async fn test_pool_exhaustion() {
        let path = "test_leases_exhaustion.json".to_string();
        let _guard = TestGuard(path.clone());

        let config = Arc::new(Config {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 101),
            leases_file: path,
            ..Config {
                server_ip: Ipv4Addr::new(192, 168, 1, 1),
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                pool_start: Ipv4Addr::new(192, 168, 1, 100),
                pool_end: Ipv4Addr::new(192, 168, 1, 101),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                domain_name: None,
                lease_duration_seconds: 3600,
                renewal_time_seconds: None,
                rebinding_time_seconds: None,
                broadcast_address: None,
                mtu: None,
                static_bindings: vec![],
                leases_file: String::new(),
                interface_index: None,
            }
        });

        let manager = Leases::new(config).await.unwrap();

        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
        let client3 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03]);

        let ip1 = manager.allocate_ip(&client1).await.unwrap();
        manager.create_lease(&client1, ip1, None, None).await.unwrap();

        let ip2 = manager.allocate_ip(&client2).await.unwrap();
        manager.create_lease(&client2, ip2, None, None).await.unwrap();

        let result = manager.allocate_ip(&client3).await;
        assert!(matches!(result, Err(crate::error::Error::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_get_lease_by_ip() {
        let (config, _guard) = test_config("get_by_ip");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager
            .create_lease(&client_id, ip, Some("test-host".to_string()), None)
            .await
            .unwrap();

        let lease = manager.get_lease_by_ip(ip).await;
        assert!(lease.is_some());
        assert_eq!(lease.unwrap().hostname, Some("test-host".to_string()));

        let no_lease = manager
            .get_lease_by_ip(Ipv4Addr::new(192, 168, 1, 200))
            .await;
        assert!(no_lease.is_none());
    }

    #[tokio::test]
    async fn test_renew_nonexistent_lease() {
        let (config, _guard) = test_config("renew_none");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let result = manager.renew_lease(&client_id, None).await;
        assert!(matches!(result, Err(crate::error::Error::LeaseNotFound(_))));
    }

    #[tokio::test]
    async fn test_decline_ip_not_in_pool() {
        let (config, _guard) = test_config("decline_not_pool");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let outside_pool = Ipv4Addr::new(10, 0, 0, 1);
        let result = manager.decline_ip(outside_pool, &client_id).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_list_leases() {
        let (config, _guard) = test_config("list");
        let manager = Leases::new(config).await.unwrap();

        let client1 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let client2 = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

        let ip1 = manager.allocate_ip(&client1).await.unwrap();
        manager.create_lease(&client1, ip1, None, None).await.unwrap();

        let ip2 = manager.allocate_ip(&client2).await.unwrap();
        manager.create_lease(&client2, ip2, None, None).await.unwrap();

        let leases = manager.list_leases().await;
        assert_eq!(leases.len(), 2);
    }

    #[tokio::test]
    async fn test_active_lease_count() {
        let (config, _guard) = test_config("active_count");
        let manager = Leases::new(config).await.unwrap();
        let client_id = make_client_id(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert_eq!(manager.active_lease_count().await, 0);

        let ip = manager.allocate_ip(&client_id).await.unwrap();
        manager.create_lease(&client_id, ip, None, None).await.unwrap();

        assert_eq!(manager.active_lease_count().await, 1);
    }
}
