# Architecture

This document describes the internal architecture of dhcplease, a DHCP server implementation in Rust.

## Overview

dhcplease is structured as a single-threaded async server using Tokio. It listens on UDP port 67, parses incoming DHCP packets, processes them according to RFC 2131/2132, and sends appropriate responses. The server maintains lease state in memory with periodic persistence to a JSON file.

```mermaid
flowchart TB
    subgraph DhcpServer
        Socket["Socket<br/>(UDP:67)"]
        Config["Config<br/>(Arc)"]
        Leases["Leases<br/>(Arc)"]
        RateLimiter["RateLimiter<br/>(Arc)"]

        subgraph PacketHandler
            Parse["Parse packets"]
            Dispatch["Dispatch by message type"]
            Build["Build responses"]
        end

        Socket --> PacketHandler
        Leases --> PacketHandler
    end
```

## Module Structure

```
src/
├── main.rs      # CLI entry point, argument parsing
├── lib.rs       # Public API exports
├── server.rs    # DHCP server and packet handling
├── config.rs    # Configuration loading and validation
├── lease.rs     # Lease management and persistence
├── packet.rs    # DHCP packet parsing and encoding
├── options.rs   # DHCP option parsing and encoding
└── error.rs     # Error types
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `server` | Main event loop, packet dispatch, response building |
| `config` | Load/save JSON config, validation, static bindings |
| `lease` | IP allocation, lease CRUD, persistence, thread safety |
| `packet` | Parse/encode 236-byte DHCP header + options |
| `options` | Parse/encode individual DHCP options (TLV format) |
| `error` | `Error` enum and `Result` type alias |

## Packet Flow

### Receive Path

```mermaid
flowchart TD
    A[UDP Socket<br/>port 67] --> B[DhcpServer::run<br/>main event loop]
    B -->|recv_from| C[tokio::spawn<br/>task per packet]
    C --> D[PacketHandler::<br/>handle_packet]
    D --> E[DhcpPacket::parse<br/>fixed header + options]
    E --> F[Rate limit check<br/>10 req/MAC/sec]
    F --> G{Message type<br/>Option 53}
    G --> H[DISCOVER]
    G --> I[REQUEST]
    G --> J[RELEASE]
    G --> K[DECLINE]
    G --> L[INFORM]
```

### DORA Flow

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: DISCOVER (broadcast from 0.0.0.0:68)
    Note over Server: 1. allocate_ip() - reserve from pool<br/>2. track_pending_offer() - 60s hold<br/>3. build_offer_options()
    Server->>Client: OFFER (broadcast or unicast)

    Client->>Server: REQUEST (broadcast, server_id)
    Note over Server: 1. Verify server_id matches<br/>2. create_lease() - commit to store<br/>3. Clear pending offer
    Server->>Client: ACK (full configuration)
```

### Response Destination Logic

```mermaid
flowchart TD
    A[Send Reply] --> B{giaddr != 0?}
    B -->|Yes| C[Send to giaddr:67<br/>relay agent]
    B -->|No| D{Is NAK?}
    D -->|Yes| E[Broadcast<br/>255.255.255.255:68]
    D -->|No| F{Broadcast flag?}
    F -->|Yes| E
    F -->|No| G{ciaddr == 0?}
    G -->|Yes| E
    G -->|No| H[Unicast to ciaddr:68]
```

## Data Structures

### DhcpPacket

Represents the wire format of a DHCP message (RFC 2131 §2):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr (4)                           |
+---------------------------------------------------------------+
|                          yiaddr (4)                           |
+---------------------------------------------------------------+
|                          siaddr (4)                           |
+---------------------------------------------------------------+
|                          giaddr (4)                           |
+---------------------------------------------------------------+
|                          chaddr (16)                          |
+---------------------------------------------------------------+
|                          sname (64)                           |
+---------------------------------------------------------------+
|                          file (128)                           |
+---------------------------------------------------------------+
|                    magic cookie (4) = 99.130.83.99            |
+---------------------------------------------------------------+
|                          options (variable)                   |
+---------------------------------------------------------------+
```

Key fields:
- `op`: 1 = BOOTREQUEST (client), 2 = BOOTREPLY (server)
- `xid`: Transaction ID, echoed in replies
- `ciaddr`: Client's current IP (used in RENEWING/REBINDING)
- `yiaddr`: "Your" IP - the address being assigned
- `giaddr`: Relay agent IP (non-zero if relayed)
- `chaddr`: Client hardware address (MAC)
- `flags`: Bit 15 = broadcast flag

### DhcpOption

Options use TLV (Type-Length-Value) encoding:

```
+--------+--------+--------+--------+
|  Code  | Length |       Data      |
+--------+--------+--------+--------+
   1 byte  1 byte   Length bytes
```

Special cases:
- Code 0 (Pad): No length/data, used for alignment
- Code 255 (End): No length/data, terminates options

Implemented options:

| Code | Name | Purpose |
|------|------|---------|
| 1 | Subnet Mask | Network mask for client |
| 3 | Router | Default gateway(s) |
| 6 | DNS Server | DNS server address(es) |
| 12 | Hostname | Client's hostname |
| 15 | Domain Name | DNS domain suffix |
| 26 | Interface MTU | Maximum transmission unit |
| 28 | Broadcast Address | Subnet broadcast address |
| 50 | Requested IP | Client's preferred IP |
| 51 | Lease Time | Lease duration in seconds |
| 52 | Option Overload | sname/file contain options |
| 53 | Message Type | DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE/DECLINE/INFORM |
| 54 | Server Identifier | DHCP server's IP |
| 55 | Parameter Request List | Options client wants |
| 58 | Renewal Time (T1) | When to start unicast renewal |
| 59 | Rebinding Time (T2) | When to start broadcast renewal |
| 61 | Client Identifier | Unique client ID (overrides chaddr) |
| 82 | Relay Agent Info | Added by relay, must be echoed |

### Lease

```rust
struct Lease {
    ip_address: Ipv4Addr,      // Assigned IP
    client_id: String,          // Hex-encoded client identifier
    hostname: Option<String>,   // From Option 12
    expires_at: DateTime<Utc>,  // When lease expires
    created_at: DateTime<Utc>,  // Original creation time
    last_seen: DateTime<Utc>,   // Last renewal/activity
}
```

### LeaseStore (Persisted State)

```rust
struct LeaseStore {
    leases: HashMap<String, Lease>,           // client_id → Lease
    ip_to_client: HashMap<Ipv4Addr, String>,  // Reverse lookup
    declined_ips: HashMap<Ipv4Addr, DateTime<Utc>>,  // Conflict tracking
}
```

### InternalState (Runtime State)

```rust
struct InternalState {
    store: LeaseStore,                              // Persisted data
    free_ips: BTreeSet<Ipv4Addr>,                   // Available pool IPs
    pending_offers: HashMap<String, PendingOffer>,  // Pre-lease reservations
    pending_ips: HashSet<Ipv4Addr>,                 // IPs in pending offers
    dirty: bool,                                    // Needs persistence
    last_save: Instant,                             // Rate limit saves
}
```

## Thread Safety Model

The server uses a "spawn per packet" model with shared state protected by async locks:

```mermaid
flowchart TB
    subgraph DhcpServer
        Config["config: Arc &lt;Config&gt;<br/>Immutable"]
        Leases["leases: Arc&lt;Leases&gt;<br/>Interior mutability"]
        Socket["socket: Arc&lt;UdpSocket&gt;<br/>Thread-safe"]
        Rate["rate_limiter: Arc&lt;Mutex&gt;<br/>Per-MAC tracking"]
    end

    DhcpServer --> Task1["Task 1<br/>(Packet)"]
    DhcpServer --> Task2["Task 2<br/>(Packet)"]
    DhcpServer --> Task3["Task 3<br/>(Packet)"]
```

### Lock Strategy

| Resource | Lock Type | Reason |
|----------|-----------|--------|
| `InternalState` | `RwLock` | Allows concurrent reads (get_lease, list_leases) |
| `rate_limiter` | `Mutex` | Simple map, no read-heavy workload |
| `save_lock` | `Mutex` | Prevents concurrent file writes |

### Lock Ordering

To prevent deadlocks, locks are always acquired in this order:
1. `state` (RwLock)
2. `save_lock` (Mutex) - only held during file I/O

The `rate_limiter` is independent and never held while acquiring other locks.

## IP Allocation Algorithm

```mermaid
flowchart TD
    A[allocate_ip] --> B{Static binding<br/>for this MAC?}
    B -->|Yes| C[Return static IP]
    B -->|No| D{Existing<br/>non-expired lease?}
    D -->|Yes| E[Return leased IP]
    D -->|No| F{Pending offer<br/>for this client?}
    F -->|Yes| G[Return pending IP]
    F -->|No| H[Cleanup expired leases]
    H --> I[Cleanup expired<br/>declined IPs]
    I --> J{Free IP<br/>available?}
    J -->|Yes| K[Track as pending<br/>60 second hold]
    K --> L[Return IP]
    J -->|No| M[Error: Pool Exhausted]
```

### Pending Offer Lifecycle

```mermaid
flowchart TD
    A[DISCOVER received] --> B[allocate_ip creates<br/>pending offer 60s TTL]
    B --> C{What happens next?}
    C -->|REQUEST received| D[create_lease<br/>clears pending]
    C -->|Timeout 60s| E[IP returned<br/>to free pool]
```

## Lease Persistence

### Write Strategy

To avoid excessive disk I/O:
1. State is marked `dirty` on any mutation
2. Saves are rate-limited to every 5 seconds minimum
3. `maybe_save()` checks both conditions before writing

```rust
async fn maybe_save(state: &mut InternalState) {
    if state.dirty && state.last_save.elapsed() >= 5 seconds {
        // Serialize and write
        state.dirty = false;
        state.last_save = Instant::now();
    }
}
```

### File Format

```json
{
  "leases": {
    "01:aa:bb:cc:dd:ee:ff": {
      "ip_address": "192.168.1.100",
      "client_id": "01:aa:bb:cc:dd:ee:ff",
      "hostname": "client-pc",
      "expires_at": "2024-01-15T12:00:00Z",
      "created_at": "2024-01-14T12:00:00Z",
      "last_seen": "2024-01-14T18:00:00Z"
    }
  },
  "ip_to_client": {
    "192.168.1.100": "01:aa:bb:cc:dd:ee:ff"
  },
  "declined_ips": {
    "192.168.1.105": "2024-01-14T10:00:00Z"
  }
}
```

### Recovery on Startup

```mermaid
flowchart TD
    A[Server starts] --> B[Load leases.json]
    B --> C[Build free_ips set]
    C --> D["Start with all IPs in<br/>[pool_start, pool_end]"]
    D --> E[Remove IPs in ip_to_client<br/>active leases]
    E --> F[Remove IPs in static_ip_to_mac<br/>reserved]
    F --> G[Ready to serve]
```

## Rate Limiting

Protects against DHCP starvation attacks and misbehaving clients.

**Configuration:**
- Window: 1 second
- Max requests: 10 per MAC per window
- Cleanup threshold: 1000 tracked MACs

```mermaid
flowchart TD
    A[is_rate_limited] --> B{Tracking > 1000 MACs?}
    B -->|Yes| C[Remove stale entries]
    B -->|No| D[Get timestamps for MAC]
    C --> D
    D --> E[Filter to last 1 second]
    E --> F{Count >= 10?}
    F -->|Yes| G[Return true<br/>rate limited]
    F -->|No| H[Add current timestamp]
    H --> I[Return false<br/>allowed]
```

## DHCP Relay Support

When a relay agent forwards a packet, it sets `giaddr` to its own IP and may add Option 82.

### Relay Detection

```rust
if request.giaddr != Ipv4Addr::UNSPECIFIED {
    // This is a relayed packet
    // - Reply to giaddr:67 (relay agent)
    // - Echo Option 82 if present
}
```

### Option 82 Handling

```mermaid
flowchart LR
    subgraph Incoming
        A["Option 82<br/>(Relay Agent Info)"]
        A --- B["Circuit ID"]
        A --- C["Remote ID"]
    end

    Incoming -->|Preserved as<br/>raw bytes| Outgoing

    subgraph Outgoing
        D["Option 82<br/>(echoed verbatim)"]
    end
```

## Message Type Handlers

### DISCOVER → OFFER

```mermaid
flowchart TD
    A[handle_discover] --> B[Extract client_id<br/>Option 61 or htype+chaddr]
    B --> C{Requested IP<br/>Option 50?}
    C -->|Valid & available| D[Use requested IP]
    C -->|Otherwise| E[allocate_ip]
    D --> F[Build options]
    E --> F
    F --> G["Server ID, Lease Time,<br/>Subnet, Router, DNS,<br/>Domain, Broadcast,<br/>T1=lease/2, T2=lease*7/8,<br/>MTU if configured"]
    G --> H[Filter by Parameter<br/>Request List]
    H --> I{Option 82<br/>present?}
    I -->|Yes| J[Echo it]
    I -->|No| K[Send OFFER]
    J --> K
```

### REQUEST → ACK/NAK

```mermaid
flowchart TD
    A[handle_request] --> B{Server ID<br/>Option 54}
    B -->|Present but not us| C[Ignore<br/>client chose other server]
    B -->|Matches or absent| D[Get requested IP<br/>Option 50 or ciaddr]
    D --> E{IP in pool or<br/>static binding?}
    E -->|No| F[Send NAK]
    E -->|Yes| G[Negotiate lease time<br/>clamp to 60s - max]
    G --> H[Create or renew lease]
    H --> I[Build options]
    I --> J[Send ACK]
```

### RELEASE

```mermaid
flowchart TD
    A[handle_release] --> B{ciaddr matches<br/>client's lease?}
    B -->|No| C[Error]
    B -->|Yes| D[Remove lease from store]
    D --> E[Return IP to free pool]
    E --> F[Mark state dirty]
```

### DECLINE

```mermaid
flowchart TD
    A[handle_decline] --> B[Get declined IP<br/>from Option 50]
    B --> C{Client had rights<br/>to this IP?}
    C -->|No| D[Reject]
    C -->|Yes| E[Add IP to declined_ips]
    E --> F[Remove from free pool]
    F --> G[Remove client's lease]
    G --> H[IP unavailable<br/>for 1 hour]
```

### INFORM

```mermaid
flowchart TD
    A[handle_inform] --> B[Client already has IP<br/>via static config]
    B --> C[Build config options<br/>no lease time]
    C --> D[Send ACK with<br/>configuration only]
```

## Configuration

### Static Bindings

```json
{
  "static_bindings": [
    {
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "ip_address": "192.168.1.50",
      "hostname": "printer"
    }
  ]
}
```

Static bindings:
- Always return the same IP for the MAC
- IP can be outside the dynamic pool
- Still go through DORA (client must request)
- Create normal leases (for tracking)

### Interface Binding (Windows)

```json
{
  "interface_index": 12
}
```

Uses `setsockopt(IP_UNICAST_IF)` to bind to a specific network adapter, preventing responses from going out the wrong interface on multi-homed systems.

## Error Handling

```rust
enum Error {
    InvalidPacket(String),     // Malformed DHCP packet
    InvalidConfig(String),     // Bad configuration
    PoolExhausted,             // No IPs available
    AddressOutOfRange(Ipv4Addr), // IP not in pool
    LeaseNotFound(String),     // No lease for client
    Io(std::io::Error),        // File/network I/O
    Json(serde_json::Error),   // Config/lease parsing
    Socket(String),            // Socket setup
}
```

### Error Recovery

| Error | Recovery |
|-------|----------|
| Invalid packet | Log warning, ignore packet |
| Pool exhausted | Log warning, no response (client retries) |
| I/O error on receive | Log error, continue listening |
| I/O error on send | Log warning, continue |
| Lease file corrupt | Fail startup (manual intervention needed) |

## Performance Characteristics

### Memory Usage

- ~100 bytes per active lease
- ~50 bytes per pending offer
- ~24 bytes per tracked MAC (rate limiting)
- O(pool_size) for free_ips set

### Scalability

| Operation | Complexity |
|-----------|------------|
| Packet parsing | O(options) |
| IP allocation | O(1) average, O(pool) worst case |
| Lease lookup | O(1) hash lookup |
| Lease creation | O(1) |
| File save | O(leases) |

### Bottlenecks

1. **Single file persistence**: All leases in one JSON file
2. **Save rate limiting**: 5 second minimum between writes
3. **Lock contention**: RwLock on state for all operations

For most deployments (< 10,000 clients), these are not limiting factors.
