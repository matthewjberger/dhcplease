# DHCP Sequence Diagrams

## Full Lease Lifecycle

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Leases

    Note over Client: Needs IP address

    Client->>Server: DISCOVER (broadcast from 0.0.0.0)
    Server->>Leases: allocate_ip(client_id)
    Leases-->>Server: 192.168.1.100 (pending 60s)
    Server->>Client: OFFER (yiaddr=192.168.1.100, T1, T2, options)

    Client->>Server: REQUEST (server_id, requested_ip)
    Server->>Leases: create_lease(client_id, ip)
    Leases-->>Server: lease committed
    Server->>Client: ACK (full configuration)

    Note over Client: Uses network with leased IP

    Note over Client: T1 timer (50%) expires
    Client->>Server: REQUEST (unicast renewal)
    Server->>Leases: renew_lease(client_id)
    Leases-->>Server: lease extended
    Server->>Client: ACK (lease renewed)

    Note over Client: Done with IP

    Client->>Server: RELEASE (ciaddr)
    Server->>Leases: release_lease(client_id)
    Leases-->>Server: IP returned to pool
```

## DISCOVER → OFFER Detail

```mermaid
sequenceDiagram
    participant Client
    participant RateLimiter
    participant Parser
    participant Handler
    participant Leases

    Client->>RateLimiter: UDP packet (port 67)
    RateLimiter->>RateLimiter: check(mac) < 10/sec?
    RateLimiter->>Parser: OK

    Parser->>Parser: DhcpPacket::parse()
    Note over Parser: Validate magic cookie<br/>Extract header fields<br/>Decode options (TLV)

    Parser->>Handler: msg_type = DISCOVER

    Handler->>Leases: allocate_ip(client_id)
    Note over Leases: 1. Check static binding<br/>2. Check existing lease<br/>3. Check pending offer<br/>4. Find first free IP<br/>5. Track pending (60s)
    Leases-->>Handler: 192.168.1.100

    Handler->>Handler: build_offer_options()
    Note over Handler: subnet, gateway, dns,<br/>lease time, T1, T2,<br/>server_id, broadcast

    Handler->>Client: OFFER packet
```

## REQUEST → ACK/NAK

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Leases

    Client->>Server: REQUEST (server_id, requested_ip)

    alt Server ID doesn't match us
        Note over Server: Ignore (client chose different server)
    else Server ID matches
        Server->>Server: Validate requested IP

        alt IP not in pool and not static binding
            Server->>Client: NAK
            Note over Client: Must restart DORA
        else IP valid
            Server->>Server: negotiate_lease_time()
            Server->>Leases: create_lease(client_id, ip, duration)

            alt IP already leased to different client
                Leases-->>Server: Error
                Server->>Client: NAK
            else Success
                Leases-->>Server: lease committed
                Server->>Client: ACK (full config)
            end
        end
    end
```

## Relay Agent Flow

```mermaid
sequenceDiagram
    participant Client
    participant Relay
    participant Server

    Client->>Relay: DISCOVER (broadcast)

    Note over Relay: Sets giaddr=192.168.2.1<br/>Adds Option 82 (circuit info)

    Relay->>Server: DISCOVER (unicast to server)

    Note over Server: Sees giaddr is set<br/>Allocates from correct subnet<br/>Will echo Option 82

    Server->>Relay: OFFER (dst=giaddr:67, Option 82 echoed)
    Relay->>Client: OFFER (broadcast/unicast)

    Client->>Relay: REQUEST (broadcast)
    Relay->>Server: REQUEST (unicast, giaddr, Option 82)
    Server->>Relay: ACK (dst=giaddr:67)
    Relay->>Client: ACK
```

## T2 Rebinding (Primary Server Down)

```mermaid
sequenceDiagram
    participant Client
    participant ServerA as Server A (primary)
    participant ServerB as Server B (backup)

    Note over Client: Has lease from Server A

    Note over Client: T1 (50%) - attempt renewal
    Client->>ServerA: REQUEST (unicast)

    Note over ServerA: Server down/unreachable

    Note over Client: No response... timeout

    Note over Client: T2 (87.5%) - attempt rebind
    Client->>ServerA: REQUEST (broadcast)
    Client->>ServerB: REQUEST (broadcast)

    Note over ServerB: Can respond if it<br/>recognizes this client

    ServerB->>Client: ACK (lease renewed)

    Note over Client: Now bound to Server B
```

## DECLINE (IP Conflict)

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Leases

    Note over Client: Received ACK for 192.168.1.100

    Client->>Client: ARP probe for 192.168.1.100
    Note over Client: Someone responds!<br/>IP already in use!

    Client->>Server: DECLINE (requested_ip=192.168.1.100)

    Server->>Leases: decline_ip(ip, client_id)
    Note over Leases: 1. Remove client's lease<br/>2. Add IP to declined_ips<br/>3. Quarantine for 1 hour
    Leases-->>Server: done

    Note over Server: No response sent to DECLINE

    Note over Client: Must restart DORA
    Client->>Server: DISCOVER
    Server->>Client: OFFER (different IP)
```

## Response Destination Logic

```mermaid
flowchart TD
    A[Send Reply] --> B{giaddr set?}
    B -->|Yes| C[Send to giaddr:67<br/>Relay agent]
    B -->|No| D{Is NAK?}
    D -->|Yes| E[Broadcast to<br/>255.255.255.255:68]
    D -->|No| F{Broadcast flag set?}
    F -->|Yes| E
    F -->|No| G{ciaddr == 0.0.0.0?}
    G -->|Yes| E
    G -->|No| H[Unicast to<br/>ciaddr:68]
```

## IP Allocation Algorithm

```mermaid
flowchart TD
    A[allocate_ip] --> B{Static binding<br/>for this MAC?}
    B -->|Yes| C[Return static IP]
    B -->|No| D{Existing non-expired<br/>lease?}
    D -->|Yes| E[Return leased IP]
    D -->|No| F{Pending offer<br/>for this client?}
    F -->|Yes| G[Return pending IP]
    F -->|No| H[Cleanup expired leases]
    H --> I[Cleanup expired declined IPs]
    I --> J{Free IP available?}
    J -->|Yes| K[Track as pending offer<br/>60 second hold]
    K --> L[Return IP]
    J -->|No| M[Error: Pool Exhausted]
```
