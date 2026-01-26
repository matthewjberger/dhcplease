# dhcplease

A developer-grade DHCP server for Windows, written in Rust.

## Features

- Full DHCP protocol implementation (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM)
- Configurable IP pool, lease duration, gateway, DNS servers, and more
- Static MAC-to-IP bindings
- Lease persistence across restarts
- CLI and library crate for embedding in your own applications
- Async/await with Tokio

## Installation

```bash
cargo install --path .
```

## Usage

### Run the server

```bash
# Run with default config (will create config.json if it doesn't exist)
dhcplease run

# Run with custom config
dhcplease -c my-config.json run

# Run with debug logging
dhcplease -l debug run
```

**Note:** DHCP requires binding to port 67, which requires administrator privileges on Windows.

### Other commands

```bash
# Show current configuration
dhcplease show-config

# List active leases
dhcplease list-leases

# Clean up expired leases
dhcplease cleanup-leases
```

## Configuration

On first run, `config.json` is created with default values:

```json
{
  "server_ip": "192.168.1.1",
  "subnet_mask": "255.255.255.0",
  "pool_start": "192.168.1.100",
  "pool_end": "192.168.1.200",
  "gateway": "192.168.1.1",
  "dns_servers": ["8.8.8.8", "8.8.4.4"],
  "domain_name": null,
  "lease_duration_seconds": 86400,
  "renewal_time_seconds": null,
  "rebinding_time_seconds": null,
  "broadcast_address": null,
  "mtu": null,
  "static_bindings": [],
  "leases_file": "leases.json",
  "interface_index": null
}
```

### Configuration options

| Option | Description |
|--------|-------------|
| `server_ip` | IP address of the DHCP server |
| `subnet_mask` | Subnet mask to provide to clients |
| `pool_start` | First IP address in the dynamic pool |
| `pool_end` | Last IP address in the dynamic pool |
| `gateway` | Default gateway to provide to clients |
| `dns_servers` | List of DNS servers to provide to clients |
| `domain_name` | Domain name to provide to clients |
| `lease_duration_seconds` | How long leases are valid |
| `renewal_time_seconds` | When clients should attempt renewal (default: half of lease duration) |
| `rebinding_time_seconds` | When clients should attempt rebinding (default: 7/8 of lease duration) |
| `broadcast_address` | Broadcast address (calculated from server_ip and subnet_mask if not set) |
| `mtu` | Interface MTU to provide to clients |
| `static_bindings` | List of MAC-to-IP static assignments |
| `leases_file` | Path to the lease persistence file |
| `interface_index` | Windows network interface index to bind to (optional) |

### Static bindings

To always assign a specific IP to a MAC address:

```json
{
  "static_bindings": [
    {
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "ip_address": "192.168.1.150",
      "hostname": "my-device"
    }
  ]
}
```

## Using as a library

Add to your `Cargo.toml`:

```toml
[dependencies]
dhcplease = { path = "../dhcplease" }
```

Example:

```rust
use dhcplease::{Config, DhcpServer};

#[tokio::main]
async fn main() -> dhcplease::Result<()> {
    let config = Config::load_or_create("config.json")?;
    let server = DhcpServer::new(config).await?;
    server.run().await
}
```

## License

MIT OR Apache-2.0
