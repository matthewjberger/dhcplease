# dhcplease

A DHCP server for Windows, written in Rust.

## Features

- Full DHCP protocol implementation (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, DECLINE, INFORM)
- Client Identifier (Option 61) support for proper client identification
- Relay Agent Info (Option 82) echoing for relay environments
- Configurable IP pool, lease duration, gateway, DNS servers, and more
- Static MAC-to-IP bindings
- Lease persistence across restarts
- Concurrent packet handling with rate limiting
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

## Testing with a Real Device

### Prerequisites

1. **Windows host machine** running dhcplease
2. **A second device** (laptop, phone, Raspberry Pi, etc.) that needs an IP address
3. **Direct connection** between devices via:
   - Ethernet cable (direct or through a switch)
   - USB-to-Ethernet adapter
   - WiFi hotspot (Windows host acts as hotspot)

### Setup Steps

#### 1. Identify your network interface

Open PowerShell and run:

```powershell
Get-NetAdapter | Format-Table Name, InterfaceIndex, Status
```

Note the `InterfaceIndex` of the adapter connected to your test device.

#### 2. Configure a static IP on the Windows host

Set a static IP on the interface you'll use for DHCP:

```powershell
# Replace <InterfaceIndex> and IPs as needed
New-NetIPAddress -InterfaceIndex <InterfaceIndex> -IPAddress 192.168.1.1 -PrefixLength 24
```

#### 3. Disable Windows DHCP client on that interface

```powershell
Set-NetIPInterface -InterfaceIndex <InterfaceIndex> -Dhcp Disabled
```

#### 4. Configure dhcplease

Create or edit `config.json`:

```json
{
  "server_ip": "192.168.1.1",
  "subnet_mask": "255.255.255.0",
  "pool_start": "192.168.1.100",
  "pool_end": "192.168.1.200",
  "gateway": "192.168.1.1",
  "dns_servers": ["8.8.8.8", "8.8.4.4"],
  "lease_duration_seconds": 3600,
  "leases_file": "leases.json",
  "interface_index": <InterfaceIndex>
}
```

#### 5. Disable Windows Firewall for the interface (or add rules)

Either disable the firewall for testing:

```powershell
Set-NetFirewallProfile -Profile Private -Enabled False
```

Or add specific rules for DHCP:

```powershell
New-NetFirewallRule -DisplayName "DHCP Server In" -Direction Inbound -LocalPort 67 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "DHCP Server Out" -Direction Outbound -LocalPort 68 -Protocol UDP -Action Allow
```

#### 6. Run dhcplease as Administrator

```powershell
# Open an elevated PowerShell prompt
dhcplease -l debug run
```

#### 7. Connect and test the client device

On the client device:
- Connect to the network (ethernet cable or WiFi hotspot)
- Set the interface to obtain IP via DHCP
- Renew the DHCP lease:
  - **Windows client:** `ipconfig /release && ipconfig /renew`
  - **Linux client:** `sudo dhclient -r && sudo dhclient`
  - **macOS client:** System Preferences > Network > Renew DHCP Lease

You should see DISCOVER, OFFER, REQUEST, and ACK messages in the dhcplease output.

### Verifying the lease

On the Windows host:

```powershell
dhcplease list-leases
```

On the client:
- **Windows:** `ipconfig /all`
- **Linux/macOS:** `ip addr` or `ifconfig`

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Access denied" error | Run dhcplease as Administrator |
| No packets received | Check firewall rules, verify interface_index |
| Client not getting IP | Ensure client is set to DHCP, check cable/connection |
| Wrong interface | Use `Get-NetAdapter` to verify interface_index |

### Testing with a USB-to-Ethernet Adapter

USB-to-Ethernet adapters work well for isolated testing:

1. Plug in the adapter
2. Run `Get-NetAdapter` to find its interface index
3. Set a static IP on the adapter
4. Configure dhcplease with that interface_index
5. Connect your test device to the adapter

This keeps your test network completely isolated from your main network.

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
    let config = Config::load_or_create("config.json").await?;
    let server = DhcpServer::new(config).await?;
    server.run().await
}
```

## License

MIT OR Apache-2.0
