# dhcplease

[<img alt="github" src="https://img.shields.io/badge/github-matthewjberger/dhcplease-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/matthewjberger/dhcplease)
[<img alt="crates.io" src="https://img.shields.io/crates/v/dhcplease.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/dhcplease)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-dhcplease-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/dhcplease)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/matthewjberger/dhcplease/rust.yml?branch=main&style=for-the-badge" height="20">](https://github.com/matthewjberger/dhcplease/actions?query=branch%3Amain)

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

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
dhcplease = "0.1.0"
```

## Installation

```bash
cargo install dhcplease
```

Or build from source:

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

**Note:** Binding to port 67 requires administrator privileges. Run from an elevated PowerShell or Command Prompt.

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
2. **A second device** (laptop, Raspberry Pi, etc.) that needs an IP address
3. **Direct Ethernet connection** between devices via:
   - Ethernet cable (direct or through an isolated switch)
   - USB-to-Ethernet adapter

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

Create or edit `config.json`, replacing `12` with your actual interface index:

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
  "interface_index": 12
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

On the client device, connect via Ethernet and trigger a DHCP request.

**Windows client:**
```cmd
ipconfig /release
ipconfig /renew
```

**Linux client:**
```bash
sudo dhclient -r eth0 && sudo dhclient eth0
```

**macOS client (see detailed section below):**
```bash
sudo ipconfig set en6 DHCP
```

You should see DISCOVER, OFFER, REQUEST, and ACK messages in the dhcplease output.

### Testing with a MacBook

This section covers testing dhcplease from a Windows host with a MacBook as the DHCP client.

#### Hardware Setup

Connect the MacBook to your Windows machine:
- **Direct connection:** USB-C/Thunderbolt to Ethernet adapter on MacBook, Ethernet cable to Windows
- **Through a switch:** Both machines connected to an isolated switch (no other DHCP server)

#### Find the MacBook's Ethernet Interface

On the MacBook, open Terminal and run:

```bash
networksetup -listallhardwareports
```

Look for your USB/Thunderbolt Ethernet adapter. It will show something like:

```
Hardware Port: USB 10/100/1000 LAN
Device: en6
Ethernet Address: aa:bb:cc:dd:ee:ff
```

Note the device name (e.g., `en6`).

#### Request a DHCP Lease

With the Windows host running dhcplease, run on the MacBook:

```bash
# Release any existing lease and request a new one
sudo ipconfig set en6 DHCP

# Or force a renewal
sudo ipconfig set en6 BOOTP && sudo ipconfig set en6 DHCP
```

#### Verify the Lease

Check the assigned IP on the MacBook:

```bash
ipconfig getifaddr en6
```

View full DHCP information:

```bash
ipconfig getpacket en6
```

This shows the server IP, lease time, DNS servers, and other options received.

#### Monitor DHCP Traffic (Optional)

To see the raw DHCP packets on macOS:

```bash
sudo tcpdump -i en6 -n port 67 or port 68
```

#### Expected Output

On the Windows host running `dhcplease -l debug run`, you should see:

```
INFO DISCOVER from aa:bb:cc:dd:ee:ff (0.0.0.0:68)
INFO OFFER 192.168.1.100 to aa:bb:cc:dd:ee:ff
INFO REQUEST from aa:bb:cc:dd:ee:ff (0.0.0.0:68)
INFO ACK 192.168.1.100 to aa:bb:cc:dd:ee:ff (lease: 3600 seconds)
```

#### Troubleshooting macOS

| Issue | Solution |
|-------|----------|
| `en6` not found | Run `networksetup -listallhardwareports` to find correct interface |
| No IP assigned | Check Windows firewall, verify cable connection |
| Gets `169.254.x.x` | DHCP failed; check dhcplease is running and interface_index is correct |
| Adapter not recognized | Try unplugging and replugging the USB-Ethernet adapter |

### Testing with a Linux Client

#### Find the Ethernet Interface

```bash
ip link show
```

Look for your Ethernet interface (commonly `eth0`, `enp0s3`, or `enpXsY` for USB adapters).

#### Request a DHCP Lease

**Using dhclient (Debian/Ubuntu):**

```bash
# Release existing lease
sudo dhclient -r eth0

# Request new lease
sudo dhclient -v eth0
```

The `-v` flag shows verbose output including the DHCP exchange.

**Using dhcpcd (Arch, Raspberry Pi OS):**

```bash
# Release and renew
sudo dhcpcd -k eth0
sudo dhcpcd eth0
```

**Using NetworkManager (most desktop distros):**

```bash
# Restart the connection
nmcli connection down "Wired connection 1"
nmcli connection up "Wired connection 1"

# Or force DHCP renewal
nmcli device reapply eth0
```

**Using systemd-networkd:**

```bash
sudo networkctl renew eth0
```

#### Verify the Lease

```bash
# Show IP address
ip addr show eth0

# Show full lease info (dhclient)
cat /var/lib/dhcp/dhclient.leases

# Show lease info (dhcpcd)
cat /var/lib/dhcpcd/dhcpcd-eth0.lease
```

#### Monitor DHCP Traffic

```bash
sudo tcpdump -i eth0 -n port 67 or port 68
```

#### Troubleshooting Linux

| Issue | Solution |
|-------|----------|
| Interface not found | Check `ip link show`, interface may have different name |
| Permission denied | Run dhclient/dhcpcd with `sudo` |
| Gets `169.254.x.x` | Link-local fallback means DHCP failed; check server is running |
| NetworkManager conflicts | Stop NetworkManager: `sudo systemctl stop NetworkManager` |
| No response | Verify firewall on Windows host allows UDP 67/68 |

### Testing with a Raspberry Pi

Raspberry Pi makes an excellent isolated test client:

1. Connect Pi to Windows host via Ethernet (direct or through switch)
2. Boot the Pi (it will automatically try DHCP)
3. Or manually trigger: `sudo dhcpcd -n eth0`

For headless setup, monitor dhcplease output to see when the Pi gets an IP, then SSH to that address.

### Verifying Leases on the Server

```powershell
dhcplease list-leases
```

## Using as a Library

```rust
use dhcplease::{Config, DhcpServer};

#[tokio::main]
async fn main() -> dhcplease::Result<()> {
    let config = Config::load_or_create("config.json").await?;
    let server = DhcpServer::new(config).await?;
    server.run().await
}
```

See the [API documentation](https://docs.rs/dhcplease) for details on programmatic configuration.

## License

MIT OR Apache-2.0
