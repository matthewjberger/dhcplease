# Troubleshooting

## Server Won't Start

### "Failed to bind to 0.0.0.0:67"

**Cause**: Port 67 requires administrator privileges.

**Fix**: Run from an elevated PowerShell/Command Prompt.

```powershell
# Right-click PowerShell → "Run as administrator"
dhcplease run
```

### "Failed to bind to 0.0.0.0:67: address already in use"

**Cause**: Another DHCP server is running (Windows DHCP Server service, or another instance).

**Fix**:
```powershell
# Check what's using port 67
netstat -ano | findstr :67

# Stop Windows DHCP Server if running
Stop-Service DHCPServer
```

### "setsockopt IP_UNICAST_IF failed"

**Cause**: Invalid `interface_index` in config.

**Fix**: Find the correct index:
```powershell
Get-NetAdapter | Format-Table Name, InterfaceIndex, Status
```

## Clients Not Getting IPs

### Client gets 169.254.x.x (APIPA)

**Cause**: Client didn't receive a DHCP response.

**Check**:
1. Is dhcplease running? Check for "DHCP server ready and listening"
2. Is Windows Firewall blocking?
   ```powershell
   # Add firewall rules
   New-NetFirewallRule -DisplayName "DHCP In" -Direction Inbound -LocalPort 67 -Protocol UDP -Action Allow
   New-NetFirewallRule -DisplayName "DHCP Out" -Direction Outbound -LocalPort 68 -Protocol UDP -Action Allow
   ```
3. Is the client on the same network segment?
4. Is `interface_index` set correctly (for multi-homed hosts)?

### Server shows DISCOVER but client doesn't get IP

**Cause**: Response not reaching client.

**Check**:
1. Run with debug logging: `dhcplease -l debug run`
2. Look for "OFFER" and "ACK" messages
3. If OFFER sent but no REQUEST, client might be accepting a different server's offer

### "Pool exhausted" warnings

**Cause**: No free IPs in the pool.

**Fix**:
```powershell
# Check active leases
dhcplease list-leases

# Clean up expired leases
dhcplease cleanup-leases

# Or expand the pool in config.json
```

### Client gets wrong IP / different subnet

**Cause**: Another DHCP server on the network.

**Fix**:
- Disconnect from networks with other DHCP servers
- Use an isolated switch
- Disable DHCP on your router for testing

## Lease Issues

### Leases not persisting across restarts

**Check**:
1. Is `leases_file` path writable?
2. Did the server shut down cleanly? (Ctrl+C triggers save)
3. Check for JSON errors in leases file

### Client always gets different IP

**Cause**: Client identifier changing, or lease expiring.

**Fix for stable IP**: Add a static binding in config.json:
```json
{
  "static_bindings": [
    {
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "ip_address": "192.168.1.50"
    }
  ]
}
```

### Client keeps old IP after server config change

**Cause**: Client has cached lease, won't DISCOVER until it expires.

**Fix on client**:
```powershell
# Windows
ipconfig /release
ipconfig /renew
```
```bash
# Linux
sudo dhclient -r eth0
sudo dhclient eth0
```
```bash
# macOS
sudo ipconfig set en0 BOOTP
sudo ipconfig set en0 DHCP
```

## Network Configuration Issues

### Server on wrong interface

**Symptoms**: Server runs but no clients see it.

**Fix**: Set `interface_index` in config.json:
```powershell
# Find the right interface
Get-NetAdapter | Format-Table Name, InterfaceIndex, Status, MacAddress

# Note the InterfaceIndex for your test network adapter
```

### Responses going to wrong interface

**Symptoms**: tcpdump/Wireshark shows responses on wrong NIC.

**Fix**: Set `interface_index` to bind to the correct adapter.

## Debug Techniques

### Enable verbose logging

```powershell
dhcplease -l debug run
```

Shows:
- Every DISCOVER, OFFER, REQUEST, ACK
- Client MAC addresses
- Assigned IPs
- Rate limiting events

### Monitor DHCP traffic

**Windows** (requires Wireshark):
```
Filter: udp.port == 67 or udp.port == 68
```

**Linux/macOS**:
```bash
sudo tcpdump -i eth0 -n port 67 or port 68
```

### Check lease state

```powershell
# List all leases
dhcplease list-leases

# View raw lease file
Get-Content leases.json | ConvertFrom-Json | Format-List
```

### Test with a known client

Use a VM or Raspberry Pi with a clean network config:
```bash
# Linux VM
sudo dhclient -v eth0
```

The `-v` flag shows the full DORA exchange.

## Common Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Not running as admin | "Failed to bind" | Elevate privileges |
| Firewall blocking | Client times out | Add UDP 67/68 rules |
| Wrong interface | No clients seen | Set `interface_index` |
| Router also doing DHCP | Wrong IPs assigned | Disable router DHCP |
| Pool too small | "Pool exhausted" | Expand pool range |
| Static IP conflicts with pool | Duplicate IP | Move static outside pool |
