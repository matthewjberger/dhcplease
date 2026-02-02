# RFC Compliance

## RFC 2131 - Dynamic Host Configuration Protocol

| Section | Feature | Status |
|---------|---------|--------|
| 2 | Protocol Summary | ✅ |
| 3.1 | Client-server model | ✅ |
| 3.1 | UDP ports 67/68 | ✅ |
| 3.1 | Transaction ID (xid) | ✅ |
| 3.1 | Broadcast flag | ✅ |
| 4.1 | DHCPDISCOVER | ✅ |
| 4.2 | DHCPOFFER | ✅ |
| 4.3 | DHCPREQUEST | ✅ |
| 4.3.1 | REQUEST in SELECTING state | ✅ |
| 4.3.2 | REQUEST in INIT-REBOOT state | ✅ |
| 4.3.4 | REQUEST in RENEWING state | ✅ |
| 4.3.5 | REQUEST in REBINDING state | ✅ |
| 4.3.3 | DHCPINFORM | ✅ |
| 4.4.1 | DHCPACK | ✅ |
| 4.4.2 | DHCPNAK | ✅ |
| 4.4.3 | DHCPRELEASE | ✅ |
| 4.4.4 | DHCPDECLINE | ✅ |
| 4.1 | Relay agent (giaddr) | ✅ |
| 4.1 | Minimum packet size (300 bytes) | ✅ |
| 4.1 | Maximum hop count (16) | ✅ |
| 4.3.1 | Server identifier in REQUEST | ✅ |
| 4.4.1 | Lease time negotiation | ✅ |
| 3.3 | T1/T2 timers | ✅ |
| 4.4.4 | Declined IP quarantine | ✅ (1 hour) |
| 3.5 | Parameter Request List | ✅ |

## RFC 2132 - DHCP Options

| Option | Name | Status |
|--------|------|--------|
| 0 | Pad | ✅ |
| 1 | Subnet Mask | ✅ |
| 3 | Router | ✅ |
| 6 | Domain Name Server | ✅ |
| 12 | Host Name | ✅ |
| 15 | Domain Name | ✅ |
| 26 | Interface MTU | ✅ |
| 28 | Broadcast Address | ✅ |
| 50 | Requested IP Address | ✅ |
| 51 | IP Address Lease Time | ✅ |
| 52 | Option Overload | ✅ (parsing) |
| 53 | DHCP Message Type | ✅ |
| 54 | Server Identifier | ✅ |
| 55 | Parameter Request List | ✅ |
| 58 | Renewal Time (T1) | ✅ |
| 59 | Rebinding Time (T2) | ✅ |
| 61 | Client Identifier | ✅ |
| 255 | End | ✅ |

### Options NOT Implemented

| Option | Name | Reason |
|--------|------|--------|
| 2 | Time Offset | Rarely used |
| 4 | Time Server | Rarely used |
| 5 | Name Server | Obsolete (IEN 116) |
| 7-11 | Various servers | Rarely used |
| 13 | Boot File Size | BOOTP legacy |
| 16 | Swap Server | Rarely used |
| 17 | Root Path | PXE/diskless boot |
| 18 | Extensions Path | Rarely used |
| 19-25 | IP layer params | Rarely needed |
| 27 | All Subnets Local | Rarely used |
| 29-36 | Various | Rarely used |
| 40-49 | NIS/NetBIOS | Legacy |
| 56 | Message | Could add |
| 57 | Maximum Message Size | Could add |
| 60 | Vendor Class ID | Could add |
| 66 | TFTP Server Name | PXE boot |
| 67 | Bootfile Name | PXE boot |

## RFC 3046 - Relay Agent Information Option

| Feature | Status |
|---------|--------|
| Option 82 parsing | ✅ |
| Option 82 echoing | ✅ |
| Sub-option parsing | ❌ (preserved as raw bytes) |

## RFC 4361 - Node-specific Client Identifiers

| Feature | Status |
|---------|--------|
| DUID-based client ID | ✅ (accepts any Option 61) |
| IAID handling | ❌ |

## BOOTP Compatibility (RFC 951)

| Feature | Status |
|---------|--------|
| BOOTREQUEST/BOOTREPLY | ✅ |
| Packets without Option 53 | ✅ (treated as BOOTP) |
| Infinite lease for BOOTP | ✅ |

## Not Implemented

| Feature | RFC | Reason |
|---------|-----|--------|
| DHCPv6 | 8415 | IPv4 only |
| Failover | 7031 | Single server |
| DDNS updates | 4702 | Out of scope |
| Authentication | 3118 | Rarely used |
| Rapid Commit | 4039 | Could add |
| Lease Query | 4388 | Could add |
