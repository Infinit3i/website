---
title: "LAN MTU Scanner"
date: 2026-04-01 07:00:00 -0500
categories: [Project, Networking]
tags: [linux, networking, mtu, jumbo frames, bash, lan, performance, arch-linux, ping, optimization]
image:
  path: https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fi.ytimg.com%2Fvi%2FLeaEmOUVEn0%2Fmaxresdefault.jpg&f=1&nofb=1&ipt=01b9f81a9d931a4044a2d4bf15979b7278bec533677f3040a5b60d4ae5c7c101
---

A simple script to discover the maximum MTU supported by every device on your LAN — so you can confidently enable jumbo frames without breaking connectivity.

## Why

Most home and lab networks run at the default MTU of 1500 bytes. But if your switch and NICs support jumbo frames (up to 9000 bytes), you're leaving throughput on the table — especially for large file transfers, NAS backups, and VM traffic. The problem is that **every device in the path** must support the same MTU. One misconfigured device and packets get silently dropped or fragmented.

This script removes the guesswork. It scans your LAN, finds live hosts, and tests each one to determine the largest packet it will accept without fragmentation.

## How It Works

```
Scan LAN for active hosts
        |
        v
  For each host:
        |
        v
  Send ping with DF (Don't Fragment) bit set
  Starting at 9000 bytes, step down
        |
        ├── Ping succeeds
        |     -> Report max MTU for this host
        |
        └── Ping fails
              -> Reduce size and retry
              -> Floor at 1500 (standard MTU)
```

The key flag is `ping -M do` which sets the Don't Fragment bit. If the packet is too large for any link in the path, ICMP will reject it instead of silently fragmenting — giving us an exact measurement.

## The Script

```bash
#!/bin/bash
# mtu-scan.sh — Discover max MTU for each device on your LAN

SUBNET="${1:-192.168.1}"
MTU_START=9000
MTU_STEP=500
MTU_MIN=1500

echo "Scanning ${SUBNET}.0/24 for max MTU support..."
echo "=============================================="

for host in $(seq 1 254); do
    ip="${SUBNET}.${host}"

    # skip hosts that aren't alive
    ping -c 1 -W 1 "$ip" &>/dev/null || continue

    mtu=$MTU_START
    max_mtu=$MTU_MIN

    while [ $mtu -ge $MTU_MIN ]; do
        payload=$((mtu - 28))  # subtract IP + ICMP headers
        if ping -M do -c 1 -W 1 -s "$payload" "$ip" &>/dev/null; then
            max_mtu=$mtu
            break
        fi
        mtu=$((mtu - MTU_STEP))
    done

    if [ $max_mtu -gt $MTU_MIN ]; then
        echo "$ip — max MTU: $max_mtu (jumbo frames supported)"
    else
        echo "$ip — max MTU: $MTU_MIN (standard)"
    fi
done

echo ""
echo "Done. The lowest value above is your safe network-wide MTU."
```

## Usage

```bash
chmod +x mtu-scan.sh

# Scan default subnet (192.168.1.x)
./mtu-scan.sh

# Scan a different subnet
./mtu-scan.sh 10.0.0
```

## Example Output

```
Scanning 192.168.1.0/24 for max MTU support...
==============================================
192.168.1.1   — max MTU: 1500 (standard)
192.168.1.10  — max MTU: 9000 (jumbo frames supported)
192.168.1.15  — max MTU: 9000 (jumbo frames supported)
192.168.1.20  — max MTU: 1500 (standard)
192.168.1.100 — max MTU: 9000 (jumbo frames supported)

Done. The lowest value above is your safe network-wide MTU.
```

In this example, the router (`.1`) and one device (`.20`) only support 1500 — so enabling 9000 network-wide would break connectivity to those devices. You could either upgrade those devices or set jumbo frames only between the hosts that support it.

## Fine-Tuning

The default `MTU_STEP` of 500 gives a fast scan. For an exact measurement, you can do a second pass:

```bash
# Binary search between 1500 and the value found above
MTU_STEP=1
```

Or modify the script to do a binary search between the last failure and last success for each host.

## What is MTU

| MTU | Name | Use Case |
|---|---|---|
| 1500 | Standard Ethernet | Default for most networks |
| 9000 | Jumbo Frames | NAS, iSCSI, VM migration, bulk transfers |
| 1280 | IPv6 Minimum | Smallest allowed for IPv6 |

## Things to Know

- **All devices in the path matter** — your NIC, switch, router, and destination all need to support the MTU you set
- **Switches don't respond to ping** — this script tests end-to-end path MTU, not individual switch capability
- **VPN and tunnels reduce MTU** — WireGuard typically needs ~1420, OpenVPN ~1400 due to encapsulation overhead
- **Setting MTU too high causes silent failures** — packets get dropped with no obvious error, making it hard to debug without a tool like this
