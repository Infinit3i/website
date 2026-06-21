---
title: "Watch Tower"
date: 2026-10-25 09:00:00 -0500
categories: [HackTheBox, Challenges, ICS]
tags: [hackthebox, challenge, ics, modbus, covert-channel, forensics, tshark, cwe-319, cwe-514]
description: "A Very Easy ICS challenge built from a Modbus/TCP packet capture. The flag isn't in the register values the intruder wrote — it's hidden in the register addresses, one ASCII byte per write, because Modbus lets you address anything you like."
---

## Overview

`Watch Tower` is a Very Easy HackTheBox **ICS** challenge. You get a single packet
capture, `tower_logs.pcapng`, and a prompt about intruders who "collected and altered"
data on a monitored network. The capture is 100% Modbus/TCP. The twist: the data the
attacker smuggled out is not in the register *values* they wrote — those are decoy — but
in the register *addresses*, each one an ASCII byte of the flag. Because Modbus has no
[authentication](https://cwe.mitre.org/data/definitions/306.html) and no integrity
checking, a writer can target any register number it likes, turning the address field
into a [covert channel](https://cwe.mitre.org/data/definitions/514.html).

## The technique

First, triage the capture. The protocol hierarchy shows it is entirely Modbus, and a
function-code histogram tells you what the conversation actually does:

```bash
tshark -r tower_logs.pcapng -q -z io,phs
tshark -r tower_logs.pcapng -T fields -e modbus.func_code | sort | uniq -c
#   304  func 1   (Read Coils)
#     2  func 15  (Write Multiple Coils)
#   114  func 16  (Write Multiple Registers)
```

The prompt's "altered" data is the write traffic. The obvious move — dump the values
written by the 114 FC16 (Write Multiple Registers) requests — gives random-looking
16-bit numbers. Decoy. The payload lives in the register **addresses**
(`modbus.reference_num`): each FC16 write targets a register whose address byte is one
printable ASCII character, so reading them in frame order spells the flag.

One gotcha: the slave echoes every write, so if you don't filter you get each character
twice (`44LLRR00...`). Filtering to the master's requests (`ip.src==192.168.1.150`)
fixes it.

## Solution

`solve.py` shells out to `tshark`, pulls the FC16 register addresses in order, and turns
them into text:

```python
#!/usr/bin/env python3
# Each FC16 (Write Multiple Registers) request's register ADDRESS
# (modbus.reference_num) is one ASCII byte of the flag. The register
# VALUES are decoy. Filter to the master's requests (192.168.1.150) so
# the slave's echo doesn't double every character.
import subprocess, sys
pcap = sys.argv[1] if len(sys.argv) > 1 else "files/tower_logs.pcapng"
out = subprocess.check_output([
    "tshark", "-r", pcap,
    "-Y", "modbus.func_code==16 && ip.src==192.168.1.150",
    "-T", "fields", "-e", "modbus.reference_num"],
    stderr=subprocess.DEVNULL).decode()
vals = [int(x) for x in out.split() if x.strip()]
s = "".join(chr(v) for v in vals if 32 <= v < 127)
print("decoded:", s)
i, j = s.find("HTB{"), s.find("}")
print("FLAG:", s[i:j+1] if i >= 0 else "(no HTB{} found)")
```

```bash
python3 solve.py
# decoded: 4LR0P3Un8F-HTB{...}-r6ZJa0
# FLAG:    HTB{...}
```

The decoded string carries some non-flag junk around the braces, so the script just
slices out the `HTB{...}` portion.

## Why it worked

Modbus/TCP carries no authentication and no integrity check
([CWE-319](https://cwe.mitre.org/data/definitions/319.html)). Nothing ties a written
register address to a real device point, so an attacker on the bus can issue writes to
arbitrary addresses purely to carry data — a textbook protocol-field
[covert channel](https://cwe.mitre.org/data/definitions/514.html). The register values
were a deliberate red herring; the message was in the metadata.

## Fix / defense

- Segment the OT network — never expose Modbus to untrusted segments.
- Front Modbus with an authenticated gateway/VPN and a deep-packet-inspection firewall
  that validates register maps.
- Alert on writes to register addresses outside a device's known point map — exactly the
  anomaly this capture recorded.
