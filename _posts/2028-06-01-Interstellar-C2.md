---
layout: post
title: "Interstellar C2"
date: 2028-06-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, pcap, poshc2, c2, aes, powershell, stego, cwe-321]
description: "A packet capture of a PoshC2 implant talking to its server. A hard-coded key in the PowerShell dropper unlocks the first stage, a marker-wrapped session key unlocks the rest, and the flag turns out to be a sticky note in an exfiltrated screenshot hidden inside a decoy PNG."
---

## Overview

Interstellar C2 is a **Medium** HackTheBox **Forensics** challenge. You get a single `capture.pcapng` of one machine talking to a command-and-control server. The traffic is [PoshC2](https://github.com/nettitude/PoshC2) — a PowerShell C2 framework — and the path to the flag is: read the obfuscated dropper to recover a static AES key, identify the framework, pull the per-session key out of its handshake, then decrypt an exfiltrated screenshot that was appended to an innocent-looking PNG.

## The technique

The whole challenge unravels from one weakness: [hard-coded and recoverable symmetric keys](https://cwe.mitre.org/data/definitions/321.html). PoshC2's default HTTP profile ships a static "setup" key in the stager, exchanges a per-session key in a predictable marker-wrapped format, and exfiltrates data as AES-CBC blobs glued onto decoy PNGs at a fixed offset. A defender holding only the pcap can reconstruct every layer of plaintext.

## Solution

### 1. Triage the capture

```bash
tshark -r capture.pcapng -q -z io,phs      # protocol hierarchy — HTTP + PNG data
tshark -r capture.pcapng -q -z conv,tcp    # find the fat conversations
```

One victim (`192.168.25.140`) talks to one C2 server (`64.226.84.200`) over ports 80/8080. Most conversations are tiny; one POST upload is 846 KB.

### 2. The dropper (TCP stream 0)

`GET /vn84.ps1` returns an obfuscated PowerShell script (`-f` string-format + backtick noise). Deobfuscating it exposes a **hard-coded AES-CBC key and IV as byte arrays**:

```
key = (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
iv  = (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
```

The script downloads a blob and AES-decrypts it into the implant EXE. This confirms the actor and hands us the first key.

### 3. Identify PoshC2 and the session key

The implant and the C2 responses use PoshC2's tell-tale `RANDOMURI19901(...)10991IRUMODNAR` wrappers and `/RandomName/uuid/?query` tasking URIs. The first check-in uses a hard-coded base64 key; the server then returns a **per-session key** that replaces it for all later traffic:

```
nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=
```

Every AES-CBC payload uses **IV = its own first 16 bytes**.

### 4. Carve and decrypt the screenshot

PoshC2 exfiltrates screenshots as `gzip(base64(realPNG))`, AES-encrypted and appended to a valid 32×32 decoy PNG **after a fixed 1500-byte offset**. The 846 KB POST (TCP stream 28) is the screenshot. Carve its request body:

```bash
tshark -r capture.pcapng -Y 'tcp.stream==28 && http.request' \
  -T fields -e http.file_data | tr -d '\n' > s28_hex.txt
python3 -c "open('s28_body.bin','wb').write(bytes.fromhex(open('s28_hex.txt').read().strip()))"
```

Create `solve.py`:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from base64 import b64decode
import gzip

KEY = b64decode('nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=')

data = open('s28_body.bin', 'rb').read()
enc  = data[1500:]
iv, ct = enc[:16], enc[16:]
ct = ct[:len(ct) - (len(ct) % 16)]
pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)

i   = pt.find(b'\x1f\x8b\x08')
raw = gzip.decompress(pt[i:] if i >= 0 else pt)
png = b64decode(raw) if raw[:8] == b'iVBORw0K' else raw
open('final.png', 'wb').write(png)
print('wrote final.png')
```

```bash
python3 solve.py
```

`final.png` is a 1914×924 desktop screenshot. The flag is text on a sticky note in the top-right corner: *"password for the relic vault: `HTB{...}`"*.

## Why it worked

PoshC2's default profile is decryptable from a pcap alone. The dropper's key literally travels the wire in the PowerShell, and the session key is exchanged in a fixed marker format — so nothing about "encrypted C2" actually protects the traffic once you know the framework's conventions. The 1500-byte decoy-PNG prefix and IV-prepended AES-CBC are documented behaviours, not secrets.

## Fix / defense

- Treat any captured C2 traffic (PoshC2, Covenant, Cobalt Strike default profiles) as fully recoverable once the stager/dropper is in hand — the fix is not "better client-side crypto" but hunting the artifacts.
- Detection signals: PowerShell downloading and AES-decrypting a payload into `%temp%`, `Microsoft BITS` user-agent on the payload GET, `/RandomName/uuid/?query` tasking URIs, `RANDOMURI` markers in responses, and outbound PNGs whose byte length dwarfs their pixel dimensions (a 32×32 image should not be 846 KB).
