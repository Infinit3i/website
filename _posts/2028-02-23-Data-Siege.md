---
layout: post
title: "Data Siege"
date: 2028-02-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, pcap, activemq, cve-2023-46604, asyncrat, aes-cbc, malware-analysis]
description: "A single PCAP records an ActiveMQ OpenWire RCE dropping an AsyncRAT-style .NET implant; the three-part flag hides in AES-CBC C2 traffic whose key and IV are both baked into the binary, so the whole session decrypts offline."
---

## Overview

Data Siege is a Medium forensics challenge from Cyber Apocalypse 2024. You get one file — `capture.pcap` — with no target and no shell; everything is in the traffic. The capture records a full intrusion: an [ActiveMQ OpenWire RCE (CVE-2023-46604)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604) that drops a .NET remote-access trojan, which then talks to its operator over an AES-encrypted C2 channel. The flag is split into three parts, all of them inside that encrypted channel — and the implant hard-codes its own crypto, so the entire conversation decrypts offline.

## The technique

The chain in the pcap, reconstructed from the TCP conversations (`tshark -r capture.pcap -q -z conv,tcp`):

1. **[ActiveMQ OpenWire deserialization RCE (CVE-2023-46604)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)** on port `61616` — a crafted OpenWire frame makes the broker instantiate a Spring `ClassPathXmlApplicationContext` from an attacker URL.
2. **Spring XML → command execution** on port `8080` — the served bean runs `ProcessBuilder("cmd.exe","/c", <powershell>)` that downloads and starts the implant.
3. **Implant download** on port `8000` — `aQ4caZ.exe`, a .NET (Mono/.Net) AsyncRAT-style RAT.
4. **Encrypted C2** on port `1234` — base64-wrapped AES-CBC messages between implant and operator. The flag lives here.

The crux is that the implant is a compiled client shipping its own symmetric secret. Decompiling it (`ilspycmd aQ4caZ.exe`) exposes the `Constantes` class and the encrypt/decrypt routine: a hard-coded password, a 13-byte salt, and — critically — **both the AES-256 key and the IV are pulled from the same `Rfc2898DeriveBytes` (PBKDF2) stream** (`GetBytes(32)` then `GetBytes(16)`). .NET's `Rfc2898DeriveBytes` defaults to SHA1 / 1000 iterations, and `Aes.Create()` defaults to CBC/PKCS7. That's every parameter needed to reproduce the key schedule.

## Solution

First carve the artifacts straight out of the capture:

```bash
tshark -r capture.pcap --export-objects http,exported
file exported/*
```

That yields the Spring XML and `aQ4caZ.exe` (a .NET PE). Decompile it and read the hard-coded crypto config out of `Constantes.EncryptKey` and the salt array in the `Rfc2898DeriveBytes` call:

```bash
ilspycmd exported/aQ4caZ.exe | grep -A6 'Rfc2898DeriveBytes'
```

Then reproduce the KDF and replay-decrypt every base64 token from the C2 stream. Save `solve.py`:

```python
#!/usr/bin/env python3
import base64, re, subprocess
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PWD  = b"VYAemVeO3zUDTL6N62kVA"
SALT = bytes([86,101,114,121,95,83,51,99,114,51,116,95,83])   # "Very_S3cr3t_S"
dk   = pbkdf2_hmac("sha1", PWD, SALT, 1000, 48)               # SHA1 / 1000 iters
KEY, IV = dk[:32], dk[32:48]                                  # key AND iv from one stream

def dec(b64):
    try:
        ct = base64.b64decode(b64)
        return unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct), 16).decode("latin-1")
    except Exception:
        return None

raw = subprocess.check_output(
    ["tshark","-r","capture.pcap","-q","-z","follow,tcp,ascii,5"], text=True)
seen = set()
for t in re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', raw):
    for cand in (t, re.sub(r'^\d+\.', '', t)):      # strip a leading "len." size prefix
        pt = dec(cand)
        if pt and pt not in seen:
            seen.add(pt); print(repr(pt)); break
```

```bash
python3 solve.py
```

The decrypted session shows the operator's whole hands-on-keyboard activity, and the three flag parts fall out of it:

- **Part 1** — the operator plants an SSH key; the `echo ssh-rsa ... >> authorized_keys` command carries the key comment: `HTB{c0mmun1c4710n5`
- **Part 2** — `type C:\Users\svc01\Documents\credentials.txt` returns creds plus a literal `2nd flag part: _h45_b33n_r357`
- **Part 3** — a `powershell.exe -encoded <b64>` persistence command. Base64-decode it as **UTF-16LE** and the `Register-ScheduledTask -TaskName` string is the final part: `0r3d_1n_7h3_h34dqu4r73r5}`

Concatenated they read `HTB{...}` — "communications has been restored in the headquarters".

## Why it worked

Symmetric crypto with the key material compiled into a distributed client is reversible by definition: anyone who captures the traffic *and* the binary can recover the plaintext. Data Siege compounds it — the IV is also derived from the same fixed KDF output, so there is no per-message randomness at all, making the traffic not only decryptable but trivially replayable. AsyncRAT and its many clones are notorious for exactly this: a static config key baked into the assembly.

## Fix / defense

- **Patch ActiveMQ.** [CVE-2023-46604](https://nvd.nist.gov/vuln/detail/CVE-2023-46604) is fixed in 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3. Restrict the OpenWire transport (`61616`) to trusted hosts or disable it if unused.
- **Never ship a symmetric key or a static IV inside a client.** Use an authenticated key exchange (TLS with pinned certificates) so no long-term secret travels in the binary, and derive a fresh random IV per message, prepending it to the ciphertext. Treat any secret embedded in client-side code as public — this is a [use of hard-coded cryptographic key (CWE-321)](https://cwe.mitre.org/data/definitions/321.html).
- Alert on brokers fetching Spring `ClassPathXmlApplicationContext` beans, and egress-filter unusual outbound ports like `1234`.
