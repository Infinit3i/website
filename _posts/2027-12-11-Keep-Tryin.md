---
layout: post
title: "Keep Tryin'"
date: 2027-12-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, dns-exfiltration, dnsexfiltrator, rc4, pcap, cwe-514]
---

A 26-packet capture, a pile of base64 that looks like DNS noise, and two HTTP requests that exist only to waste your time. Keep Tryin' is a compact lesson in [DNS-based data exfiltration](https://cwe.mitre.org/data/definitions/514.html): the file left the network one TXT query at a time, and the key to decrypt it was sitting in plain sight — disguised as a decoy.

## Overview

**Category:** Forensics · **Difficulty:** Medium. You get a single `keeptryin.pcap` (2,988 bytes, 26 packets). The traffic is the [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) tool pattern: a file is zipped, RC4-encrypted, base64url-encoded, and streamed out as the subdomain labels of DNS **TXT** queries. Reassemble the labels, decrypt with the right key, and unzip to recover the exfiltrated `secret.txt`.

## The technique

Opening the capture with `tshark` shows three things:

1. **DNS TXT** queries to `*.totallylegit.com` — the real exfiltration channel.
2. A `POST /flag` whose urlencoded form is `TryHarder=` (decoy #1).
3. A `POST /lootz` whose body `S2VlcCB0cnlpbmcsIGJ1ZmZ5Cg` base64-decodes to `Keep trying, buffy` (decoy #2 — a troll).

The DNS channel follows the DNSExfiltrator layout:

```
init.c2VjcmV0LnR4dHwx.totallylegit.com                 # base64("secret.txt|1") = filename|chunkCount
0.<63chars>.<63chars>.<63chars>.w.totallylegit.com     # chunk 0: index . data-labels . domain
```

- The **init** query announces `filename|chunkCount`. Here `secret.txt|1` — one data chunk follows.
- Each **data** query is `<chunkIndex>.<base64url payload split into DNS labels>.<domain>`. A DNS label maxes out at 63 characters, so the payload is spread across up to three of them, plus any short remainder (`w`).

To rebuild a chunk you join the data labels — **drop the leading chunk-index label and the two apex labels, but keep the short trailing `w` label**, because it is payload, not filler. A quick sanity check catches the classic mistake: joining without the `w` gives 189 characters, which is invalid base64 (189 mod 4 = 1); including it gives 190, which decodes cleanly.

The decoded bytes are RC4-encrypted. The key is **not** on the wire labelled as a key — it is the *field name* of the decoy `POST /flag` form: `TryHarder`. RC4-decrypt with it and the output begins with `PK\x03\x04` — a ZIP archive. Unzip it and read `secret.txt`.

## Solution

The whole solve is one script that reads the pcap live and derives the flag — nothing is copied from anywhere.

`solve.py`:

```python
import base64, io, zipfile, subprocess

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff; S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

qn = subprocess.check_output(
    ["tshark", "-r", "keeptryin.pcap",
     "-Y", 'dns.flags.response==0 && dns.qry.name contains ".w."',
     "-T", "fields", "-e", "dns.qry.name"]).decode().strip()

sub    = qn.rsplit(".totallylegit.com", 1)[0]
data   = "".join(sub.split(".")[1:])          # drop the chunk-index label, keep the trailing 'w'
raw    = base64.urlsafe_b64decode(data + "==")

zip_bytes = rc4(b"TryHarder", raw)
assert zip_bytes[:4] == b"PK\x03\x04"

z = zipfile.ZipFile(io.BytesIO(zip_bytes))
print("FLAG:", z.read(z.namelist()[0]).decode().strip())
```

Run it against the capture and it prints the flag:

```bash
python3 solve.py
# FLAG: HTB{...}
```

Or the same thing as a one-liner with `pycryptodome`:

```bash
tshark -r keeptryin.pcap -Y 'dns.qry.type==16 && dns.qry.name contains ".w."' -T fields -e dns.qry.name \
 | python3 -c "import sys,base64,io,zipfile;from Crypto.Cipher import ARC4;d=b''.join(base64.urlsafe_b64decode(''.join(l.split('.')[1:-2])+'==') for l in sys.stdin);z=ARC4.new(b'TryHarder').decrypt(d);f=zipfile.ZipFile(io.BytesIO(z));print(f.read(f.namelist()[0]))"
```

## Why it worked

DNS is almost always permitted outbound — even where an egress firewall blocks arbitrary TCP/UDP, recursive DNS still resolves, which turns a resolver into a covert data pipe. Wrapping the payload in RC4 and zip makes every subdomain label look like random base64, so content-based IDS/DLP have nothing to match on. The author then split the two halves of the secret across two protocols: the ciphertext rode DNS, and the key hid inside HTTP as a form-field name. Neither channel alone is enough — the solve depends on correlating the whole capture and refusing to dismiss the "junk" strings.

## Fix / defense

- Pin clients to a **logging recursive resolver** and alert on long, high-entropy subdomain labels, incrementing numeric leading labels, and TXT-query floods to a newly-seen second-level domain — the classic DNS-tunnel signatures.
- Sinkhole or RPZ-block unknown external zones; DNSExfiltrator needs an attacker-controlled authoritative domain to answer the queries.
- Rate-limit TXT queries per client and block direct `udp/53` to anything but the internal resolver.
