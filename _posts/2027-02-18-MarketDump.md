---
title: "MarketDump"
date: 2027-02-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, pcap, tshark, exfiltration, base58]
description: "An Easy Forensics challenge: an attacker exfiltrates a customer database over HTTP, and the one targeted record is hidden in plain sight as the single row that breaks the dataset's structure — its base58-encoded 'card number' is the flag."
---

## Overview

**MarketDump** is an Easy HackTheBox **Forensics** challenge. You get a single
packet capture (`MarketDump.pcapng`) and a story: an attacker pivoted through a
public web platform into the internal network and exfiltrated the customer
database. The prompt says **only one customer was targeted** — find who. The path
is pure triage: carve the exfiltrated file out of the HTTP traffic, isolate the one
record that doesn't fit the dataset, and decode it.

## The technique

A secret hidden among thousands of valid-looking decoys is found by its
**structural deviation**, not by reading content. The leaked dump is a CSV of ~10 000
genuine-looking American Express card numbers; the planted record is the only row
that breaks the dominant shape, and its "card number" is really a [base58](https://en.bitcoin.it/wiki/Base58Check_encoding)-encoded
flag. Recognizing the encoding by its alphabet is the final step.

## Solution

Triage the capture by volume — `io,phs` shows the protocol breakdown, and one fat
HTTP transfer immediately stands out (`application/x-sql`):

```bash
tshark -r MarketDump.pcapng -q -z io,phs
```

Carve every transferred HTTP object to disk and sort by size — the dumped database
is on top:

```bash
tshark -r MarketDump.pcapng --export-objects http,objs
ls -S objs | head
```

That drops `costumers.sql` — a CSV of `IssuingNetwork,CardNumber` rows, ~10 114 of
them, all `American Express,<15 digits>`. Define the normal row as a regex and
**negate-match** it to isolate the anomaly:

```bash
grep -vnE '^American Express,[0-9]{15}$' costumers.sql
```

Exactly one data row breaks the pattern: a 45-character alphanumeric "card number"
`NVCijF7n6peM7a7yLYPZrPgHmWUHi97LCAzXxSEUraKme`. Mixed-case, with no `0 O I l` and
no `+ / =` — that character set is the tell for **base58** (Bitcoin alphabet), not
base64 or hex. Decode it:

Create `solve.py`:

```python
#!/usr/bin/env python3
import subprocess, os, re

PCAP = "MarketDump.pcapng"

def b58decode(s):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for c in s:
        num = num * 58 + alphabet.index(c)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')

os.makedirs("objs", exist_ok=True)
subprocess.run(["tshark", "-r", PCAP, "--export-objects", "http,objs"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

target = None
for line in open("objs/costumers.sql"):
    line = line.strip()
    if not line or line.startswith("IssuingNetwork"):
        continue
    net, num = line.split(",")
    if not re.fullmatch(r"\d{15}", num):
        target = num
        break

print(b58decode(target).decode())
```

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

The discriminator is structural. Every decoy passes `^American Express,[0-9]{15}$`;
the planted record does not, so `grep -v` finds it instantly while eyeballing 10 000
rows never would. The base58 alphabet (no `0OIl`, no `+/=`) distinguishes the encoding
on sight, which makes the final decode obvious.

## Fix / defense

The flag (`DonTRuNAsRoOt`) is a wink at the root cause: don't run internet-exposed
stock/database tooling as root, and don't expose internal services to the public web
— that's where the whole pivot started. Egress-filter and apply DLP to large
`application/x-sql` transfers leaving internal hosts so a database exfiltration is
caught on the wire instead of after the fact.
