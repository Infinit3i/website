---
title: "Easy Phish"
date: 2027-01-29 09:00:00 -0500
categories: [HackTheBox, Challenges, OSINT]
tags: [hackthebox, challenge, osint, spf, dmarc, dkim, email-spoofing, dns]
description: "An Easy OSINT challenge solved entirely from public DNS — the domain's SPF record ends in ?all and its DMARC policy is p=none, so spoofed mail is never rejected. The flag is split across the two misconfigured TXT records, so you read it straight out of the email-authentication policy."
---

## Overview

Easy Phish is an Easy **OSINT** challenge with no download, no docker, and no shell — just a domain name and a question: *"Customers of secure-startup.com have been receiving some very convincing phishing emails, can you figure out why?"* The entire solve is two DNS lookups. The reason the phishing works **is** the vulnerability, and the flag is embedded directly inside the misconfigured email-authentication records.

## The technique

Three public DNS TXT records decide whether a domain can be impersonated in email:

| Record | Lookup | Healthy | Weak (spoofable) |
|--------|--------|---------|------------------|
| **SPF** | `TXT <domain>` | ends `-all` (hardfail) | `?all` (neutral), `~all` (softfail), `+all` (pass-all) |
| **DMARC** | `TXT _dmarc.<domain>` | `p=reject` / `p=quarantine` | `p=none` (monitor only) |
| **DKIM** | `TXT <selector>._domainkey.<domain>` | key published | absent (unsigned mail) |

When SPF is permissive **and** DMARC has no enforcement, a forged `From:` domain sails through the receiver's checks — exactly the scenario the prompt describes. This is [authentication bypass by spoofing (CWE-290)](https://cwe.mitre.org/data/definitions/290.html).

## Solution

Pull the two relevant records straight from public DNS:

```bash
dig +short TXT secure-startup.com
# "v=spf1 a mx ?all - HTB{...

dig +short TXT _dmarc.secure-startup.com
# "v=DMARC1;p=none;..._DMARC}"
```

Two problems jump out:

1. **SPF ends in `?all`** — *neutral*. Senders not covered by `a`/`mx` are neither passed nor failed, so the receiver has no reason to reject a spoof.
2. **DMARC is `p=none`** — *monitor only*. Even when SPF/DKIM fail, the receiver takes no action and delivers the message anyway.

The flag is split across the two broken records — concatenate the SPF tail with the DMARC tail. A small script derives it live:

`solve.py`:

```python
#!/usr/bin/env python3
import subprocess, re

def txt(name):
    out = subprocess.run(["dig", "+short", "TXT", name], capture_output=True, text=True).stdout
    return "".join(re.findall(r'"([^"]*)"', out))

spf   = txt("secure-startup.com")
dmarc = txt("_dmarc.secure-startup.com")

part1 = spf[spf.index("HTB{"):].strip()
part2 = dmarc[dmarc.index(";", dmarc.index("p=none")) + 1:].strip()
print("FLAG:", part1 + part2)
```

```bash
python3 solve.py
# FLAG: HTB{...}
```

## Why it worked

SPF and DMARC only protect a domain when they tell the receiver to **reject** failures. `?all` and `p=none` are the "audit but allow" settings teams leave in place during rollout and forget to tighten — the mechanism is present but toothless. Anyone can read two public TXT records and instantly know the domain is impersonatable, which is why the phishing emails look like they come from the real sender.

## Fix / defense

```dns
example.com.        IN TXT "v=spf1 a mx -all"
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

- End SPF with **`-all`** (hardfail) once every legitimate sender is enumerated.
- Move DMARC to **`p=quarantine`**, then **`p=reject`**, after `rua` aggregate reports confirm alignment.
- Publish and rotate **DKIM** selector keys so all outbound mail is signed.
