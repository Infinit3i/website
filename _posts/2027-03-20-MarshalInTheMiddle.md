---
title: "Marshal in the Middle"
date: 2027-03-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, tls, pcap, wireshark, tshark, nss-keylog, exfiltration, cwe-319, cwe-312]
description: "An Easy Forensics challenge that hands you a packet capture plus the TLS master secrets. Feed the key-log to tshark, decrypt the HTTPS, and the 'production server' turns out to be POSTing a stolen credit-card dump to pastebin — with the flag hidden in it."
---

## Overview

`Marshal in the Middle` is an Easy HackTheBox **Forensics** challenge. The SOC flagged
suspicious network activity from a production web server and you have to work out whether
data was stolen and what it was. The drop is download-only — a packet capture, a set of
Bro/Zeek logs, a CA certificate, and an NSS key-log file. The one-line path: use the
key-log to decrypt the captured TLS, follow the suspicious host to its exfil destination,
and pull the stolen data (with the flag baked in) out of one oversized HTTPS POST.

## The technique

You are given more than a pcap:

- `chalcap.pcapng` — the capture, almost entirely HTTPS.
- `secrets.log` — an **NSS key-log file**: lines of `CLIENT_RANDOM <client_random> <master_secret>`.
- `bundle.pem` — a "Snoopy CA" certificate. This is the machine-in-the-middle proxy's CA, and it's a **red herring** for decryption.
- `bro/` — Zeek logs (`conn`, `dns`, `http`, `ssl`, `weird`, `files`).

TLS session keys are derived from the **master secret** and the **client random** that
are exchanged during the handshake. A normal capture of HTTPS is opaque, but if you also
have the master secrets — because the browser was told to write them out via the
`SSLKEYLOGFILE` environment variable, or because a proxy that intercepted the connection
captured them — Wireshark / `tshark` can recompute the per-session keys and decrypt the
application data with **no server private key required**. That is exactly what `secrets.log`
gives you. The `data_before_established` entries in `bro/weird.log` are the tell that
something was sitting in the middle of the TLS stream rewriting it — [cleartext transmission
of sensitive information](https://cwe.mitre.org/data/definitions/319.html)
([CWE-319](https://cwe.mitre.org/data/definitions/319.html)) once the keys are in the
defender's hands.

## Solution

First find the suspicious host straight from the Zeek logs — no decryption needed. The DNS
log shows where each internal host phoned home, and a paste service is a classic exfil
destination:

```bash
awk -F'\t' '$3=="10.10.20.13"{print $10}' bro/dns.log
# -> pastebin.com   (and an internal mysql-m1.prod.htb)
```

Now feed the key-log to `tshark` and list that host's HTTP requests. The decryption happens
in place; the oversized POST is the dump:

```bash
tshark -2 -R "ip.src==10.10.20.13 and http.request" \
  -o 'tls.keylog_file:./secrets.log' -r chalcap.pcapng \
  -T fields -e http.host -e http.request.uri -e frame.len
# -> 3x  POST  pastebin.com  /api/api_post.php   (frame.len 1804, 1278, 6855)
```

The 6855-byte POST is the data dump. Pull its body, convert the hex to bytes, and URL-decode
the form payload — the same recipe is wrapped up in `solve.py`:

```python
#!/usr/bin/env python3
import subprocess, urllib.parse, re

PCAP = "files/chalcap.pcapng"
KEYS = "files/secrets.log"   # CLIENT_RANDOM NSS key-log -> decrypts the TLS

out = subprocess.run(
    ["tshark", "-2",
     "-R", "ip.src==10.10.20.13 and http and frame.len==6855",
     "-T", "fields", "-e", "http.file_data",
     "-o", f"tls.keylog_file:{KEYS}", "-r", PCAP],
    capture_output=True, text=True).stdout.strip()

data = bytes.fromhex(out)
body = urllib.parse.unquote_plus(data.decode("latin1"))   # the POST body is form-encoded
print(re.search(r"HTB\{[^}]*\}", body).group(0))
```

```bash
python3 solve.py
# -> HTB{...}
```

The decoded body is a list of stolen credit-card numbers (Amex, etc.) with the flag
interleaved among them.

## Why it worked

The attacker was proxying the victim's traffic — a man-in-the-middle. So although the
exfiltration POST to pastebin rode over HTTPS, the proxy that captured it also possessed the
TLS secrets, and those secrets ended up in `secrets.log`. Confidential data was therefore
transmitted over a channel the defender could fully reconstruct after the fact
([CWE-319](https://cwe.mitre.org/data/definitions/319.html) /
[CWE-312](https://cwe.mitre.org/data/definitions/312.html)). The encryption added no real
secrecy once the session keys leaked. The "marshal" in the title is just theme dressing
(the flag is a Fender Rhodes pun) — the actual lesson is the key-log decrypt.

## Fix / defense

- Never let `SSLKEYLOGFILE` be set in a production environment, and treat any host able to
  transparently intercept TLS (a rogue CA in the trust store, a "Snoopy"-style proxy) as a
  full loss of confidentiality.
- Pin certificates or require mutual TLS so an injected CA cannot silently sit in the middle.
- Monitor egress to paste / file-sharing services and alert on large outbound POSTs from
  servers that have no business uploading data.
