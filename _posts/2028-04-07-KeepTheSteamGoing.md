---
layout: post
title: "Keep the steam going"
date: 2028-04-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, winrm, ntlm, spnego, pcap, secretsdump, ntds, pass-the-hash, psrp, cwe-319]
description: "A packet capture of a compromised control network. The attacker exfiltrated NTDS.dit and ran a post-exploitation shell over encrypted WinRM. Because NTLM message sealing has no forward secrecy, the recovered Administrator NT hash decrypts that WinRM session offline — and the flag is sitting in the decrypted PSRP output."
---

## Overview

Keep the steam going is a Hard HackTheBox Forensics challenge. You get a single 70 MB `capture.pcap` from a compromised OT/steam-control network — no target, no credentials, pure offline analysis. The attacker moved laterally with WMI, pulled tooling over cleartext HTTP, exfiltrated the domain's `NTDS.dit`, and ran a post-exploitation shell over **encrypted WinRM**. The whole challenge is a lesson in why encrypted-in-transit is not the same as secret: WinRM's NTLM message sealing has no forward secrecy, so the NT hash the attacker stole in the *same capture* decrypts their own shell after the fact.

## The technique

WinRM-over-HTTP (port 5985) with NTLM authentication wraps every message body with **RC4 sealing**, keyed by the NTLM session key. That session key is derived deterministically from the user's NT hash — there is no ephemeral key exchange, so anyone holding the NT hash can reconstruct the session key and decrypt the traffic offline. You can spot these sealed bodies by their `Content-Type: multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"`. This is a textbook [cleartext-equivalent transmission of sensitive information](https://cwe.mitre.org/data/definitions/319.html): confidential once, decryptable forever to a hash-holder.

## Solution

**1 — Read the pcap top-down.** The protocol hierarchy and conversation list tell the story before you decode a byte:

```bash
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -q -z conv,tcp | sort -k7 -nr | head
```

You see SMB2 + DCERPC `IWbemServices` (WMI lateral movement), cleartext `GET /rev.ps1` and `GET /n.exe` (attacker tooling), two large uploads to the attacker's `:8080` (credential-database exfil), and a WinRM session on `5985` whose bodies are SPNEGO-encrypted — that's where the flag lives.

**2 — Recover the exfiltrated NTDS.dit + SYSTEM hive.** The two big uploads are base64 wrapped in *fake* `-----BEGIN CERTIFICATE-----` markers to look like TLS. Reassemble the victim-direction stream by TCP sequence number (handles retransmits/reordering), strip the PEM frame, and base64-decode:

```python
from scapy.all import PcapReader, IP, TCP, Raw
import re, base64
segs = {}
for p in PcapReader("capture.pcap"):
    if IP in p and TCP in p and Raw in p and p[IP].src == "192.168.1.10" and p[TCP].sport == 49748:
        segs[p[TCP].seq] = bytes(p[Raw].load)
data = bytearray(); nxt = None
for seq in sorted(segs):
    q = segs[seq]
    if nxt is None or seq == nxt: data += q; nxt = seq + len(q)
    elif seq > nxt: data += q; nxt = seq + len(q)
    else:
        off = nxt - seq
        if off < len(q): data += q[off:]; nxt += len(q) - off
m = re.search(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", data, re.S)
b = re.sub(rb"\s", b"", m.group(1))
open("ntds.dit", "wb").write(base64.b64decode(b + b"=" * (-len(b) % 4)))
```

The decoded magic confirms the loot: `e3a0f73e` = ESE database (`ntds.dit`), `regf` = a registry hive (`SYSTEM`).

**3 — Dump the NT hashes offline.**

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

Use the Administrator's **stored** NT hash for Pass-the-Hash — not the empty-password default `31d6cfe0d16ae931b73c59d7e0c089c0`. (In this capture the NTDS stream dropped a handful of TCP segments, so the ESE database won't fully parse; the hash is still a valid key input and is proven correct the moment it decrypts the WinRM stream to readable XML.)

**4 — Decrypt the WinRM session with the NT hash.** Carve the WinRM TCP stream and feed it to jborean93's `winrm_decrypt.py` (fork `h4sh5/decrypt-winrm`):

```bash
tshark -r capture.pcap -Y 'tcp.stream==25' -w winrm.pcap
python3 winrm_decrypt.py -n <administrator-nt-hash> winrm.pcap > decrypted.txt
```

RC4 is a continuous stream cipher, so the tool decrypts every message in order (separate client-to-server and server-to-client keys). A wrong hash produces garbage on the very first message — instant feedback that you've got the right one.

**5 — Decode the PSRP output.** This is evil-winrm/PSRP, not a plain shell, so the commands and their output are base64 CLIXML inside `rsp:Send` / `rsp:Receive`. Decode those blobs and the flag appears in a command-output `<S>` string:

```python
import re, base64
t = open("decrypted.txt", encoding="latin1").read()
flags = set(re.findall(r"HTB\{[^}]*\}", t))
for b in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", t):
    try: flags |= set(re.findall(r"HTB\{[^}]*\}", base64.b64decode(b + "=" * (-len(b) % 4)).decode("latin1")))
    except Exception: pass
print("\n".join(flags))   # HTB{...}
```

## Why it worked

NTLM message sealing gives confidentiality but **no forward secrecy**: the RC4 sealing key is derived straight from the NTLM session key, which is derived from the user's long-term NT hash. That makes every past WinRM session retroactively decryptable to anyone who later obtains the NT hash. The attacker handed us that hash by exfiltrating `NTDS.dit` in the same capture — so the exfil that gave them the keys to the kingdom also gave the analyst the keys to their shell.

## Fix / defense

- Run WinRM over **HTTPS (5986) with TLS**, or use Kerberos with channel binding — TLS provides transport confidentiality independent of the auth key, so a leaked NT hash no longer decrypts captured traffic.
- Protect `NTDS.dit` at rest and alert on its exfil; large base64 or fake-PEM-wrapped uploads to non-standard ports are a strong indicator of compromise.
- Rotate privileged NT and KRBTGT hashes after any suspected domain-controller compromise — a single leaked NT hash retroactively unlocks every WinRM session it ever authenticated.
