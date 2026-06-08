---
title: "Expressway"
date: 2026-06-28 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, ike, ipsec, aggressive-mode, psk-crack, tftp, ike-scan, password-reuse]
image:
    path: /assets/Images/Expressway-avatar.png
    alt: Expressway
description: "A TCP scan shows only SSH, but a UDP scan reveals an IKE/IPsec VPN and an unauthenticated TFTP server; the TFTP config leaks a username, an IKE Aggressive Mode scan leaks the Pre-Shared Key hash, and cracking it offline yields an SSH password reused for the user flag."
---
## Overview

Expressway is an easy-difficulty Linux box whose entire foothold lives on UDP. A standard TCP scan finds only OpenSSH and looks like a dead end. Scanning UDP surfaces an IKE/IPsec VPN on `500/udp` and an unauthenticated TFTP server on `69/udp`. TFTP hands over a Cisco router config containing a username, the IKE service is misconfigured for Aggressive Mode (which leaks a crackable Pre-Shared Key hash), and the cracked PSK has been reused as the SSH password. This post covers recon through the user flag.

## Machine Matrix

<div style="text-align:center;margin:1.5rem 0;">
<svg viewBox="-60 0 420 300" width="420" style="max-width:100%;font-family:sans-serif;font-size:13px;">
  <polygon points="150.0,40.0 254.6,116.0 214.7,239.0 85.3,239.0 45.4,116.0" fill="none" stroke="#888" stroke-opacity="0.4"/>
  <polygon points="150.0,76.7 219.7,127.4 193.1,209.3 106.9,209.3 80.3,127.4" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <polygon points="150.0,113.4 184.8,138.7 171.5,179.6 128.5,179.6 115.2,138.7" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <g stroke="#888" stroke-opacity="0.4">
    <line x1="150" y1="150" x2="150.0" y2="40.0"/>
    <line x1="150" y1="150" x2="254.6" y2="116.0"/>
    <line x1="150" y1="150" x2="214.7" y2="239.0"/>
    <line x1="150" y1="150" x2="85.3" y2="239.0"/>
    <line x1="150" y1="150" x2="45.4" y2="116.0"/>
  </g>
  <polygon points="150.0,40.0 233.7,122.8 150.0,150.0 124.1,185.6 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Enumeration-dominant: UDP scanning reveals IKE/IPsec and TFTP, an Aggressive Mode PSK-hash crack and password reuse for SSH — realistic networking misconfig with no CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 10.0p2 | Debian, no creds — dead end |
| 500/udp | isakmp (IKE) | open, IPsec VPN |
| 69/udp | tftp | open\|filtered, no auth |

A TCP scan shows only SSH:

```bash
nmap --open -p- 10.10.10.X
nmap -p 22 -sV -sC -Pn 10.10.10.X
```

`22/tcp open ssh OpenSSH 10.0p2 Debian` — and with no credentials, that goes nowhere. The interesting surface is on UDP, so scan there next:

```bash
sudo nmap -sU --top-port=20 10.10.10.X
```

`500/udp` (isakmp) comes back **open** and `69/udp` (tftp) **open|filtered**. TFTP is worth enumerating with the `tftp-enum` script:

```bash
sudo nmap -sU -p 69 --script=tftp-enum.nse 10.10.10.X
```

The script reports a file named `ciscortr.cfg` sitting on the TFTP server.

## Enumeration

TFTP requires no authentication by default, so the config file is simply downloadable:

```bash
tftp 10.10.10.X -c get ciscortr.cfg
```

Reading it surfaces two useful facts: a user account named `ike`, and the target hostname `expressway`. The rest is routine router config for various networks and interfaces.

```
username ike password [redacted]
hostname expressway
```

`500/udp` is the Internet Key Exchange (IKE) service, the key-negotiation component of the IPsec VPN framework. The right tool to footprint it is `ike-scan`. A plain probe shows how the VPN is configured:

```bash
ike-scan -M 10.10.10.X
```

The handshake comes back with `Auth=PSK`, `Enc=3DES`, `Hash=SHA1` — the VPN authenticates with a Pre-Shared Key. That is the opening: an IKE **Aggressive Mode** exchange leaks a hash derived from the PSK before authentication completes, and that hash can be cracked offline.

## Foothold

**1 — Capture the PSK hash with an Aggressive Mode scan.** `ike-scan -A` forces Aggressive Mode and `--pskcrack` writes the leaked PSK hash to a file:

```bash
ike-scan -M -A --pskcrack=k.hash 10.10.10.X
```

The output also reveals the VPN identity (`ID=ike@expressway.htb`) and writes `k.hash` — a string of the form `<hash>:<salt...>` ready for an offline dictionary attack.

**2 — Crack the PSK offline.** No further interaction with the server is needed; the hash is cracked entirely locally:

```bash
hashcat k.hash /usr/share/wordlists/rockyou.txt
```

It falls to a `rockyou.txt` entry: `freakingrockstarontheroad`.

**3 — SSH in as `ike`.** The cracked PSK has been reused as the login password for the `ike` user found earlier in `ciscortr.cfg`:

```bash
ssh ike@10.10.10.X
```

## User flag

With a shell as `ike`, the user flag is in the home directory:

```bash
cat /home/ike/user.txt   # [redacted]
```

Foothold complete: UDP enumeration to find IKE/TFTP, an unauthenticated config leak for the username, an Aggressive Mode PSK crack for the password, and password reuse to SSH in.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Expressway-avatar.png" alt="Expressway" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
