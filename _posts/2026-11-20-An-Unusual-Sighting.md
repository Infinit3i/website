---
title: "An Unusual Sighting"
date: 2026-11-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, dfir, ssh, log-analysis, incident-response, cwe-778]
description: "A Very Easy Forensics challenge: an OpenSSH server log and a bash history from a dev server. A docker service quizzes you on six facts about the intrusion and hands back the flag. The whole solve is three log-triage tricks — pivot on operating hours, read the offered public-key fingerprint, and time-bound the attacker's commands."
---

## Overview

`An Unusual Sighting` is a Very Easy HackTheBox **Forensics** challenge. You are handed two artifacts pulled from a compromised dev server — an OpenSSH **server** log (`sshd.log`) and a timestamped **bash history** (`bash_history.txt`) — plus a `nc` service that asks six questions about the intrusion and prints the flag once you answer them all. The only context clue in the brief is that Korp's operating hours are **0900–1900**; that single sentence is the entire solve, because it tells you what "normal" looks like so you can spot what isn't.

## The technique

This is straight DFIR log triage, and three correlation tricks do all the work.

**1 — Pivot on the operating-hours window.** Pull every successful login and discard the ones inside business hours. One line is left over, and it is `root`, at 04:00, from an IP that appears nowhere else in the log:

```
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```

**2 — The attacker's fingerprint is the *offered, failed* key, not a successful one.** An SSH client always offers its public key *before* falling back to password authentication. So the `Failed publickey` line immediately above the accepted login carries the attacker's own key fingerprint — even though they ultimately logged in with a password:

```
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 ... ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 ...
```

This is the step most people miss — they read the *accepted* line, which has no fingerprint, instead of the rejected key offer just above it.

**3 — Time-bound the activity with bash history.** The history lines that fall inside the 04:00 session window give you the first and last attacker commands:

```
[2024-02-19 04:00:18] whoami            <- first command
...
[2024-02-19 04:14:02] ./setup           <- last command before logout
```

Between them sits the rest of the intrusion: recon (`uname -a`, `cat /etc/passwd`, `cat /etc/shadow`, `ps faux`), then a trojaned `iproute2` tarball pulled from a typosquat domain (`gnu-packages.com`), extracted, `shred -zu`'d to frustrate forensics, and executed via `./setup`. Insufficient logging and review of exactly this kind of authentication event is [CWE-778](https://cwe.mitre.org/data/definitions/778.html).

## Solution

The docker service asks six questions; each answer comes straight out of the two logs:

| # | Question | Answer |
|---|----------|--------|
| 1 | SSH server IP:PORT | `100.107.36.130:2221` |
| 2 | First successful login | `2024-02-13 11:29:50` |
| 3 | Unusual login time | `2024-02-19 04:00:14` |
| 4 | Attacker key fingerprint | `OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4` |
| 5 | First command | `whoami` |
| 6 | Last command before logout | `./setup` |

Rather than typing answers by hand, a small `pwntools` bot reads each `> ` prompt, keyword-matches it to the right pre-derived fact, and sends it — then scrapes `HTB{...}` from the final reply.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re
from pwn import remote, context
context.log_level = "info"

HOST, PORT = sys.argv[1], int(sys.argv[2])

ANSWERS = {
    "ip_port":     "100.107.36.130:2221",
    "first_login": "2024-02-13 11:29:50",
    "odd_login":   "2024-02-19 04:00:14",
    "fingerprint": "OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4",
    "first_cmd":   "whoami",
    "last_cmd":    "./setup",
}

def pick(p):
    p = p.lower()
    if "fingerprint" in p:                                 return ANSWERS["fingerprint"]
    if "ip" in p and "port" in p:                          return ANSWERS["ip_port"]
    if "first" in p and "command" in p:                    return ANSWERS["first_cmd"]
    if ("last" in p or "final" in p) and "command" in p:   return ANSWERS["last_cmd"]
    if "unusual" in p:                                     return ANSWERS["odd_login"]
    if "first" in p:                                       return ANSWERS["first_login"]
    return ""

io = remote(HOST, PORT)
flag = None
for _ in range(20):
    chunk = io.recvuntil(b"> ", timeout=10).decode(errors="replace")
    sys.stdout.write(chunk)
    if (m := re.search(r"HTB\{[^}]+\}", chunk)):
        flag = m.group(0); break
    io.sendline(pick(chunk).encode())
if not flag:
    tail = io.recvrepeat(3).decode(errors="replace")
    m = re.search(r"HTB\{[^}]+\}", tail); flag = m.group(0) if m else None
print(f"\n[+] FLAG: {flag}")
```

Run it against the spawned instance:

```bash
python3 solve.py <ip> <port>
# [+] Correct!  (x6)
# [+] Here is the flag: HTB{...}
```

## Why it worked

The challenge is a faithful miniature of real SSH incident response. Anomalies only become visible against a *baseline* — here, business hours — and the single off-hours `root` login is the entire thread to pull. Attribution then comes from a protocol detail: because the SSH handshake tries public-key auth first, the rejected key offer reveals the attacker's key even when the actual login succeeded by password. Dwell time and intent come from correlating the bash-history timestamps back to that one session.

## Fix / defense

- Alert on successful `root` SSH logins outside business hours, and on logins from never-before-seen source IPs.
- Log and review offered-but-rejected public-key fingerprints — they attribute the client regardless of which auth method finally succeeds.
- Ship shell history and auth logs off-host in real time so an attacker's `shred` cannot erase the local copy.
- Pin package installs to verified, signed repositories so a typosquat download like `gnu-packages.com` never executes.
