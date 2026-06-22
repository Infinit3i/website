---
layout: post
title: "PortSwigger: Unprotected Admin Functionality with Unpredictable URL"
date: 2027-09-21 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, forced-browsing, security-through-obscurity, javascript-disclosure, admin-panel, cwe-284]
---

This is the sibling of the [previous lab](/posts/portswigger-unprotected-admin-functionality/): the same unauthenticated admin panel, but this time the developers tried harder to hide it. Instead of a guessable `/admin`, the panel lives at a random path like `/admin-mnt4wg` — "unpredictable" enough that you'd never brute-force it. The catch is that the site cheerfully prints that path into the homepage for every visitor to read. The URL was never a secret, and the panel still never checks who you are. Another flavour of [broken access control](https://cwe.mitre.org/data/definitions/284.html).

## Overview

The lab is a single [improper access control](https://cwe.mitre.org/data/definitions/284.html) ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)) issue. There is a working admin panel at an unpredictable, randomly-suffixed path. It enforces **no authentication and no role check** — the developers "protected" it only by making the URL hard to guess. The objective is to find the panel and use it to delete the user `carlos`.

## The technique

Because the path is random, recon like `robots.txt` won't reveal it. But the homepage needs to render an "Admin panel" link for legitimate admins, and it does so with an inline `<script>`:

```js
adminPanelTag = document.createElement('a');
adminPanelTag.setAttribute('href', '/admin-mnt4wg');
adminPanelTag.innerText = 'Admin panel';
```

That `href` *is* the "unpredictable" path, served in plain HTML to anyone who views source. A random URL is not a credential — it's just a string the application is happy to give away. A one-line grep recovers it:

```bash
curl -s https://TARGET/ | grep -oE "/admin-[a-z0-9]+"
```

Visiting the disclosed path returns the admin panel — a list of users, each with a delete link — with no login required. Its delete action runs as a plain anonymous request:

```
GET /admin-mnt4wg/delete?username=carlos
```

The server responds `302` (redirect back to the panel) and `carlos` is gone. The lab status flips to **Solved**.

### A small wrinkle: the path rotates

On this particular instance the random path string changed on every page load, so a path grabbed in one request returned `404` by the time the next request fired. The fix is to **extract and use the path within the same session**, keeping a shared cookie jar so the server stays consistent:

```bash
B="https://TARGET"
P=$(curl -sk -c cookies.txt "$B/" | grep -oE "/admin-[a-z0-9]+" | head -1)
curl -sk -b cookies.txt "$B$P/delete?username=carlos" -o /dev/null -w '%{http_code}\n'   # 302
```

## Why it works

This is **security through obscurity**: trusting that nobody will discover a hidden URL, rather than verifying that whoever requests it is allowed to. Two failures stack up:

1. **The "secret" isn't secret.** The admin path is emitted into client-side HTML/JS for every visitor. Secret URLs leak constantly — in inline scripts, comments, JavaScript source maps, `sitemap.xml`, referrer headers, and browser history.
2. **The panel performs no authorization.** Even if the URL were truly unguessable, the panel and its delete endpoint never check the requester's identity or role. The URL was doing 100% of the (non-existent) access control.

## The fix

- **Enforce server-side authorization on every admin route and action.** Verify the session belongs to an administrator before rendering the panel or processing `/delete`. The URL must never be the access control.
- **Never treat an unpredictable or secret URL as protection.** Don't emit admin paths into client-side HTML/JS, and assume any URL you ship can be read by anyone.
- **Apply deny-by-default access control to the entire admin namespace**, so a forgotten or newly-added admin endpoint is locked down automatically rather than exposed by default.

## CWE

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- OWASP [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
