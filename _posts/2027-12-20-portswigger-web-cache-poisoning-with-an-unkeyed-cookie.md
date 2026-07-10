---
layout: post
title: "PortSwigger: Web cache poisoning with an unkeyed cookie"
date: 2027-12-20 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebCachePoisoning]
tags: [portswigger, web-cache-poisoning, unkeyed-cookie, cache-key, xss, cwe-525, cwe-79]
---

A cache sits in front of this shop to serve popular pages fast. To decide whether two requests are "the same page" — and can therefore share one stored response — it builds a **cache key** from parts of the request. Here the key is just the **host + path**, and it ignores cookies. That omission ([CWE-525](https://cwe.mitre.org/data/definitions/525.html) / [CWE-79](https://cwe.mitre.org/data/definitions/79.html)) is the whole bug, because the app *reflects* a cookie into the page.

## Overview

The home page sets a front-end routing cookie and echoes its value straight into a chunk of JavaScript:

```
Set-Cookie: fehost=prod-cache-01
```

```js
data = {"host":"...","path":"/","frontend":"prod-cache-01"}
```

Two facts together make this exploitable:

1. The origin reflects the `fehost` cookie value into that `"frontend":"..."` string.
2. The cache key does **not** include the cookie, so a response built from *my* `fehost` cookie is stored under the same plain `/` key that every normal visitor requests.

So if I put an XSS payload in `fehost` and get that response cached, everyone who loads the home page is served my payload — the cookie that created it is invisible to both the cache and the victim.

## Breaking out of the JavaScript string

The value lands inside a double-quoted string. To run code and keep the JavaScript valid, I close the quote, run my code, and re-open a quote:

```
fehost=someString"-alert(1)-"someString
```

which reflects as:

```js
data = {...,"frontend":"someString"-alert(1)-"someString"}
```

The engine reads `"someString" - alert(1) - "someString"` as a subtraction, and evaluating it *calls* `alert(1)`.

I confirmed the reflection first with a throwaway `?cb=x` query parameter. On this lab the **query string is part of the cache key** while the cookie is not, so `?cb=x` gives me a private cache entry to probe against without touching the shared `/` entry that visitors read:

```bash
curl -sk -H 'Cookie: fehost=someString"-alert(1)-"someString' \
  'https://LAB/?cb=x' | grep frontend
# -> "frontend":"someString"-alert(1)-"someString"}
```

## Poisoning the shared cache entry

The cache already held a fresh clean copy of `/` (`Cache-Control: max-age=30`), so my poison requests were simply handed that clean copy back — `X-Cache: hit`, nothing stored. The move is to keep sending the poison request until **my own** request returns `X-Cache: miss`: that miss is the instant the entry expired and *my* payloaded response is the one the cache stored.

```bash
until curl -sk -H 'Cookie: fehost=someString"-alert(1)-"someString' \
  'https://LAB/' -D - -o /tmp/p.html | grep -qi 'x-cache: miss' \
  && grep -q 'alert(1)' /tmp/p.html; do :; done
```

Verified as an anonymous victim (no cookie at all):

```bash
curl -sk -D - 'https://LAB/'
# -> x-cache: hit, and the body contains someString"-alert(1)-"someString
```

The lab's victim bot then browsed the poisoned home page, `alert(1)` fired, and the status widget flipped to **Solved**.

## Why it worked

The victim does nothing unusual — no crafted cookie, no crafted link. They just visit `/`. Because my poisoned response is sitting in the shared cache under the plain `/` key, every request for `/` during the cache lifetime is served my XSS. The attacker's malicious cookie built the response but is invisible to the cache key and to the victim.

## How to fix it

- **Key the cache on every input that changes the response.** If `fehost` affects the body, include the cookie in the cache key, or mark those responses `Cache-Control: no-store`.
- **Encode reflected values.** JSON/JS-string-encode the cookie before embedding it in a script object so a `"` can never break out.
- **Don't reflect infrastructure cookies at all.** A front-end routing hint like `fehost` should never appear in client-visible HTML or JavaScript.
