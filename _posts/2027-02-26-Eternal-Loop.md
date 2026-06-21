---
title: "Eternal Loop"
date: 2027-02-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, zip, nested-archive, zip2john, john, sqlite]
description: "An Easy Misc challenge: an archive wrapped roughly five hundred times, where each layer's password is the name of the zip inside it. Automate the peel until one layer breaks the pattern, crack that one with john, and read the flag out of the SQLite database hiding at the bottom."
---

## Overview

**Eternal Loop** is an Easy HackTheBox **Misc** challenge. You download a single
zip that turns out to be a matryoshka doll: roughly five hundred password-protected
archives nested one inside the next. The trick is that each layer's password is
self-describing — it's the *name* of the zip stored inside it — so the whole stack
peels open with a short loop. One layer near the bottom breaks the pattern with a
real password (cracked instantly with `john`), and the final payload is a SQLite
database with the flag sitting in one of its tables. No exploit, just patient,
scripted unwrapping.

## The technique

The outer download opens with the usual `hackthebox` password and gives you
`37366.zip`. Open that and you find it contains exactly **one** file: `5900.zip`.
Try to read `5900.zip` and it's encrypted — but the password is simply `5900`, the
name of the file minus its `.zip` extension. That relationship holds for every
layer:

```
37366.zip --(pw "5900")--> 5900.zip --(pw "....")--> ....zip --> ...
```

So you never have to guess: read `namelist()[0]`, strip the `.zip`, and use that
string as the password for the next read. Loop until the bytes you extract no
longer start with the zip magic `PK` (`\x50\x4b`) — that's your signal you've
reached the real payload.

Around depth 500 the inner entry is named **`DoNotTouch`** (no `.zip` extension),
and its name is *not* the password. That's the cue to stop looping and switch to an
offline crack.

## Solution

First, automate the peel. Each layer's password is the inner file's own name:

Create `solve.py`:

```python
#!/usr/bin/env python3
import zipfile

def unwrap(start):
    open("/tmp/cur.zip", "wb").write(open(start, "rb").read())
    depth = 0
    while True:
        z = zipfile.ZipFile("/tmp/cur.zip")
        inner = z.namelist()[0]
        pw = inner[:-4].encode() if inner.endswith(".zip") else b"letmeinplease"
        data = z.read(inner, pwd=pw); z.close()
        depth += 1
        if data[:2] != b"PK":              # no longer a zip -> payload reached
            open("/tmp/final.db", "wb").write(data)
            return inner, len(data), depth
        open("/tmp/cur.zip", "wb").write(data)

name, size, depth = unwrap("files/37366.zip")
print(f"[+] {depth} layers peeled, final entry {name} ({size} bytes)")
```

When the loop hits the `DoNotTouch` layer, the name stops being the password.
Dump a hash for that single archive and crack it — it falls to rockyou instantly:

```bash
zip2john /tmp/cur.zip > dnt.hash
john --wordlist=/usr/share/wordlists/rockyou.txt dnt.hash
# -> letmeinplease  (PKZIP, cracked in well under a second)
```

`DoNotTouch` decrypts to a **SQLite 3 database** (the well-known Chinook sample DB).
Don't trust `strings` — query it properly. The flag is an injected row in the
`employees` table:

```bash
file /tmp/final.db
# /tmp/final.db: SQLite 3.x database
sqlite3 /tmp/final.db "SELECT * FROM employees;" | grep 'HTB{'
# 69|YoMomma|YoPapa|...|HTB{...}
```

Flag: `HTB{...}` *(redacted)*.

## Why it worked

The author needed a recursion deep enough to be tedious by hand but trivial to
automate, so they encoded each layer's password in the inner archive's filename —
making the stack machine-solvable. The lone "real password" layer (`DoNotTouch`)
exists purely to force a quick offline crack instead of a pure loop, and the final
payload is a perfectly normal database where the flag is just another record. The
title is the hint: it's an *eternal loop* of zips, and the way through is to loop
right back.

## Fix / defense

There's no real-world vulnerability here — it's a puzzle — but the shape is the same
one that powers decompression bombs. Any parser that auto-extracts nested archives
should cap **recursion depth** and **total inflated size**, and treat archive member
names as untrusted input rather than as control data (passwords, paths, or
commands). The same discipline that stops a zip bomb from exhausting memory is what
keeps "an archive inside an archive" from becoming a denial-of-service.
