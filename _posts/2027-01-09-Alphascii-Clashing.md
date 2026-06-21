---
title: "Alphascii Clashing"
date: 2027-01-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, md5, hash-collision, authentication-bypass]
description: "A Very Easy Crypto challenge built on a login service that keys authentication on md5(username) but decides identity by comparing the username string. MD5 is collision-broken, so two different alphanumeric strings can share one digest — register as the first, log in as the second, and a backdoor branch meant to be unreachable prints the flag."
---

## Overview

`Alphascii Clashing` is a Very Easy HackTheBox **Crypto** challenge. The target is a tiny login
service that authenticates users on the pair `[md5(username), password]` but then decides
*identity* by comparing the raw username string. The author parked the flag in a branch they
believed was unreachable — the case where the hash and password match but the username string
does not. Because MD5 fails collision resistance, that "impossible" case is trivial to reach.
The whole solve is to register one half of a known MD5 collision pair and log in with the other.

## The technique

The vulnerability is [use of a weak hash as an identity](https://cwe.mitre.org/data/definitions/328.html)
([CWE-328](https://cwe.mitre.org/data/definitions/328.html)). The login handler looks like this:

```python
usr_hash = md5(usr.encode()).hexdigest()
for db_user, v in users.items():
    if [usr_hash, pwd] == v:
        if usr == db_user:
            print(f'[+] welcome, {usr}')
        else:
            print(f"... :: {open('flag.txt').read()}")   # the backdoor
            exit()
```

Authentication is decided by `md5(username)` plus the password, but the username's *identity*
is the string itself. The author assumed `[md5(usr), pwd] == v` could only ever be true when
`usr == db_user`, making the `else` branch dead code — so they left the flag there.

That assumption only holds if MD5 is collision-resistant. It is not: since 2004, distinct inputs
that produce an identical MD5 digest are cheap to generate. If two different strings collide,
one authenticates as the other while failing the string-equality check — and the "unexpected
user" branch fires.

Registration is gated by `usr.isalnum() and pwd.isalnum()`, but that filter is input hygiene,
not a security control: Marc Stevens published fully **alphanumeric** ASCII MD5 collisions
(TEXTCOLL), so the gate is satisfied anyway.

## Solution

Use a published alphanumeric MD5 collision pair. These two strings differ only at the 22nd
character (`A` vs `E`) yet share one digest:

```
S1 = TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
S2 = TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
md5(S1) == md5(S2) == faad49866e9498fc1719f5289e7a0269
```

1. **Register** username `S1` with a password (both alphanumeric, so the `isalnum()` gate
   accepts them). The service stores `users[S1] = [md5(S1), password]`.
2. **Log in** as username `S2` with the same password. `md5(S2) == md5(S1)` and the password
   matches, so `[usr_hash, pwd] == v` is true against the `S1` record — but `S2 != S1`, so the
   backdoor branch runs and prints the flag.

The working solver:

```python
#!/usr/bin/env python3
import json, sys
from hashlib import md5
from pwn import remote

S1 = "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
S2 = "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
PWD = "collide123"
assert md5(S1.encode()).hexdigest() == md5(S2.encode()).hexdigest() and S1 != S2

io = remote(sys.argv[1], int(sys.argv[2]))
io.recvuntil(b"Option (json format) ::"); io.sendline(json.dumps({"option": "register"}).encode())
io.recvuntil(b"::"); io.sendline(json.dumps({"username": S1, "password": PWD}).encode())
io.recvuntil(b"Option (json format) ::"); io.sendline(json.dumps({"option": "login"}).encode())
io.recvuntil(b"::"); io.sendline(json.dumps({"username": S2, "password": PWD}).encode())
print(io.recvall(timeout=5).decode(errors="replace"))
```

Run it against the instance:

```bash
python3 solve.py <host> <port>
```

The flag (`HTB{...}`, redacted here) appears in the login response.

## Why it worked

MD5 has been collision-broken for two decades, and chosen-prefix collisions are practical with
tools like `fastcoll` and `hashclash`. Any system that treats `md5(x)` as a stand-in for the
identity of `x` can be deceived by two inputs that share a digest. The `isalnum()` filter looked
like a constraint but provided no protection, because alphanumeric collisions exist.

## Fix / defense

- Never derive or compare identity from a hash — compare the canonical username or user id directly.
- If a digest is genuinely required, use a collision-resistant hash (SHA-256 / SHA-3), never MD5 or SHA-1.
- Store a per-user salted password hash (bcrypt / argon2) bound to the exact account row, and
  authenticate against that — not a shared `[hash, password]` tuple.
- Treat input-charset filters such as `isalnum()` as input hygiene, never as a security boundary.
