---
layout: post
title: "Secure Source"
date: 2028-03-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, ecdsa, jwt, signature-verification, brainpool, forgery]
description: "A Flask app signs its 'JWT' with ECDSA and checks it on the admin dashboard. The intended path is predicting a Mersenne-Twister nonce, but the verifier reads the public key straight from a cookie, so you just sign the admin token with your own key."
---

## Overview

Secure Source is a Medium crypto challenge: a small Flask notes app issues an "EC256 JWT" on login and gates the flag behind an admin dashboard that verifies that token. The intended solution predicts the weak Mersenne-Twister nonce to recover the server's ECDSA private key — but the token verifier reads the public key from a user cookie, an [improper verification of a cryptographic signature](https://cwe.mitre.org/data/definitions/347.html) ([CWE-347](https://cwe.mitre.org/data/definitions/347.html)) that lets you sign the admin token with a keypair you generate yourself.

## The technique

The app's token is `base64(header) . base64(payload) . base64(r || s)`, where `r || s` is an ECDSA signature over the bytes `base64(header).base64(payload)` on curve brainpoolP256r1. The dashboard route is the flag:

```python
@bp.route('/dashboard')
def dashboard():
    token  = request.cookies.get('token')
    pubkey = request.cookies.get('pubkey').split(',')   # from the client!
    if not jwt.verify_token(pubkey, token): ...redirect
    if not jwt.check_admin(token): ...redirect
    return render_template('dashboard.html', secret=open('/flag.txt').read())
```

`check_admin` only string-matches the payload's `username` against the admin name. And `verify_token` builds the verification point `Q` **from the `pubkey` cookie** and runs textbook ECDSA verification against it — never checking that `Q` is the server's own key.

Verifying a signature only proves *"whoever holds the private key for this public key signed this."* If the attacker chooses the public key, that "whoever" is the attacker. No nonce prediction and no private-key recovery required — you bring your own key.

## Solution

Generate a fresh keypair, sign a forged admin token with it, and hand the server both the token and your public key. The brainpoolP256r1 parameters are the RFC 5639 standard values, so a short pure-Python EC implementation is enough — no `fastecdsa` or Sage needed.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, json, base64, secrets
from hashlib import sha256
import requests

p  = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
a  = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
q  = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997

def inv(x, m): return pow(x, -1, m)

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    l = ((3*x1*x1 + a) * inv(2*y1, p) if P == Q
         else (y2 - y1) * inv(x2 - x1, p)) % p
    x3 = (l*l - x1 - x2) % p
    return (x3, (l*(x1 - x3) - y1) % p)

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

def l2b(n): return n.to_bytes(32, 'big')

def sign(m, d):
    H = int(sha256(m).hexdigest(), 16)
    while True:
        k = secrets.randbelow(q - 1) + 1
        r = mul(k, (Gx, Gy))[0] % q
        if r == 0: continue
        s = inv(k, q) * (H + d*r) % q
        if s: return base64.b64encode(l2b(r) + l2b(s))

d = secrets.randbelow(q - 1) + 1
Q = mul(d, (Gx, Gy))
header  = base64.b64encode(json.dumps({'alg': 'EC256', 'typ': 'JWT'}).encode())
payload = base64.b64encode(json.dumps({'username': 'HTBAdmin1337_ZUSD3uQG4I',
                                       'email': 'a@b.c', 'iat': '1700000000'}).encode())
sig   = sign(header + b'.' + payload, d)
token = (header + b'.' + payload + b'.' + sig).decode()
r = requests.get(sys.argv[1].rstrip('/') + '/dashboard',
                 cookies={'token': token, 'pubkey': f'{Q[0]},{Q[1]}'})
import re; m = re.search(r'HTB\{[^}]+\}', r.text)
print(m.group(0) if m else r.text[:400])
```

Run it against the instance:

```bash
python3 solve.py http://<host>:<port>
# HTB{...}
```

Every check in the verifier passes because the signature really is valid for the public key we supplied, and `check_admin` sees the admin username we baked into the payload.

## Why it worked

The verifier's root of trust was attacker-controlled. A signature scheme's security depends on the verifier knowing *which* public key is authoritative; reading that key from the request collapses the whole scheme to "trust whatever the client says." The challenge's flag hints at the *intended* weakness — a predictable Mersenne-Twister nonce — but the client-supplied key is a strictly simpler break of the same trust model.

## Fix / defense

Pin the verification key server-side — never read it from a cookie, header, or body:

```python
SERVER_PUBKEY = load_trusted_pubkey()          # config/keystore, fixed

def verify_token(token):
    header, payload, sig = token.split('.')
    return ecc.verify(SERVER_PUBKEY, sig, header + '.' + payload)
```

If several keys are legitimate, resolve them by a **trusted key-id against an allow-list**, not by an inline public key. For real JWTs, reject attacker-supplied `jwk`/`jku`/`x5c` headers unless they map to a pre-registered trusted set. It is the same failure family as JWT `alg:none` and RS256→HS256 confusion: never let the token tell you which key (or algorithm) to trust.
