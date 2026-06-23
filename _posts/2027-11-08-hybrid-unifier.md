---
title: "hybrid unifier"
date: 2027-11-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, diffie-hellman, key-exchange, small-subgroup, aes-cbc, cwe-322]
description: "A 'hybrid' Diffie-Hellman + AES API never checks the client's public key, so sending a public key of 1 forces the shared secret to a constant and hands you the entire AES session key for free."
---

## Overview

hybrid unifier is an easy HackTheBox **Crypto** challenge. It exposes a Flask API that performs a Diffie-Hellman key exchange and then wraps the rest of the session in AES-CBC — "hybrid" cryptography. The flaw is a classic one: the server computes the shared secret from your supplied public key but **never validates it**. By sending a degenerate public key of `1`, the shared secret is forced to a constant the attacker already knows, which makes the AES session key fully recoverable without ever solving the discrete logarithm problem.

## The technique

The server derives its session key like this:

```python
def establish_session_key(self, client_public_key):
    key = pow(client_public_key, self.a, self.p)   # no validation of client_public_key
    self.session_key = sha256(str(key).encode()).digest()
```

A safe Diffie-Hellman implementation rejects degenerate public keys — `0`, `1`, `p-1`, and anything outside the intended large prime-order subgroup — before using them. This server accepts **any integer**, so the client can pick a public key that *forces* the shared secret to a value it already knows. This is the trivial end of the [small-subgroup confinement](https://cwe.mitre.org/data/definitions/322.html) family:

| client public key | shared secret `pow(x, a, p)` | session key |
|---|---|---|
| `0` | `0` | `sha256("0")` |
| `1` | `1` (for any secret `a`) | `sha256("1")` |
| `p-1` | `±1` (depends on parity of `a`) | one of two known keys |

Sending **`client_public_key = 1`** is the cleanest: `1` raised to any exponent modulo `p` is `1`, so the session key is deterministically `sha256(b"1").digest()` regardless of the server's secret exponent. The entire "end-to-end encryption" collapses because the attacker owns the key.

The protocol then has four steps:

1. `POST /api/request-session-parameters` → returns `g = 2` and a 384-bit prime `p`.
2. `POST /api/init-session` with your public key → server fixes the session key.
3. `POST /api/request-challenge` → an AES-CBC ciphertext of 24 random challenge bytes.
4. `POST /api/dashboard` with `sha256(challenge_plaintext).hex()` plus an AES-CBC packet whose action is `flag`.

Once the key is known, every step is just honest protocol participation: decrypt the challenge, hash its plaintext to pass the gate, and ask for the flag.

## Solution

The full solver sends the malicious public key, derives the known AES key, and walks the protocol:

```python
#!/usr/bin/env python3
import sys, requests
from hashlib import sha256
from base64 import b64encode as be, b64decode as bd
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

HOST, PORT = sys.argv[1], sys.argv[2]
BASE = f"http://{HOST}:{PORT}"
s = requests.Session()

# Step 1+2: send malicious public key = 1 -> shared secret forced to 1
s.post(f"{BASE}/api/request-session-parameters")
s.post(f"{BASE}/api/init-session", json={"client_public_key": 1})

# Known session key: shared secret == 1 -> sha256(str(1))
KEY = sha256(b"1").digest()

def dec(b64):
    raw = bd(b64.encode()); iv, ct = raw[:16], raw[16:]
    return unpad(AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct), 16)

def enc(data):
    iv = os.urandom(16)
    ct = iv + AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(data.encode(), 16))
    return be(ct).decode()

# Step 3: decrypt the challenge with our known key
ec = s.post(f"{BASE}/api/request-challenge").json()["encrypted_challenge"]
challenge = dec(ec)

# Step 4: answer the challenge and request the flag
r = s.post(f"{BASE}/api/dashboard", json={
    "challenge": sha256(challenge).hexdigest(),
    "packet_data": enc("flag"),
}).json()
print(dec(r["packet_data"]).decode())
```

Running it against the live instance prints the flag:

```bash
python3 solve.py <target-ip> <target-port>
# [+] FLAG: HTB{...}
```

## Why it worked

Diffie-Hellman security rests on the public keys living in a large prime-order subgroup. By skipping validation of the peer's public key, the server let the attacker choose `1` — a fixed point of exponentiation whose every power is `1` — collapsing the shared secret to a constant. The AES layer on top is irrelevant the moment the key derivation becomes predictable.

## Fix / defense

- **Validate every Diffie-Hellman public key** before use: reject `pub <= 1` and `pub >= p-1`, and require subgroup membership (`pow(pub, q, p) == 1` for subgroup order `q`).
- Prefer standardized groups (RFC 7919 ffdhe) or X25519, which fold these checks into the design.
- Never derive a session key from an unvalidated shared secret — [CWE-322](https://cwe.mitre.org/data/definitions/322.html) (key exchange without entity authentication) / [CWE-320](https://cwe.mitre.org/data/definitions/320.html) (key management errors). The weakness class is "small-subgroup / invalid-curve confinement."
