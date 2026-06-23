---
layout: post
title: "Bloom Bloom"
date: 2027-11-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, blum-blum-shub, prng, shamir-secret-sharing, lagrange]
---

A post-apocalyptic story about teleporting robot guards whose movements you must "predict" — which is the flavour text for a broken pseudo-random number generator. The challenge hands you a `source.py` and an `output.txt`: a homemade **Blum Blum Shub** keystream derives the AES keys that protect five messages, and a separate `KEY` (with a published SHA-256 prefix) encrypts the flag. The intended path is to notice the BBS generator collapses to a constant output, decrypt the messages for free, then reassemble the real `KEY` with Shamir Secret Sharing.

## Overview

- **Category:** Crypto (Easy)
- **Bug class:** [use of a cryptographically weak PRNG](https://cwe.mitre.org/data/definitions/338.html) — Blum Blum Shub iterated-squaring keystream converges to a fixed point.
- **One-line path:** BBS keystream collapses to all-`0`/all-`1` → only two possible AES keys → decrypt the five messages → recover 5 Shamir shares + a prime field → Lagrange-interpolate the secret `KEY` → AES-ECB decrypt the flag.

## The technique

The generator is a textbook Blum Blum Shub:

```python
class BBS:
    def reset_params(self):
        self.state = randint(2, 2 ** self.bits - 2)
        self.m = getPrime(self.bits//2) * getPrime(self.bits//2) * randint(1, 2)

    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)   # x <- x^2 mod m
        return str(self.state % 2)                # emit the LSB
```

The flaw is the trailing `* randint(1, 2)`. About half the time it is `2`, so `m = 2·p·q` is **even** — and reducing modulo an even number cannot change a value's parity. Since `x²` always has the same parity as `x`, every emitted LSB (`state % 2`) equals the parity of the *seed*, and the whole 256-bit output is the constant `'0'*256` (even seed) or `'1'*256` (odd seed). (The squaring fixed points `0` and `1` give those same two constants, but the even-modulus parity argument is the dominant cause.) Simulating `BBS(512, 256)`: **every** run with an even `m` produces a constant output and no run with an odd `m` does — overall ~25 % output `'0'*256` and ~23 % output `'1'*256`, so the supposed 2²⁵⁶ keystream space collapses to just **two** usable outputs. (With the `* 2`, `m` isn't even a proper Blum integer.)

Each of the five messages is encrypted **ten independent times**:

```python
key = sha256(out.encode()).digest()    # out = the 256-bit BBS string
enc_messages.append([encryptor.encrypt(msg) for _ in range(10)])
```

The probability that *none* of those ten encryptions used a convergent keystream is roughly `(1/2)¹⁰`, so for every message at least one ciphertext was encrypted under a fully deterministic key: either `sha256(b'0'*256)` or `sha256(b'1'*256)`. No state recovery, no factoring — just two candidate keys to try.

## Solution

The decrypted messages contain a guided treasure hunt: five Shamir Secret Sharing shares plus the prime field, with instructions to interpolate the polynomial and use its constant term as the flag key. The full solve runs offline against the provided `output.txt`:

```python
import ast
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes

data = open('files/crypto_bloom_bloom/output.txt').read().splitlines()
enc_messages = ast.literal_eval(data[0])
enc_flag = bytes.fromhex(data[1])

# BBS converges to all-0 or all-1 -> only two possible AES keys
CANDIDATE_KEYS = [sha256(b'0'*256).digest(), sha256(b'1'*256).digest()]

def decrypt_msg(group):                      # group = 10 (iv,ct) of the SAME plaintext
    for iv, ct in group:
        for k in CANDIDATE_KEYS:
            pt = AES.new(k, AES.MODE_CBC, bytes.fromhex(iv)).decrypt(bytes.fromhex(ct))
            try:
                up = unpad(pt, 16)
                if all(32 <= b < 127 or b in (10, 13, 9) for b in up):
                    return up.decode()       # convergent-key hit -> printable
            except ValueError:
                pass
    raise RuntimeError("no convergent-key plaintext found")

shares, p = [], None
for group in enc_messages:
    txt = decrypt_msg(group)
    shares.append(ast.literal_eval(txt.split('#: ')[1].strip()))   # (x, y) share
    if 'GF(' in txt:
        p = int(txt.split('GF(')[1].split(')')[0])                 # prime field

# Shamir SSS: secret = P(0) = polynomial constant term; Lagrange-interpolate at x=0 mod p
def lagrange_at_zero(points, p):
    total = 0
    for j, (xj, yj) in enumerate(points):
        num = den = 1
        for m, (xm, _) in enumerate(points):
            if m == j:
                continue
            num = (num * (-xm)) % p
            den = (den * (xj - xm)) % p
        total = (total + yj * num * pow(den, -1, p)) % p
    return total

KEY = long_to_bytes(lagrange_at_zero(shares, p))
assert sha256(KEY).hexdigest().startswith('709149eb5baf8f8cb617226854a7b4f3')
print(unpad(AES.new(KEY, AES.MODE_ECB).decrypt(enc_flag), 16).decode())
```

```bash
python3 solve.py
# HTB{...}
```

The published `sha256(KEY)` prefix is a built-in correctness oracle — the `assert` trips before you ever touch the flag ciphertext if the interpolation is wrong, so there is no guesswork. The reconstruction is pure-Python big integers (`pow(den, -1, p)` for the modular inverse); no Sage or `PolynomialRing` is required.

## Why it worked

Two independent design errors chain together. First, an iterated map `x ← f(x)` with absorbing states (squaring has `{0, 1}`) cannot be used as a keystream — a large slice of seeds produces a constant output, and re-encrypting the same plaintext ten times all but guarantees you observe one. Second, deriving a key from that low-entropy keystream means there is no key to brute-force at all; the effective keyspace is the two convergent strings. Once the messages decrypt, the Shamir scheme is being used exactly as intended — you legitimately hold all five shares, so Lagrange interpolation at `x = 0` recovers the constant term that is the flag's AES key.

## Fix / defense

Use a vetted CSPRNG (`secrets` / `os.urandom`) for any key material. If Blum Blum Shub is genuinely required, enforce a proper Blum integer (`m = p·q` with `p ≡ q ≡ 3 (mod 4)`, both safe primes), reject seeds that fall into the small fixed-point or short-cycle set, and never re-use a low-entropy keystream directly as an encryption key — especially while encrypting the same plaintext many times, where each repeat is another chance to land on a constant output. The general heuristic for attackers stays the same: before reaching for lattices or factoring against a homemade PRNG-keyed cipher, first test whether the keystream is simply all-zeros or all-ones.
