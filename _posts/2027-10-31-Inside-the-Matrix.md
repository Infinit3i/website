---
layout: post
title: "HackTheBox: Inside the Matrix"
date: 2027-10-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, linear-algebra, matrix-cipher, crt, chosen-plaintext]
---

Inside the Matrix is an Easy **Crypto** challenge. The "encryption" is a single matrix multiply over a tiny prime field — and the server politely hands you the key through a debug menu. Once the key is known, decryption is just multiplying by its inverse. The only real puzzle is that the prime modulus is small, secret, and re-rolled on every page, so you recover the flag one modulus at a time and stitch the bytes back together with a little statistics.

## Overview

You connect to a service that shows a "book" with options to **L**ook at a page, **T**urn the page, or **C**heat. Each page is an encrypted 25-byte flag laid out as a 5×5 matrix; the `[C]heat` option leaks both the ciphertext **and** the key. The whole challenge reduces to inverting a known [linear transformation](https://cwe.mitre.org/data/definitions/327.html) and reassembling bytes from their residues modulo several small primes.

## The technique

The server "encrypts" like this:

```python
# FLAG is 25 bytes -> 5x5 matrix `message` (each byte taken mod p)
key = parse(os.urandom(25))          # random 5x5, mod p
p   = randprime(2**4, 2**6)          # a prime in {17,19,...,61}  -- tiny
ct  = (message @ key) % p            # the "ciphertext"
# [C]heat prints (ct, key);  [T]urn re-rolls a NEW prime + NEW key
```

Because the multiply is over a tiny prime, every value you see is `< p`. And because `[T]urn` rotates the prime, repeatedly cheating gives you many `(ct, key)` pairs under *different* primes. That sets up two problems, both solved without any heavy machinery:

1. **The key is disclosed.** A linear map with a known key is not encryption — `message = ct · key⁻¹ (mod p)` (a Gauss-Jordan inverse over GF(p)) recovers the plaintext mod `p`. Since `p < 64`, that only gives `FLAG mod p`, not the real ASCII byte.
2. **The modulus is small and hidden.** `p` is never printed, but every matrix entry is `< p`, so `p > max(entry)` bounds it. Rather than pin `p`, just try **all 12 candidate primes**: a page that actually used prime `q` produces the true `FLAG mod q`; a page that used a different prime produces garbage when you (wrongly) reduce it mod `q`. Over many pages, the **most common residue** per `(prime, position)` is the true one.

To turn residues into bytes, the flag bytes are printable ASCII, so for each position pick the byte `b ∈ [32,126]` whose value matches the per-prime modal residues, weighted by how many pages voted for each (a robust CRT-by-voting). Two of these primes already exceed 255, so a handful of correct residues pins each byte uniquely.

## Solution

The full, runnable solver:

```python
#!/usr/bin/env python3
import sys, socket, ast
from collections import Counter
from sympy import primerange

HOST, PORT = sys.argv[1], int(sys.argv[2])
PAGES = int(sys.argv[3]) if len(sys.argv) > 3 else 80
PRIMES = list(primerange(2**4, 2**6))   # 17,19,...,61

def matinv_mod(M, p):
    n = len(M)
    A = [[M[i][j] % p for j in range(n)] + [1 if j == i else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if A[r][col] % p), None)
        if piv is None:
            return None
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, p)
        A[col] = [(x * inv) % p for x in A[col]]
        for r in range(n):
            if r != col and A[r][col]:
                f = A[r][col]
                A[r] = [(A[r][k] - f * A[col][k]) % p for k in range(2 * n)]
    return [row[n:] for row in A]

def matmul_mod(A, B, p):
    n = len(A)
    return [[sum(A[i][k] * B[k][j] for k in range(n)) % p for j in range(n)] for i in range(n)]

def collect(host, port, pages):
    s = socket.create_connection((host, port), timeout=30); s.settimeout(30)
    buf = b""
    def recv_until(tok):
        nonlocal buf
        while tok not in buf:
            d = s.recv(65536)
            if not d: break
            buf += d
        i = buf.index(tok) + len(tok)
        out, buf = buf[:i], buf[i:]
        return out
    pairs = []
    recv_until(b"> ")
    for _ in range(pages):
        s.sendall(b"C\n")
        data = recv_until(b"> ")
        lines = [l.strip() for l in data.decode(errors="ignore").splitlines() if l.strip().startswith("[[")]
        pairs.append((ast.literal_eval(lines[0]), ast.literal_eval(lines[1])))
        s.sendall(b"T\n"); recv_until(b"> ")
    s.close()
    return pairs

def main():
    pairs = collect(HOST, PORT, PAGES)
    res = {q: [Counter() for _ in range(25)] for q in PRIMES}
    for ct, key in pairs:
        mx = max(max(r) for r in ct + key)
        for q in PRIMES:
            if q <= mx:                      # entries must be < p
                continue
            inv = matinv_mod(key, q)
            if inv is None:                  # key singular mod q
                continue
            m = matmul_mod(ct, inv, q)       # candidate FLAG mod q
            for pos, v in enumerate(m[i][j] for i in range(5) for j in range(5)):
                res[q][pos][v] += 1          # vote
    flag = []
    for pos in range(25):
        modes = {q: res[q][pos].most_common(1)[0] for q in PRIMES if res[q][pos]}
        best = max(range(32, 127), key=lambda b: sum(n for q, (v, n) in modes.items() if b % q == v))
        flag.append(best)
    print("FLAG:", bytes(flag).decode())

if __name__ == "__main__":
    main()
```

Run it against a fresh instance:

```bash
python3 solve.py <ip> <port> 130
```

About 130 leaked pages give a clean, stable recovery — `HTB{...}`. (The flag contains a run of underscores that are simply padding to make it exactly 25 bytes.)

## Why it worked

A keyed *linear* transform over a tiny modulus is not encryption — it is a reversible matrix operation whose key was disclosed through a debug endpoint ([information exposure](https://cwe.mitre.org/data/definitions/200.html)). The only remaining "secret" was the modulus, and it lives in a 12-element space that leaks through the value bound on the matrix entries plus statistical voting across many pages.

## Fix / defense

- Never expose key material — the `[C]heat` option is the entire bug.
- Don't build ciphers from a single linear map; any linear scheme is invertible the moment the transform is known. Use a vetted primitive such as AES with a proper authenticated mode and a per-message nonce.
- A larger or secret modulus would not save a linear scheme once the key is known — the structure, not the parameter size, is the weakness ([CWE-327](https://cwe.mitre.org/data/definitions/327.html)).
