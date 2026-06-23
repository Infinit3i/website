---
layout: post
title: "HackTheBox: Bank-er-smith"
date: 2027-10-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, coppersmith, lattice, fpylll]
---

Bank-er-smith is an Easy **Crypto** challenge built on RSA. The bank's vault gives you a "magic-proof hint" that looks harmless — but it leaks the high bits of one of the RSA primes, and that is enough to factor the modulus outright with Coppersmith's method. No brute force, no oracle abuse: a little lattice reduction recovers the private key and unlocks the vault.

## Overview

A `nc` service exposes three options: get the public certificate (`n`, `e`), calculate a "hint", and unlock a vault. The hint is the prime `p` with its low 256 bits zeroed — i.e. the top 768 bits of a 1024-bit prime handed to you for free. With ~75% of a factor known, **[factoring the modulus](https://cwe.mitre.org/data/definitions/320.html)** becomes a polynomial-time problem via Coppersmith / Howgrave-Graham ("factoring with high bits known"). Recover `p`, derive `d`, decrypt the vault passphrase, and open the vault for the flag.

## The technique

The menu:

| Option | What it gives you |
|--------|-------------------|
| `[1] Get public certificate` | RSA modulus `n` (2048-bit) and `e = 65537` |
| `[2] Calculate Hint` | a constant = `(p >> 256) << 256` — prime `p` with its low **256 bits zeroed** |
| `[3] Unlock Vault` | prompts for a vault name (`vault_68`) then the passphrase |

The banner also prints `c`, the RSA-encrypted vault passphrase.

Recognising the leak: the hint is exactly 1024 bits and its low 256 bits are all zero (`hint & (2**256 - 1) == 0`). So `hint = p - (p mod 2**256)` — the high 768 bits of a 1024-bit prime, with only the bottom 256 unknown.

Write the unknown prime as `p = hint + x` where `0 ≤ x < 2**256`. Because `p | n`, the integer `x` is a **small root of `f(X) = X + hint` modulo `p`**, and `p ≈ n^0.5` (so `beta = 0.5`). Coppersmith's theorem says a monic degree-`d` polynomial that is `≡ 0 (mod b)` for a divisor `b ≥ n^beta` of `n` has all its small roots recoverable up to roughly `n^(beta^2 / d)`. Here `d = 1`, `beta = 0.5`, so the bound is `≈ n^0.25 ≈ 2^512` — the 256-bit unknown is comfortably inside it, so a tiny lattice cracks it instantly.

Kali ships no SageMath, so the lattice + LLL is done with **fpylll**, and the final big-integer root-finding with **sympy `real_roots`** (Sturm sequences + arbitrary-precision `evalf` — `numpy.roots` overflows on these coefficients).

## Solution

Pull `n, e, c, hint` from the menu over one connection, run Coppersmith to recover `p`, derive `d`, decrypt, then unlock the vault. The full, runnable solver:

```python
#!/usr/bin/env python3
import sys, socket, time, re, json
from fpylll import IntegerMatrix, LLL

def fetch_params(host, port):
    s = socket.socket(); s.connect((host, int(port))); s.settimeout(8)
    def rd():
        time.sleep(0.7); out = b""
        try:
            while True:
                d = s.recv(65535)
                if not d: break
                out += d
                t = out.rstrip()
                if t.endswith(b">") or t.endswith(b":"): break
        except: pass
        return out.decode(errors='replace')
    b = rd()
    c = int(b.split("retrieve:")[1].split("\n")[0].strip(), 16)
    s.sendall(b"1\n"); o1 = rd()
    n = int(re.findall(r'\d{50,}', o1)[0])
    em = re.findall(r'\n(\d{1,7})\s', o1); e = int(em[0]) if em else 65537
    s.sendall(b"2\n"); o2 = rd()
    h = int(re.findall(r'\d{50,}', o2)[0])
    return s, rd, n, e, c, h

def pmul(p, q):                       # multiply two integer-coeff polynomials
    r = [0]*(len(p)+len(q)-1)
    for i, pi in enumerate(p):
        for j, qj in enumerate(q):
            r[i+j] += pi*qj
    return r

def coppersmith_high_bits(N, a, X, m=5, t=4):
    """Find x, |x|<X, with (a+x) | N.  f(x)=x+a is 0 mod p>=N^0.5."""
    f = [a, 1]
    fpow = [[1]]
    for _ in range(m):
        fpow.append(pmul(fpow[-1], f))
    polys  = [[(N**(m-i))*ci for ci in fpow[i]] for i in range(m+1)]   # N^(m-i)*f^i
    polys += [[0]*i + fpow[m] for i in range(1, t+1)]                  # x^i * f^m
    deg = max(len(p) for p in polys) - 1
    B = IntegerMatrix(len(polys), deg+1)
    for r, p in enumerate(polys):
        for j, cj in enumerate(p):
            B[r, j] = cj * (X**j)          # scale column j by X^j
    LLL.reduction(B)
    coeffs = [B[0, j] // (X**j) for j in range(deg+1)]   # shortest vector -> h(x)
    from sympy import symbols, Poly, ZZ, Rational
    x = symbols('x')
    pol = Poly(sum(int(coeffs[j])*x**j for j in range(deg+1)), x, domain=ZZ)
    for r in pol.real_roots():             # big-int-safe root finding (not numpy)
        x0 = int(round(Rational(str(r.evalf(400)))))
        for cand in (x0, x0-1, x0+1):
            if a+cand > 0 and N % (a+cand) == 0:
                return a + cand            # recovered prime p
    return None

def main():
    host, port = sys.argv[1], sys.argv[2]
    s, rd, n, e, c, h = fetch_params(host, port)
    p = coppersmith_high_bits(n, h, 1 << 256)
    q = n // p
    d = pow(e, -1, (p-1)*(q-1))
    pt = pow(c, d, n).to_bytes(256, 'big').lstrip(b'\x00')   # vault passphrase
    print("[+] passphrase:", pt)
    s.sendall(b"3\n"); rd()                 # "Which vault would you like to open:"
    s.sendall(b"vault_68\n"); rd()          # "Enter the passphrase:"
    s.sendall(pt + b"\n")
    out = rd()
    fl = re.search(r'HTB\{[^}]+\}', out)
    if fl: print("FLAG:", fl.group())

if __name__ == "__main__":
    main()
```

Running it recovers the passphrase `horcrux_horcrux_Helga_Hufflepuff's_cup`, feeds it to vault `vault_68`, and the bank returns the flag:

```
[+] passphrase: b"horcrux_horcrux_Helga_Hufflepuff's_cup"
FLAG: HTB{...}
```

One trap: the vault id (`vault_68`) is validated *after* the passphrase is entered — a wrong id raises a `KeyError`, so you must supply both the right vault name and the right passphrase.

## Why it worked

The cryptosystem itself — 2048-bit RSA with `e = 65537` — is perfectly sound. The bug is the **side channel**: the bank voluntarily discloses 768 contiguous bits of a secret prime, dressed up as a harmless "fingerprint". Coppersmith's lattice turns "most of a factor" into "all of `n`" in milliseconds, and from there the private key and every message under it fall out.

## Fix / defense

- **Never leak any bits of `p`, `q`, or `d`.** There is no "safe fraction" — once an attacker knows more than ~25% of the high (or low) bits of either prime, Coppersmith recovers the rest.
- Don't build oracles that return functions of private key material, even "redacted" ones. A masked value (`p` with low bits zeroed) still publishes every bit it retains.
- If you must expose a key fingerprint, hash the **public** modulus (`SHA-256(n)`) — never truncate a **private** factor.

This is **[CWE-320](https://cwe.mitre.org/data/definitions/320.html)** (key management errors) / **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)** (information exposure): partial private-key disclosure enabling lattice factorization.
