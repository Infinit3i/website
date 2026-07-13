---
layout: post
title: "Zombie Rolled"
date: 2028-05-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elliptic-curve, multi-prime-rsa, coppersmith, sage, lattice]
description: "A home-rolled cryptosystem builds its public exponent out of a pretty rational identity — and that identity is secretly the group law of an elliptic curve. The public key is literally twice the private key on that curve, so you halve the point to recover the hidden multi-prime RSA modulus, then finish with a bivariate Coppersmith. ECC is magic, isn't it?"
---

## Overview

Zombie Rolled is a **Hard** HackTheBox **Crypto** challenge. You're handed a
`source.py` and an `output.txt` — no modulus, no obvious RSA. The public
exponent is the numerator of a rational "magic" identity, the modulus
`n = p·q·r` is never printed, and the only leaked data is a `pub` triple plus a
`mix` pair derived from a signature over the flag. The whole path: recognize the
identity as a disguised elliptic curve, **halve the public point** to recover the
private primes, rebuild the modulus, then bivariate-Coppersmith the flag out of
the signature-verify relation.

## The technique

The scheme's "magic" function is

```python
def magic(a, b, c):
    return (a+b)/(b+c) + (b+c)/(a+c) + (a+c)/(a+b)   # exact fraction
```

Substituting `X = a+b`, `Y = b+c`, `Z = a+c` collapses it to the classic form
`X/Y + Y/Z + Z/X`. The public exponent is `e = numerator(magic(pub))`, the
modulus is `n = p·q·r` (three 1024-bit primes), and the key generator makes the
public triple satisfy `magic(pub) = magic(priv)`.

That symmetric cubic identity is not just a curiosity — it **parameterizes an
elliptic curve**:

```
E_f :  v² = u³ + A·u + B ,   A = 27f(24 − f³),   B = 54(216 − 36f³ + f⁶)
```

The key derivation produces the public key by **doubling** the private point:
`G_pub = 2·G_priv`. So recovering the private key is one point *halving* away.

## Solution

**1. Build the curve and halve the public point.** `magic` is scale-invariant, so
halving only recovers the private triple projectively. Re-pin the absolute scale
using the denominator of `f`: `A2·B2·C2 = f.denominator()·g` for a small integer
`g` (here `g = 192`), take the integer cube-root for `λ`, then invert the
substitution `X = p+q`, `Y = q+r`, `Z = p+r` to the primes. Confirm all three
are prime, then `n = p·q·r`, `d = e⁻¹ mod (p−1)(q−1)(r−1)`.

**2. Decrypt the `mix`** to recover the two signature halves, then
`r_val = s1^e` and `C = s2^e mod n`. By how the signature verifies,
`r_val = magic(m, sha256(m), C) mod n` where `m` is the flag.

**3. Bivariate Coppersmith.** Clearing denominators gives one relation in two
small unknowns `m` (flag, < 2⁵¹²) and `h = sha256(m)` (< 2²⁵⁶):

```
(m+h)²(m+C) + (h+C)²(m+h) + (m+C)²(h+C) − r_val·(m+h)(h+C)(m+C) ≡ 0  (mod n)
```

Both roots are tiny relative to the ~3072-bit `n`, so a bivariate Coppersmith
lattice recovers `m`. Decode `m` → the flag (`HTB{...}`).

The durable solver, run headless in a Docker SageMath image
(`docker run --rm --entrypoint bash -v "$PWD":/work sagemath/sagemath -c 'cp /work/solve.sage /work/output.txt /tmp/ && cd /tmp && sage solve.sage'`):

```python
exec(open('output.txt').read(), globals())   # pub, mix
a, b, c = pub
X, Y, Z = QQ(a+b), QQ(b+c), QQ(a+c)           # magic == X/Y + Y/Z + Z/X
f = X/Y + Y/Z + Z/X
e, fd = Integer(f.numerator()), Integer(f.denominator())

A = 27*f*(24 - f**3); B = 54*(216 - 36*f**3 + f**6)
E = EllipticCurve(QQ, [A, B])
u = QQ((3*f*f*Z - 36*X)/Z); v = QQ(108*(2*X*Y - f*X*Z + Z**2)/Z**2)
P = E(u, v)

def find_abc(G):
    uu, vv = G.xy()
    x_z = QQ((3*f**2 - uu)/36); x = x_z.numerator(); z1 = x_z.denominator()
    y_z = QQ((vv/108 + f*x_z - 1)/(2*x_z)); y = y_z.numerator(); z2 = y_z.denominator()
    z = lcm(z1, z2); return Integer(x*(z//z1)), Integer(y*(z//z2)), Integer(z)

priv = None
for G in P.division_points(2):                # pub point = 2 * priv point
    T = find_abc(G); prodT = T[0]*T[1]*T[2]
    for g in range(1, 200):
        if (fd*g) % prodT: continue
        lam = Integer((fd*g)//prodT).nth_root(3, truncate_mode=True)[0]
        if lam**3 != (fd*g)//prodT: continue
        for (AA, BB, CC) in [(lam*T[0], lam*T[1], lam*T[2])]:
            p = (AA-BB+CC)//2; q = (AA+BB-CC)//2; r = (-AA+BB+CC)//2
            if min(p, q, r) > 0 and is_prime(p) and is_prime(q) and is_prime(r):
                priv = (p, q, r)
    if priv: break

p, q, r = priv; n = p*q*r
d = inverse_mod(e, (p-1)*(q-1)*(r-1)); inv2 = inverse_mod(2, n)
t0, t1 = power_mod(mix[0], d, n), power_mod(mix[1], d, n)
s1, s2 = (t0+t1)*inv2 % n, (t0-t1)*inv2 % n
r_val, C = power_mod(s1, e, n), power_mod(s2, e, n)

PR = PolynomialRing(Zmod(n), 'mh', 2); m, h = PR.gens()
G = (m+h)**2*(m+C) + (h+C)**2*(m+h) + (m+C)**2*(h+C) - r_val*(m+h)*(h+C)*(m+C)
# bivariate Coppersmith on G with bounds m < 2^512, h < 2^256  ->  m = flag
```

## Why it worked

The author tried to hide the secret primes inside a "clever" algebraic identity.
But a symmetric cubic in three unknowns is an
[elliptic curve](https://cwe.mitre.org/data/definitions/1240.html) in disguise,
and publishing `2·G_priv` as the public key means the private key is one point
**halving** away. Once the primes fall out, it's textbook multi-prime RSA and a
routine lattice attack. The flag says it best: *ECC is magic, isn't it?* — the
"magic" was the curve the whole time.

## Fix / defense

- Never derive key material from an invertible public relation. If `pub` and
  `priv` satisfy the same low-degree identity and `pub` is a group multiple of
  `priv`, that multiple is reversible.
- Don't roll your own crypto — use standard, reviewed primitives (real RSA /
  ECDSA) instead of home-rolled "magic" schemes. The secret components were
  recoverable precisely because the structure was algebraic, not random.
