---
layout: post
title: "Mayday Mayday"
date: 2028-05-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, crt-rsa, partial-key-exposure, coppersmith, small-roots, lattice]
description: "CRT-RSA that leaks the top half of dp and dq — with a small public exponent, Vieta over Z_e recovers the multipliers and Coppersmith finishes the factorization."
---

## Overview

Mayday Mayday is a **Medium** HackTheBox **Crypto** challenge (HTB University CTF 2023). You get a 2048-bit RSA public key, a ciphertext, and the **high 512 bits** of both CRT private exponents `dp` and `dq`. That partial leak — combined with an unusually small public exponent — is enough to recover the full factorization, using a [known CRT-RSA partial key exposure attack](https://cwe.mitre.org/data/definitions/320.html) (paper [eprint 2022/271](https://eprint.iacr.org/2022/271.pdf)).

## The technique

The generator leaks the top half of each CRT exponent and picks a small `e`:

```python
self.alpha = 1/9;  self.delta = 1/4
self.known = int(self.bits * self.delta)          # 512
self.e = getPrime(int(self.bits * self.alpha))    # ~227-bit — small
dp = pow(self.e, -1, p-1);  dq = pow(self.e, -1, q-1)
f.write(f'dp = 0x{(dp >> (rsa.bits//2 - rsa.known)):x}\n')   # dpM = dp >> 512
f.write(f'dq = 0x{(dq >> (rsa.bits//2 - rsa.known)):x}\n')   # dqM = dq >> 512
```

Define `k, l` by the CRT identities `e·dp = k·(p-1) + 1` and `e·dq = l·(q-1) + 1`. Because `e` is small, `k, l < e` — small enough to solve for exactly. Once `k` is known, the unknown low 512 bits of `dp` sit inside Coppersmith's small-root bound, so the leak of the top half is fatal.

## Solution

1. **Approximate `k·l`** from `k·l·N ≈ e²·dp·dq ≈ e²·dpM·dqM·2^1024`.
2. **Recover `k` and `l` via Vieta over GF(e)** — they are the roots of `x² − (k·l·(1−N)+1)·x + k·l` mod `e`.
3. **Coppersmith** on `f(dpL) = e·(dpM·2^512 + dpL) + k − 1 ≡ 0 (mod k·p)`, where `k·p` is an unknown factor of the known modulus `k·N`, recovers `dpL`.
4. **Factor and decrypt**: `k·p = f(dpL)`, `p = gcd(k·p, N)`, then standard RSA.

Create `solve.sage`:

```python
import json
def l2b(x):
    x=int(x); return x.to_bytes((x.bit_length()+7)//8,'big')
v=json.load(open("vals.json"))
N=Integer(int(v["N"],16)); e=Integer(int(v["e"],16)); c=Integer(int(v["c"],16))
dpM=Integer(int(v["dp"],16)); dqM=Integer(int(v["dq"],16))
i=512
kl=(e**2*dpM*dqM*2**(2*i))//N + 1
R.<x>=PolynomialRing(GF(e))
poly=x^2-(kl*(1-N)+1)*x+kl
for kk,_ in poly.roots():
    k=Integer(kk)
    Rz.<dpL>=PolynomialRing(Zmod(k*N))
    f=e*(dpM*2**i+dpL)+k-1
    for r in f.monic().small_roots(X=2**i, beta=0.4, epsilon=0.03):
        kp=int(e*(dpM*2**i+int(r))+k-1)
        p=gcd(Integer(kp),N)
        if 1<p<N and N%p==0:
            q=N//p
            d=inverse_mod(e,(p-1)*(q-1))
            print(l2b(power_mod(c,d,N)))
```

Run it in Sage against the challenge's `output.txt` values and the flag prints:

```
HTB{...}
```

Flag value redacted.

## Why it worked

CRT-RSA is only as safe as `dp` and `dq` are fully secret. Leaking **half** their bits, plus a **small `e`** that bounds the multipliers `k, l < e` (so Vieta over `Z_e` pins them exactly), reduces the remaining secret to a 512-bit tail — squarely inside Coppersmith's small-root reach. As the flag says, any leakage of private information results in broken crypto.

## Fix / defense

- Never expose any bits of `d`, `dp`, or `dq`; treat CRT-exponent side channels as key-recovery bugs.
- Use `e = 65537`. A tiny exponent amplifies partial-key-exposure attacks by shrinking the `k, l` search to a solvable quadratic; standard `e` forces far more leakage before the attack becomes feasible.
