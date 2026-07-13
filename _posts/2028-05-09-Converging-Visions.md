---
layout: post
title: "Converging Visions"
date: 2028-05-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, elliptic-curve, smart-attack, anomalous-curve, ecdlp, prng]
description: "A menu server multiplies a secret elliptic-curve point by a PRNG seed and only ever shows you the point multiplied by the seed squared. Two mistakes stack: the curve is anomalous, so Smart's attack turns its discrete log into one division, and the PRNG's giant modulus is a red herring once you reduce everything mod p. No Sage required — Q_p by hand."
---

## Overview

Converging Visions is a **Hard** HackTheBox **Crypto** challenge. A menu server holds a secret
256-bit prime `p` and a secret elliptic curve `y^2 = x^3 + a*x + b mod p`. Each round it advances a
custom PRNG, multiplies a **secret** point `P` by the raw seed, multiplies a **public** point `EP` by
the seed *squared*, and shows you only `EP`. Win by predicting the secret point one step ahead. The
curve turns out to be **anomalous** (`#E(F_p) == p`), so its discrete log is broken by
[Smart's attack](https://cwe.mitre.org/data/definitions/327.html), and the PRNG's oversized modulus
collapses the moment you reduce mod `p`.

## The technique

Three weaknesses, chained:

1. **The parameters are recoverable.** `p`, `a`, `b` are secret, but the server leaks curve points.
   For any two points, subtracting the curve equation eliminates `b` and gives `a`; then `b` follows.
   To get `p` without abusing the `x >= p` rejection oracle (the server has a per-connection alarm
   that kills a 255-step binary search), collect ~9 points `(X, Y)`, form `u = Y^2 - X^3`, and note
   that the rows `[X, 1, u]` are linearly dependent mod `p`. Every 3×3 determinant is therefore
   `0 mod p`, so `p = gcd` of a few determinants (strip small cofactors).

2. **The curve is anomalous → Smart's attack.** When the group order equals the field prime,
   `#E(F_p) == p`, the elliptic-curve discrete log is *not* hard. Lift the curve and points into the
   `p`-adics `Q_p`, multiply each point by `p` to drop it into the formal group (whose structure is
   just `(F_p, +)`), read the formal logarithm `t = -x/y`, and the discrete log is the ratio of the
   two logs mod `p`. Since `EP1 = enc_seed1 * P0`, this recovers `enc_seed1 mod p`.

3. **The PRNG collapses mod p.** The recurrence `seed_{i+1} = a*seed_i^3 + b*seed_i + inc (mod p*C)`
   *looks* protected by the huge modulus `p*C`. But EC scalar multiplication is effectively mod the
   group order `p`, and polynomial reduction commutes with `mod p`, so only `seed_i mod p` ever
   matters. Recover `seed1 = sqrt(enc_seed1) mod p`, disambiguate the two square roots against a
   second observed `EP2`, and roll the recurrence forward to predict the secret point.

## Solution

Kali here had **no Sage and no PARI**, so Smart's attack is implemented in pure Python with a
hand-rolled `Q_p` class (a p-adic is `(val, unit mod p^PREC)`). Two bugs are easy to hit:

- **Zero under finite precision:** subtracting two *equal* p-adics leaves `val >= PREC` garbage, not
  an exact zero — so `is_zero()` must treat `val >= PREC` as zero, or the doubling branch never fires
  and `[p]P` never reaches the reduction kernel.
- **Non-torsion lift:** lift the `a`-invariant to `a + r*p` (`r != 0`) and re-Hensel `y`, so
  `[p]P != O` globally. The recovered scalar is independent of the lift choice.

The p-adic core of `smart.py`:

```python
PREC = 20  # relative p-adic precision (digits)

class Qp:
    def __init__(self, val, unit, p):
        self.p = p
        if unit % p == 0 and unit != 0:
            v2, u2 = val_unit(unit, p, PREC)
            self.val, self.unit = val + v2, u2
        else:
            self.val, self.unit = val, unit % (p ** PREC)
        if self.unit == 0:
            self.val = 10 ** 9

    def is_zero(self):
        return self.unit == 0 or self.val >= PREC   # the load-bearing fix

def smart_attack(Px, Py, Qx, Qy, a, b, p, r=1):
    a_l = a + r * p                                 # non-torsion lift
    A = Qp.from_int(a_l, p)
    Plift = (Qp.from_int(Px, p), Qp.from_int(hensel_y(Px, Py, a_l, b, p, PREC), p))
    Qlift = (Qp.from_int(Qx, p), Qp.from_int(hensel_y(Qx, Qy, a_l, b, p, PREC), p))
    pP, pQ = ec_mul(Plift, p, A, p), ec_mul(Qlift, p, A, p)
    tP = -(pP[0] / pP[1])                           # formal log, valuation 1
    tQ = -(pQ[0] / pQ[1])
    return (tQ / tP).unit % p                        # d = t_Q / t_P mod p
```

And the driver that recovers the parameters, runs Smart's attack, and predicts the point:

```python
p = gcd_of_3x3_determinants(points)                 # rows [X, 1, Y^2 - X^3] dep mod p
a = (y1*y1 - y2*y2 - x1**3 + x2**3) * pow(x1 - x2, -1, p) % p
b = (y1*y1 - x1**3 - a*x1) % p

enc1  = smart_attack(P0.x, P0.y, EP1.x, EP1.y, a, b, p)   # anomalous-curve ECDLP
seed1 = tonelli(enc1, p)                                   # two roots
seed1 = pick_root_that_predicts(EP2)                       # disambiguate

s2 = (a*seed1**3 + b*seed1 + INC) % p
s3 = (a*s2**3    + b*s2    + INC) % p
P_true = P0 * (seed1 * s2 % p * s3 % p)                    # send x, y -> flag
```

Feeding the predicted point into option 3 returns the flag:

```text
You have confirmed the location. However, It's dangerous to go alone. Take this: HTB{...}
```

## Why it worked

The service tried to hide the seed behind a squaring (`enc = seed^2`) and a giant modulus (`p*C`), but
neither survives contact with the curve. The squaring is invertible with a modular square root once
you know the seed *squared* — and you learn the seed squared by solving the ECDLP, which is only hard
if the curve is chosen well. It wasn't: an [anomalous curve](https://cwe.mitre.org/data/definitions/327.html)
(`#E(F_p) == p`) makes the discrete log a single division. And because EC scalar multiplication runs
mod the group order `p`, the PRNG's `mod p*C` arithmetic is indistinguishable from `mod p` for
everything you can observe — the extra modulus protects nothing.

## Fix / defense

- Never instantiate ECC over an anomalous curve. Reject any curve where `#E(F_p) == p` (trace of
  Frobenius `!= 1`) at key generation, and prefer a vetted prime-order curve (P-256 / Curve25519)
  whose order differs from the field prime — [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
- Don't derive an observable from a secret via a cheap, invertible map (here `seed -> seed^2`) and
  expose it. If a PRNG feeds secret state, its public outputs must not be a recoverable function of
  that state.
