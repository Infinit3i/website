---
title: "Fast Carmichael"
date: 2027-01-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, miller-rabin, primality, carmichael, pseudoprime]
description: "A Very Easy Crypto challenge whose server decides primality with a hand-rolled, deterministic Miller-Rabin over a fixed set of witness bases. Because the witness set is finite and public, Arnault's construction yields a composite Carmichael number that passes the fixed-basis test yet fails a real primality check — satisfying the flag gate."
---

## Overview

`Fast Carmichael` is a Very Easy HackTheBox **Crypto** challenge. A professor "checks if a
number is prime as quickly as possible" — the server validates your number with a hand-rolled,
**deterministic** [Miller–Rabin](https://cwe.mitre.org/data/definitions/327.html) test over a
**fixed, public** set of witness bases, and hands over the flag only when your number *passes
that test but is not actually prime*. The whole game is to forge a composite that lies to those
exact witnesses.

## The technique

The server's code is the spec for the attack:

```python
def generate_basis(n):                       # returns every prime < n
    ...

def millerRabin(n, b):
    basis = generate_basis(300)              # FIXED, PUBLIC: all primes < 293
    ...                                       # standard strong-probable-prime loop

def _isPrime(p):
    return p >= 1 and millerRabin(p, 300)

# flag gate
if _isPrime(p) and not isPrime(p):           # passes MY test, fails the REAL one
    sendMessage(s, FLAG)
```

Miller–Rabin only *probabilistically* proves compositeness: a composite that survives a base
is a **strong pseudoprime** to that base. There is no composite that is a strong pseudoprime to
*every* base — but you can deliberately construct one that fools any **finite, known** set of
bases. Here the basis is fixed (every prime below 300) and printed in the source, so the test is
forgeable offline.

The recipe comes from Arnault, *"Constructing Carmichael numbers which are strong pseudoprimes to
several bases"*. It builds

```
n = p1 · (313·(p1 − 1) + 1) · (353·(p1 − 1) + 1)
```

where `p1` is chosen so all three factors are prime and `n` is a strong pseudoprime to every
prime base ≤ 293. The published `p1` yields a 397-digit composite that:

- **passes** the server's fixed-basis Miller–Rabin (`_isPrime` → `True`), yet
- **fails** `Crypto.Util.number.isPrime` (BPSW = Miller–Rabin + a strong Lucas test; the Lucas
  leg catches it) → `not isPrime(p)` is `True`.

Both gate conditions hold, so the flag drops.

## Solution

`solve.py`:

```python
from Crypto.Util.number import isPrime
import socket, sys

# Arnault: strong pseudoprime to every prime base < 300, but genuinely composite.
p1 = 29674495668685510550154174642905332730771991799853043350995075531276838753171770199594238596428121188033664754218345562493168782883
n = p1 * (313 * (p1 - 1) + 1) * (353 * (p1 - 1) + 1)

assert not isPrime(n)            # truly composite (three prime factors)

host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((host, port), timeout=15)
s.recv(4096)                     # "Give p: "
s.sendall((str(n) + "\n").encode())
print(s.recv(4096).decode().strip())   # -> HTB{...}
```

```bash
python3 solve.py <target-host> <target-port>
# Give p:
# HTB{...}
```

> One pitfall worth noting: pycryptodome 3.10.4's `isPrime` returns the **integer** `0`/`1`, not a
> bool, so `isPrime(n) is False` is *always* false. Use truthiness (`not isPrime(n)`), never
> identity.

## Why it worked

The primality check is **deterministic** and its witness set is **public and finite**. That turns
"prove your number is prime" into the solvable offline problem "find a composite that lies to
*these* 62 witnesses" — exactly what Arnault's construction does. Determinism plus a bounded,
known basis equals a forgeable primality oracle.

## Fix / defense

- Use a **proven** primality test for any security decision — BPSW as in
  `Crypto.Util.number.isPrime`, or AKS/ECPP for certainty — never a hand-rolled fixed-basis
  Miller–Rabin.
- If Miller–Rabin must be used, choose the witness bases **randomly per call** so no single number
  can be precomputed to pass.
- A deterministic witness set is only sound *below its proven bound* (e.g. the first 12 primes
  suffice deterministically only for `n < 3.18 × 10²³`) — never beyond it.
