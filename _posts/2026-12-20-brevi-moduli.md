---
title: "brevi moduli"
date: 2026-12-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, factorization, mpqs, pari]
description: "A Very Easy crypto challenge where RSA's only weakness is the key size: each modulus is built from two 110-bit primes, so n is just ~220 bits and factors directly in seconds with PARI's quadratic sieve — no oracle, no padding trick, just an undersized modulus."
---

## Overview

`brevi moduli` ("short moduli") is a Very Easy HackTheBox **Crypto** challenge. A network
service runs five rounds; in each round it hands you an RSA public key and demands the two
prime factors of its modulus before it will move on. Give the correct factors for all five
rounds and it prints the flag. The catch — and the entire lesson — is that the modulus is
far too small: `n = p * q` with `p` and `q` only **110 bits each**, so `n` is ~220 bits
(66 decimal digits) and factors on a laptop in a few seconds. This is
[inadequate encryption strength](https://cwe.mitre.org/data/definitions/326.html)
([CWE-326](https://cwe.mitre.org/data/definitions/326.html)): RSA assumes you cannot factor
`n`, and at this size you simply can.

## The technique

The provided `server.py` is short and tells you everything:

```python
from Crypto.Util.number import isPrime, getPrime
from Crypto.PublicKey import RSA

rounds = 5
e = 65537

for i in range(rounds):
    pumpkin1 = getPrime(110)
    pumpkin2 = getPrime(110)
    n = pumpkin1 * pumpkin2
    large_pumpkin = RSA.construct((n, e)).exportKey()
    print(large_pumpkin.decode())

    assert isPrime(_pmp1 := int(input('enter your first pumpkin = ')))
    assert isPrime(_pmp2 := int(input('enter your second pumpkin = ')))
    if n != _pmp1 * _pmp2:
        print('wrong! bye...')
        exit()

print(open('flag.txt').read())
```

There is no exotic RSA attack here — no small `e`, no shared primes, no padding oracle.
The two primes are random and the *same size*, which rules out elliptic-curve factorization
(ECM is only fast when one factor is much smaller than the other). The right tool for a
balanced semiprime of this size is a general-purpose sieve — the
**Multiple-Polynomial Quadratic Sieve (MPQS)**. PARI/GP implements an industrial-strength
one, and a 220-bit modulus drops in roughly eight seconds.

Two practical notes that turn this from "easy in theory" into "easy in practice":

- A stock Kali box has no `gp`, `sage`, `yafu`, or `ecm`, and `pip` is externally managed.
  The fastest workaround is the **`cypari2` wheel**, which *bundles* `libpari` — so a plain
  virtualenv gives you PARI's factorizer with no `apt`/`sudo`:
  `python3 -m venv venv && ./venv/bin/pip install cypari2 pycryptodome pwntools`.
- You **must** raise PARI's stack before factoring (`pari.allocatemem(1 << 30)`), or MPQS
  overflows the default 8 MB stack on a 66-digit input and aborts with
  `the PARI stack overflows`.

For contrast: pure-Python `sympy.factorint` solved the same modulus too, but took ~350
seconds versus PARI's ~8 — far too slow to clear five rounds inside the connection.

## Solution

The solver connects once, and for each of the five rounds: reads up to the prompt, pulls
the PEM out of the banner, extracts `n` from it, factors `n` with PARI, and sends the two
primes back. After the fifth round the flag arrives.

Create `solve.py`:

```python
import sys, re, time, cypari2
from Crypto.PublicKey import RSA
from pwn import remote, context

context.log_level = 'info'
HOST, PORT = sys.argv[1], int(sys.argv[2])

pari = cypari2.Pari()
pari.allocatemem(1 << 30)  # MPQS on a 220-bit n overflows the default 8MB stack

def factor_n(n):
    f = pari.factor(n)
    facs = sorted(int(x) for x in f[0])
    assert len(facs) == 2 and facs[0] * facs[1] == n, facs
    return facs

io = remote(HOST, PORT)
for rnd in range(5):
    blob = io.recvuntil(b'enter your first pumpkin = ').decode(errors='replace')
    pem = re.search(r'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----', blob, re.S).group(0)
    n = RSA.import_key(pem).n
    t = time.time()
    p, q = factor_n(n)
    print(f'[round {rnd+1}] n={n} ({n.bit_length()} bits) factored in {time.time()-t:.1f}s')
    io.sendline(str(p).encode())
    io.recvuntil(b'enter your second pumpkin = ')
    io.sendline(str(q).encode())

print(io.recvall(timeout=10).decode(errors='replace'))
```

Run it against the spawned instance:

```bash
./venv/bin/python solve.py <target-host> <target-port>
```

```
[round 1] n=826857119625343992996162117681462655523598912449714808122725777153 (219 bits) factored in 7.6s
[round 2] n=889257717189752323352556443347177005477626520591490469630096689823 (220 bits) factored in 8.3s
[round 3] ... factored in 8.2s
[round 4] ... factored in 10.7s
[round 5] ... factored in 9.0s

HTB{...}
```

## Why it worked

RSA's security is the assumption that factoring `n` is infeasible — and that assumption is
only true for *large* `n`. NIST SP 800-57 sets the floor at 2048-bit moduli precisely
because anything materially smaller is within reach of public sieving software. At 220 bits
the modulus is 66 digits, which MPQS clears in seconds, so recovering `p` and `q` (and
therefore the entire private key) needs no cleverness beyond pointing a good factorizer at
the number. The challenge never had to leak a private key — the public key *was* the leak.

## Fix / defense

Use a modulus that is actually hard to factor: `n >= 2048` bits (each prime `>= 1024` bits),
and 3072/4096 bits for anything new. Generate keys with a vetted primitive
(`RSA.generate(3072)`) rather than hand-picking short primes, and reject or rotate any key
whose modulus falls below the 2048-bit floor.

```python
# vulnerable: ~220-bit modulus, factorable in seconds
p, q = getPrime(110), getPrime(110)
n = p * q

# fixed: >= 2048-bit modulus
key = RSA.generate(3072)
```
