---
layout: post
title: "AbraCryptabra"
date: 2028-06-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, lcg, prng, lattice, lll, hidden-number-problem, knapsack, merkle-hellman, cjloss, fpylll, cwe-338, cwe-327]
description: "A Medium Crypto challenge with two stacked locks: a truncated linear congruential generator whose unknown increment and seed are recovered with a Hidden Number Problem lattice, and a Merkle-Hellman knapsack broken with the CJLOSS low-density subset-sum lattice. Both solved with fpylll — no SageMath."
---

## Overview

*AbraCryptabra* is a Medium **Crypto** challenge served over `nc`, wrapped in a
Harry-Potter theme. Two independent crypto locks stand between you and the flag:
first you must out-predict a [predictable PRNG](https://cwe.mitre.org/data/definitions/338.html)
(a truncated linear congruential generator) ~200 times to "beat the Basilisk",
and then you break a [broken knapsack cipher](https://cwe.mitre.org/data/definitions/327.html)
(Merkle-Hellman) to read the flag. Both stages are lattice attacks solved with
`fpylll` — no SageMath required.

## The technique

### Stage 1 — truncated LCG with unknown increment

`Wizard.attack()` steps a linear congruential generator and leaks only the top
32 bits of each new state:

```python
self.spell = (self.armor * self.spell + self.critChance) % self.magicka
spellAttack = self.spell >> (self.magicka.bit_length() - self.stamina)  # top 32 bits
```

The modulus (`magicka`, 127-bit) and multiplier (`armor`) are baked into the
source, but the increment (`critChance`) and seed are random. Each round you
guess `spellAttack`; a wrong guess costs 1 of 100 HP but leaks the true value, so
you can gather samples. Write each state as `s_i = y_i·2^95 + low_i` with the
32-bit leak `y_i` and an unknown `low_i < 2^95`. Across several samples this is a
**Hidden Number Problem** in the two unknowns `(seed, increment)`, and an LLL
lattice recovers them. To run the classic SageMath recipe on plain `fpylll`,
multiply the whole rational-weighted matrix by the modulus `m` — LLL is
scale-invariant, so you just divide back when reading the solution.

### Stage 2 — Merkle-Hellman knapsack

The flag bits select elements of a public "scroll" (a superincreasing list
masked by `x2·i mod x1`); the server sends the public key and the subset sum. At
this instance's density (~0.64) the textbook **Lagarias-Odlyzko** lattice fails,
but the **CJLOSS centered lattice** (diagonal 2, an all-ones row, the answer
surfacing as a ±1 vector) solves subset-sums up to density ~0.9408.

## Solution

Two practical facts make the difference between a working and a hanging exploit:

- The recovered `(seed, increment)` is **spurious ~50% of the time** — it matches
  the samples you collected but not the future. So verify each candidate against
  every leak, and let the live 200-round fight be the final oracle: on divergence,
  discard and retry with more samples.
- HTB challenge **instances die in ~1-2 minutes**, so collect samples
  *incrementally on one connection* rather than reconnecting (each reconnect is a
  fresh unknown seed).

The AES-CBC wrapper on the subset sum looks intimidating but the IV is never
sent — the plaintext prefix `"You're a wizard Harry, "` pushes the hex flag past
the first block, and CBC recovers every block after block 0 without the IV. One
last trick: the MSB of every ASCII byte is 0, so the server never adds those
knapsack items — drop every 8th public-key element and rebuild each character
from 7 bits.

The full commented exploit (`solve.py`):

```python
#!/usr/bin/env python3
import sys
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fpylll import IntegerMatrix, LLL
from pwn import remote, log


def lll_int(rows):
    n, m = len(rows), len(rows[0])
    A = IntegerMatrix(n, m)
    for i in range(n):
        for j in range(m):
            A[i, j] = int(rows[i][j])
    LLL.reduction(A)
    return [[A[i, j] for j in range(m)] for i in range(n)]


def do_round(io, guess=1337):
    io.sendlineafter(b'> ', str(guess).encode())
    io.recvline()
    r = io.recvline().decode()
    if r != '\n':
        return int(r)


def hidden_number_problem(a, b, m, X):
    n1, n2 = len(a), len(a[0])
    N = n1 + n2 + 1
    B = [[0] * N for _ in range(N)]
    for i in range(n1):
        for j in range(n2):
            B[n1 + j][i] = m * a[i][j]
        B[i][i] = m * m
        B[n1 + n2][i] = m * (b[i] - X // 2)
    for j in range(n2):
        B[n1 + j][n1 + j] = X
    B[n1 + n2][n1 + n2] = m * X
    cands = []
    for v in lll_int(B):
        for w in (v, [-x for x in v]):
            if w[n1 + n2] != m * X:
                continue
            xs = [w[i] // m + X // 2 for i in range(n1)]
            ys = [(w[n1 + j] // X) % m for j in range(n2)]
            if all(y != 0 for y in ys) and all(0 <= x < X for x in xs):
                cands.append((xs, ys))
    return cands


def crack_tlcg(y, k, s, m, a):
    a_, b_ = [], []
    X = 2 ** (k - s)
    mult1, mult2 = a, 1
    for i in range(len(y)):
        a_.append([mult1, mult2])
        b_.append(-X * y[i])
        mult1 = (a * mult1) % m
        mult2 = (a * mult2 + 1) % m
    for _, (x0_, c_) in hidden_number_problem(a_, b_, m, X):
        st, ok = x0_, True
        for want in y:
            st = (a * st + c_) % m
            if st >> (k - s) != want:
                ok = False
                break
        if ok:
            return m, a, c_, x0_
    return None


class LCG:
    def __init__(self, m, a, c, s0):
        self.m, self.a, self.c = m, a, c
        self.k = int(m).bit_length()
        self.state = s0

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state >> (self.k - 32)


def knapsack(a_i, b):
    n = len(a_i)
    M = [[0] * (n + 1) for _ in range(n + 1)]
    for i, a in enumerate(a_i):
        M[i][i] = 2
        M[i][-1] = a
    for i in range(n):
        M[-1][i] = 1
    M[-1][-1] = b
    for row in lll_int(M):
        if row[-1] != 0 or not all(v in (-1, 1) for v in row[:-1]):
            continue
        for sf in (1, -1):
            x = [(1 - sf * v) // 2 for v in row[:-1]]
            if b == sum(a * u for a, u in zip(a_i, x)):
                return x
    return None


def bin2dec(bits):
    return int(''.join(map(str, bits)), 2)


NSAMP0, NSMAX = 28, 85


def solve_once():
    host, port = sys.argv[1].split(':')
    io = remote(host, int(port))
    M = 108314726549199134030277012155370097074
    a = 31157724864730593494380966212158801467
    k = M.bit_length()

    Y = [do_round(io) for _ in range(NSAMP0)]
    lcg = None
    while len(Y) <= NSMAX:
        cracked = crack_tlcg(Y, k, 32, M, a)
        if cracked:
            _, _, c, s0 = cracked
            cand = LCG(M, a, c, s0)
            if all(y == cand.next() for y in Y):
                lcg = cand
                break
        Y += [do_round(io) for _ in range(4)]
    if lcg is None:
        io.close()
        return None
    log.success(f'LCG cracked with {len(Y)} samples')

    used = len(Y)
    player_health, wizard_health = 100 - used, 200
    while wizard_health:
        if do_round(io, lcg.next()) is None:
            wizard_health -= 1
        else:
            player_health -= 1
            if 100 - used - player_health > 3:
                io.close()
                return None

    length = int(io.recvline().decode())
    public_key = []
    for i in range(length):
        (public_key.append(int(io.recvline().decode())) if i % 8 else io.recvline())
    enc_message = bytes.fromhex(io.recvline().decode())
    io.close()

    for _ in range(player_health - 1):
        lcg.next()
    key = md5(str(lcg.next()).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * 16)
    try:
        message = unpad(cipher.decrypt(enc_message), AES.block_size)
    except ValueError:
        return None
    enc_flag = int(message.split(b'Harry, ')[1].decode(), 16)
    r = knapsack(public_key, enc_flag)
    if not r:
        return None
    flag = [bin2dec([0, *r[i:i + 7]]) for i in range(0, len(r), 7)]
    return 'HTB{' + ''.join(map(chr, flag)) + '}'


def main():
    for _ in range(30):
        try:
            flag = solve_once()
        except EOFError:
            continue
        if flag:
            log.success(flag)
            return


if __name__ == '__main__':
    main()
```

Running it against the live instance drops the flag:

```
[+] LCG cracked with 44 samples
[+] Player 54 | Wizard 0
[+] HTB{...}
```

Flag redacted.

## Why it worked

Both locks reduce to lattice problems. The LCG exposes its full internal state
to anyone who observes enough top-bit outputs, because a truncated LCG is a
Hidden Number Problem — the unknown low bits and the unknown increment are all
small relative to the modulus, so LLL finds them. The knapsack is a
[Merkle-Hellman cipher](https://cwe.mitre.org/data/definitions/327.html), long
known to be broken: any low-to-medium-density subset-sum falls to lattice
reduction, and CJLOSS extends the reachable density past where the naive lattice
gives up.

## Fix / defense

- **PRNG ([CWE-338](https://cwe.mitre.org/data/definitions/338.html)):** never
  expose the outputs of a non-cryptographic generator, and never use an LCG (or
  Mersenne Twister) for anything security-relevant. Use `secrets` /
  `os.urandom`. A single leaked value of a predictable generator can expose its
  entire stream.
- **Knapsack ([CWE-327](https://cwe.mitre.org/data/definitions/327.html)):**
  Merkle-Hellman is cryptographically broken. Use a vetted key-encapsulation
  mechanism (e.g. ML-KEM) instead of a home-rolled superincreasing-knapsack
  scheme.
