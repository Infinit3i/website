---
layout: post
title: "Infinite Knapsack"
date: 2028-02-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, merkle-hellman, knapsack, lll, lattice, mersenne-twister, prng]
description: "A Merkle–Hellman knapsack that doesn't guard the flag — it guards the PRNG state. Break the knapsack with a low-density subset-sum lattice reduction, restore the Mersenne Twister, and replay the exact randomness that encrypted the flag."
---

## Overview

Infinite Knapsack is a Medium crypto challenge built around the Merkle–Hellman knapsack cryptosystem — but the knapsack is a misdirection. It doesn't encrypt the flag directly; it encrypts the Python PRNG state. Break the knapsack with lattice reduction, restore the random number generator, and you can replay the exact randomness used to encrypt the flag and undo it.

## The structure

`out.txt` holds three things: the encrypted flag, the "encrypted state," and a Merkle–Hellman public key. The source does this:

```python
seed(SEED)
state = getstate()               # captured BEFORE any RNG is consumed
encrypted_flag = encrypt(FLAG)   # uses randint() then sample()
mh = MH(32)
encrypted_state = [state[0], mh.encrypt(state[1]), state[2]]
```

So `state[1]` — the 625 integers of the Mersenne Twister state — is encrypted, each 32-bit word as a Merkle–Hellman ciphertext. Recover those and you have the RNG state as it was *before* `encrypt(FLAG)` ran.

## Breaking the knapsack

Each Merkle–Hellman ciphertext is a subset-sum: `c = Σ bit_i · pubkey_i` over the 32 bits of a state word. The public key elements are ~80-bit and there are 32 of them, so the density (`n / log2(max weight)`) is about 0.4 — comfortably below the ~0.65 threshold where the Lagarias–Odlyzko lattice attack recovers the subset with LLL, no modulus or multiplier required.

For each ciphertext, build an `(n+1)×(n+1)` lattice: an identity block plus a scaled weight column, with a target row of `−s·K` for a large `K`. LLL-reduce it and look for the row whose last coordinate is 0 and whose first `n` entries are all 0/1 — those are the bits. Kali ships `fpylll` (but not Sage), so the reduction runs there directly. Cache the 625 results so you can iterate on the next stage without re-reducing.

With all 625 words recovered, `setstate((3, tuple(words), None))` restores the generator exactly — a good sanity check is that the first word is `0x80000000` and the index is 624 (a freshly seeded, unused MT).

## Replaying the flag encryption

The flag routine is:

```python
r = randint(1, 2**8)
shuffled = sample(FLAG, len(FLAG))
enc = 0
for c in map(ord, shuffled):
    enc = enc * r**c + c
```

Since the captured state predates this, `setstate(state); randint(1, 2**8)` reproduces `r` (here 31). Then peel `enc` from the end: `enc = enc_prev · r^c + c`, and because `r^c ≡ 0 (mod r)` for `c ≥ 1`, the next character satisfies `c ≡ enc (mod r)`. Greedy peeling fails — a spuriously small `c` can divide `(enc − c)` and derail the chain — so use a small backtracking search: try each candidate `c` with `c % r == enc % r` and `r^c | (enc − c)`, require every recovered character to be printable, and recurse until `enc == 0`. That yields the flag in shuffled order.

Finally, undo the shuffle. `random.sample`'s consumption depends only on `(n, k)`, not the list contents, so replaying `setstate(state); randint(1, 2**8); sample(range(n), n)` reproduces the exact permutation, and `FLAG[perm[j]] = shuffled[j]` rebuilds the flag.

Create `solve.py`:

```python
import sys; sys.set_int_max_str_digits(100000)
import random
from fpylll import IntegerMatrix, LLL

enc_flag, state_enc, pub = (lambda L: (int(L[0]), eval(L[1]), eval(L[2])))(open('out.txt').read().splitlines())
state0, cts, state2 = state_enc

def break_ss(w, s):
    n = len(w); K = 1 << (2*n); M = IntegerMatrix(n+1, n+1)
    for i in range(n): M[i, i] = 1; M[i, n] = w[i]*K
    M[n, n] = -s*K
    for row in LLL.reduction(M):
        if row[n]: continue
        b = list(row[:n])
        if all(x in (0, 1) for x in b): return b
        if all(x in (0, -1) for x in b): return [-x for x in b]

words = [int(''.join(map(str, break_ss(pub, s))), 2) for s in cts]
random.setstate((state0, tuple(words), state2))
r = random.randint(1, 2**8)

sys.setrecursionlimit(100000)
def peel(e):
    if e == 0: return []
    t = e % r
    for c in range(1, 256):
        if c % r != t or (e - c) % pow(r, c): continue
        sub = peel((e - c) // pow(r, c))
        if sub is not None and all(32 <= x < 127 for x in sub + [c]): return sub + [c]

shuffled = peel(enc_flag); n = len(shuffled)
random.setstate((state0, tuple(words), state2)); random.randint(1, 2**8)
perm = random.sample(range(n), n)
flag = [None]*n
for j, idx in enumerate(perm): flag[idx] = chr(shuffled[j])
print(''.join(flag))
```

```
HTB{...}
```

## Why it worked

Merkle–Hellman is only secure when the public knapsack has high density; here the weights are far larger than the number of items, so LLL trivially recovers each subset. And capturing `getstate()` before using the generator makes the entire "random" encryption deterministic to anyone who can restore the state — the shuffle and the multiplier are fully replayable.

## Fix / defense

Don't use knapsack cryptosystems — Merkle–Hellman has been broken since 1982. If randomness must protect data, never expose (even indirectly) the PRNG state, and use a cryptographically secure generator (`secrets` / `os.urandom`) whose state can't be rewound. A keyed, authenticated cipher over the plaintext would make both the knapsack break and the state replay useless.
