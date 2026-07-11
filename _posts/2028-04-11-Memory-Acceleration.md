---
layout: post
title: "Memory Acceleration"
date: 2028-04-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, z3, smt, proof-of-work, custom-hash, hash-inversion, cwe-1204]
description: "A network proof-of-work asks you to make a bespoke 32-bit hash output zero four times, controlling two integer keys. Instead of reversing the mixing function, model its key-controlled tail in z3 and assert output == 0 — and lengthen the controlled input so the system is satisfiable without brute force."
---

## Overview

Memory Acceleration is a Hard HackTheBox Crypto challenge. The service hands you a growing block of text and demands two integers, `first_key` and `second_key`, such that a homemade hash `phash(block, key1, key2) == 0`. Satisfy it four rounds in a row and it prints the flag. There is no factoring or lattice here — just a bespoke 32-bit mixing function you have to force to a chosen output. The intended weakness is [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html): a proof-of-work built on a [homemade, non-one-way transform](https://cwe.mitre.org/data/definitions/1204.html) that an SMT solver can invert directly.

## The technique

`phash` has two halves. The **key1 loop** runs 13 rounds mixing `md5(block)` dwords with `key1` through multiplications, `rotl`, and an AES-style S-box, producing a 32-bit state `h0`. Two side values `u, z` fall out of this loop but depend **only on the block**, not on the keys. The **key2 loop** then churns `h` once per byte of `sub(key2)` (the key run through the same S-box) and finishes `h *= u*z; h &= 0xffffffff; return h`.

The move is to stop reversing and start *solving*. Run the input-only key1 loop in plain Python to get `h0` and `uz32 = (u*z) & 0xffffffff`. Hand only the small key2 tail loop to z3, modelling `h` as a 32-bit bitvector with the S-boxed key bytes as the unknowns, and assert the final `h * uz32 == 0`.

Two facts make it clean:

- **Everything is mod 2³².** Python computes the XOR/`+`/`-` in arbitrary precision and only masks with `& 0xffffffff` at the end of each iteration. The high bits are shifted away and discarded, so a `BitVec(32)` with wrapping arithmetic reproduces the Python bit-for-bit (use `LShR` for the logical `>>`).
- **You choose how much freedom to give yourself.** The key is a variable-length integer, and its byte length sets the loop count. Pinning `key2` to 4 bytes forces a brute-force over `key1`; using an **8-byte key2** instead gives z3 64 bits of freedom against a single 32-bit `== 0` constraint, so it is satisfiable at `key1 = 0` on the very first try.

Because the key is S-boxed before use, z3 solves for the **post-S-box** bytes; invert the S-box to recover the real key bytes, keeping the leading byte's pre-image nonzero so `long_to_bytes` doesn't drop a byte and shift the loop count.

## Solution

The core solver — plain-Python prefix to compute `(h0, uz32)`, then z3 for the tail:

```python
from z3 import BitVec, BitVecVal, Solver, LShR, sat
m = 0xffffffff

def solve_key2(h0, uz32, nbytes=8):
    s = Solver()
    ds = [BitVec(f'd{i}', 32) for i in range(nbytes)]
    for d in ds:
        s.add(d >= 0, d <= 255)
    s.add(ds[0] != 0x63)                  # inv_sbox[0x63]==0; keep leading byte nonzero
    h = BitVecVal(h0, 32)
    for d in ds:
        a = (h << 1) & m
        b = (h << 3) & m
        c = LShR(h, 4) & m
        h = (h ^ ((a + b + c - d) & m)) & m
        h = (h + h) & m
    s.add(h * BitVecVal(uz32, 32) == 0)   # z3 handles uz32's 2-adic valuation
    if s.check() != sat:
        return None
    mdl = s.model()
    real = bytes([inv_sbox[mdl[d].as_long()] for d in ds])
    return bytes_to_long(real)
```

Then drive the socket: for each of the four blocks the server sends, compute `(h0, uz32)` with `key1 = 0`, solve `key2`, send both integers, and read the flag from the fourth round.

```python
for rnd in range(4):
    block = get_block()                   # read the "validate this memory block: ..." line
    k1, k2 = find_keys(block)             # key1=0; z3-solve key2 (8 bytes)
    r.sendlineafter(b'Enter first key: ',  str(k1).encode())
    r.sendlineafter(b'Enter second key: ', str(k2).encode())
```

The flag is derived live — the keys are recomputed against the real block each round, never copied.

```text
Klaus this is important!!
This can help you find your father!!
HTB{...}
```

## Why it worked

The hash designer built a nonlinear 32-bit function but exposed **two attacker-controlled inputs** and asked only that the output land on a fixed value. Any deterministic function over a bounded domain is just a satisfiability problem; z3 solves the key-controlled tail directly, and enlarging the controlled input turns "hard to invert" into "trivially satisfiable." The `u*z` multiply that terminates the hash doesn't help the defender either — asserting `h_tail * uz32 == 0` lets the solver exploit the factor-of-two structure of `uz32` for free.

## Fix / defense

A proof-of-work must be *hard to satisfy by design*. Anchor it to a preimage/second-preimage-resistant primitive — require `sha256(nonce) < target` — rather than a homemade mixing function whose output an attacker can constrain. And never let the client feed multiple free inputs into a small (32-bit) output space: that collapses the whole scheme into an SMT-solvable system.
