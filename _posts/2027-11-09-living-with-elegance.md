---
title: "Living with Elegance"
date: 2027-11-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, lwe, encryption-oracle, observable-discrepancy, cwe-203]
description: "A homemade LWE-style bit-encryption oracle forgets one final modular reduction, leaving its 'encrypt 1' and 'encrypt 0' branches in different value ranges — so every flag bit leaks by range membership, with no need to ever recover the secret."
---

## Overview

Living with Elegance is an easy HackTheBox **Crypto** challenge. A networked service hands you a per-bit
encryption oracle for the flag, built to look like LWE ("Learning With Errors") — the kind of scheme you'd
normally have to break by recovering a secret key. But the implementation forgets a single final modular
reduction, which leaves the two encryption branches sitting in **observably different value ranges**. That
single slip turns a "hard" scheme into a free bit-leak: every flag bit falls out by simply watching whether
a reply lands inside or outside the legal range — a textbook [observable discrepancy](https://cwe.mitre.org/data/definitions/203.html).

## The technique

The server exposes one operation: send the **index** of a flag bit, and it returns one encryption `(A, b)`
of that bit. You can ask for any index any number of times, and the flag's bit length is leaked in the
out-of-range error message. The encryption (with `n = 256` and a fixed 16-byte secret `S`) is:

```python
def noise_prod(self):
    return randbelow(2*self.n//3) - self.n//2     # e in [-128, 41]

def get_encryption(self, bit):
    A = token_bytes(self.d)
    b = self.punc_prod(A, self.S) % self.n         # (A.S) mod 256, in [0, 255]
    e = self.noise_prod()
    if bit == 1:
        return A, b + e                            # BUG: never reduced mod n again
    else:
        return A, randbelow(self.n)                # always in [0, 255]
```

The intended idea is LWE: `b` is a noisy inner product of a public vector `A` with the secret `S`, and to
distinguish a `1` from a `0` you would have to recover `S`. The bug is in the `bit == 1` branch: `b + e` is
**not** reduced modulo `n` a second time. Because `b ∈ [0, 255]` and the noise `e` is signed (`[-128, 41]`),
`b + e` can go **negative** or reach **`≥ 256`**.

The `bit == 0` branch, by contrast, returns `randbelow(256)`, which is **always** in `[0, 255]`.

So the distinguisher needs no algebra at all:

> **Any reply `< 0` or `≥ 256` is a guaranteed `bit == 1`.** The `bit == 0` branch can never produce such a value.

For a uniform `b`, the `bit == 1` branch escapes `[0, 255]` about **21%** of the time. So query a single index
~60 times: if **any** reply is out of range, the bit is `1`; if all 60 stay in `[0, 255]`, the bit is `0`.
The chance of misclassifying a real `1` as `0` after 60 tries is `0.79^60 ≈ 4×10⁻⁷` per bit.

## Solution

The full solver queries every flag-bit index, classifies by range membership, and reassembles the integer.
A small but important optimization: **pipeline all 60 queries for one index in a single send**, so the whole
attack is one network round-trip per bit rather than thousands of small ones (the challenge container throttles
chatty connections otherwise).

```python
#!/usr/bin/env python3
import sys
from pwn import remote, context
from Crypto.Util.number import long_to_bytes

context.log_level = 'error'
HOST, PORT = sys.argv[1], int(sys.argv[2])
TRIES = 60
PROMPT = b'index of the bit you want to get an encryption for : '

def main():
    io = remote(HOST, PORT)
    # length: an out-of-range index leaks "interval [0, L-1]"
    io.sendlineafter(PROMPT, b'999999')
    line = io.recvline_contains(b'interval').decode()
    L = int(line.split(',')[-1].split(']')[0].strip()) + 1
    print(f'[*] flag bit length = {L}')

    bits = []
    for idx in range(L):
        io.send((str(idx) + '\n').encode() * TRIES)     # pipeline all TRIES queries
        vals = []
        while len(vals) < TRIES:
            io.recvuntil(b'b = ')
            vals.append(int(io.recvline().strip()))
        # bit==0 can NEVER leave [0,255]; any out-of-range value proves bit==1
        bit = 1 if any(v < 0 or v > 255 for v in vals) else 0
        bits.append(str(bit))
        sys.stdout.write(str(bit)); sys.stdout.flush()
    print()
    flag = long_to_bytes(int(''.join(bits), 2))
    print('[+] FLAG:', flag.decode(errors='replace'))

if __name__ == '__main__':
    main()
```

Running it against the live instance recovers a 175-bit value and reassembles the flag:

```bash
python3 solve.py <host> <port>
# [*] flag bit length = 175
# 1001000010101000...0011111101
# [+] FLAG: HTB{...}
```

`long_to_bytes(int(bits, 2))` automatically restores the leading zero bits of the first character
(`'H' = 0x48 = 0100 1000`), so the decoded bytes come out correct without any extra padding.

## Why it worked

For an encryption scheme to hide a bit, encryptions of `0` and `1` must be **indistinguishable** — same
distribution, same support. Here the designer added LWE-style noise but forgot that an additive perturbation
**without a closing modular reduction changes the value range** of the output. One branch is confined to
`[0, n-1]`; the other is not. That mismatch is a side channel that requires no key recovery and no lattice
work — the intended hard problem (recovering `S`) is bypassed entirely by reading the *range* of a single
sample.

## Fix / defense

Reduce the noisy value back into the ring so both branches share the identical support `[0, n-1]`:

```python
if bit == 1:
    return A, (b + e) % self.n     # now indistinguishable from the bit==0 branch
else:
    return A, randbelow(self.n)
```

With both outputs uniform-looking over `[0, n-1]`, distinguishing a single sample collapses back to actually
breaking decision-LWE — the problem the scheme was supposed to rest on. The general lesson: whenever a crypto
oracle has a "real vs random" or "encrypt 0 vs encrypt 1" shape, first check that **both branches occupy the
same value range** (and length, and parity). If one branch can emit a value the other never can, you classify
by range membership instead of attacking the hard problem underneath.
