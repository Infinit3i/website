---
layout: post
title: "ShadowLabyrinth"
date: 2028-04-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, custom-vm, meet-in-the-middle, aes, linear-algebra, mod-2-32]
description: "A three-stage reversing crackme: meet-in-the-middle cracks 12 embedded modular equations for the first 48 flag characters, those characters ARE the AES key that decrypts a bytecode VM, and the VM's flag check is a disguised linear system A·x ≡ v (mod 2^32) that falls to Gaussian elimination."
---

## Overview

ShadowLabyrinth is a Hard HackTheBox Reversing challenge from the 2025 Business CTF. You get a stripped x86-64 ELF and an encrypted blob `file.bin`. The flag is 83 characters inside `HTB{...}`, and recovering it means peeling three coupled layers: a set of embedded modular equations gives the first 48 characters, those characters double as the AES key that decrypts a custom bytecode VM, and the VM's final check — which looks like an expensive obfuscated loop — is really a linear system over `Z/2^32` you can invert directly.

## The technique

Three ideas stack on top of each other, and each layer's output is the next layer's key:

1. **Meet-in-the-middle on modular equations.** The ELF's `.rodata` holds a table of 12 results and 12 groups of four 64-bit coefficients. Each equation is `Σ coef[j]·flag[4e+j] ≡ result (mod 2^64)` over four printable-ASCII unknowns. Brute-forcing four bytes is 256⁴; instead you split the unknowns in half and meet in the middle — build a dictionary of the ~95² partial sums for the first two characters, then look each candidate for the other two up in it. Each equation resolves to a unique printable quad. The 48 recovered bytes are the first half of the flag, but **permuted** by a 48-byte shuffle box that also lives in `.rodata`.

2. **Self-referential decryption as a correctness oracle.** Those same 48 characters are the AES-256-CBC key for `file.bin`: XOR the ciphertext head with `key[32:48]`, AES-CBC-decrypt with `key[0:32]`, then `zlib` inflate. If the inflate succeeds, the first 48 characters were correct — no separate check needed. The plaintext is a ~500 KB stream of 32-bit words: a custom VM program.

3. **A bytecode VM whose check is a linear system.** The interpreter dispatches with `call [handler_table + opcode*8]` over 16 opcodes (reset/add/sub/xor/shift/load/store/branch/getch/puts/exit). It reads the last 35 flag characters and succeeds only when 35 registers are all zero. Under the obfuscation — a "multiply" built from repeated addition, which makes naive differencing look non-linear — the computation is exactly `A·x ≡ v (mod 2^32)`, where `x` is the 35 unknown characters, `A` is a small multiplier matrix, and `v` is an expected vector.

## Solution

**Stage 1 — meet-in-the-middle for the first 48 characters.** Read the 12 results and 48 coefficients from `.rodata`, solve each equation, then un-permute with the shuffle box.

```python
import struct
d = open("shadow_labyrinth", "rb").read()
results = [struct.unpack_from("<Q", d, 0x20e0 + 8*i)[0] for i in range(12)]
coefs   = [[struct.unpack_from("<Q", d, 0x2140 + 8*(4*e+j))[0] for j in range(4)] for e in range(12)]
MOD, CH = 1 << 64, range(0x20, 0x7f)

def solve_eq(cs, r):
    A = {}
    for x0 in CH:
        for x1 in CH:
            A.setdefault((cs[0]*x0 + cs[1]*x1) % MOD, []).append((x0, x1))
    for x2 in CH:
        for x3 in CH:
            t = (r - cs[2]*x2 - cs[3]*x3) % MOD
            if t in A:
                return (*A[t][0], x2, x3)

key = b"".join(bytes(solve_eq(coefs[e], results[e])) for e in range(12))
shuffle = [16,25,32,5,0,45,38,2,14,40,24,17,7,33,23,29,39,15,35,21,46,26,19,47,
           43,20,13,31,1,22,44,42,30,8,34,11,18,27,12,9,41,36,4,28,3,6,37,10]
first48 = bytearray(48)
for i, j in enumerate(shuffle):
    first48[j] = key[i]
```

**Stage 2 — decrypt the VM.** The 48-byte key decrypts `file.bin` to the bytecode; a clean inflate confirms stage 1.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from zlib import decompress
dat = open("file.bin", "rb").read()
xored = bytes(dat[i] ^ key[32:][i % 16] for i in range(len(dat)))
iv = bytes([0x8c,0xa2,0xca,0xb2,0x29,0xdb,0x61,0x0a,0xac,0xdd,0x9d,0x43,0x7c,0x61,0x7a,0xf3])
vm = decompress(unpad(AES.new(key[:32], AES.MODE_CBC, iv).decrypt(xored), 16))
```

**Stage 3 — recover the opcode table, emulate, and solve the linear system.** Port the VM to C for speed (Python is far too slow once the repeated-addition loops run at real character values), extract the 35×35 multiplier matrix `A` and expected vector `v` from the running VM (a GDB read-watchpoint on the accumulator register during each per-character loop dumps them cleanly), then solve `x = A⁻¹·v` with Gaussian elimination over `Z/2^32` — choosing odd pivots and using `pow(a, -1, 2**32)`.

```python
def solve_mod(A, b, M):
    A = [r[:] for r in A]; b = b[:]; N = len(A); row = 0; piv = [-1]*N
    for col in range(N):
        sel = next((r for r in range(row, N) if A[r][col] & 1), -1)
        if sel < 0: continue
        A[row], A[sel] = A[sel], A[row]; b[row], b[sel] = b[sel], b[row]
        inv = pow(A[row][col], -1, M)
        A[row] = [x*inv % M for x in A[row]]; b[row] = b[row]*inv % M
        for r in range(N):
            if r != row and A[r][col]:
                f = A[r][col]
                A[r] = [(A[r][j] - f*A[row][j]) % M for j in range(N)]
                b[r] = (b[r] - f*b[row]) % M
        piv[col] = row; row += 1
    return [b[piv[c]] % M if piv[c] >= 0 else 0 for c in range(N)]

last35 = bytes(v & 0xff for v in solve_mod(A, v_vector, 1 << 32))
flag = "HTB{" + first48.decode() + last35.decode() + "}"
```

Verify live by feeding the assembled flag to the real ELF — it prints `Authentication complete!` — and by re-running the C emulator, which reports all 35 check registers at zero. The flag reads `HTB{...}` (redacted here), and the two halves spell out the challenge's own hint about adding, multiplying, and a familiar melody.

## Why it worked

Every layer trusts a value the previous layer already exposed. The modular equations are underdetermined on their own, but the printable-ASCII constraint makes each one uniquely solvable by meet-in-the-middle. Reusing the flag as the AES key means a single wrong byte breaks decompression, giving a free correctness oracle. And the VM's "hard" final check is only *presented* as an expensive computation — a repeated-addition multiply and a permutation dress it up — while the underlying map is a plain linear transform. Once you recognize `A·x ≡ v (mod 2^32)`, the whole VM collapses into one matrix inversion.

## Fix / defense

Obfuscation that reduces to linear algebra buys nothing against a patient reverser: a check that is affine over any ring is invertible in closed form regardless of how many opcodes wrap it. If the goal were genuinely to resist key recovery, the check would need a one-way, non-invertible transform (a real cryptographic hash comparison) rather than a disguised matrix multiply, and the decryption key should not be derivable from data the binary itself validates and leaks.
