---
title: "Brainy's Cipher"
date: 2027-03-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, crt, brainfuck, esolang, cwe-320]
description: "An Easy Crypto challenge with two layers: the ciphertext file is actually a Brainfuck program, and the RSA parameters it prints leak the CRT private values p, q, dp and dq — enough to decrypt directly with the Chinese Remainder Theorem, no public exponent required."
---

## Overview

`Brainy's Cipher` is an Easy HackTheBox **Crypto** challenge. The download is a single
`brainy.txt` file that, at first glance, looks like noise. Two observations crack it:
the file is a [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck) program (the prompt's
"esoteric programming" hint), and the values it prints are RSA **CRT private
parameters** — which let us decrypt with no public or private exponent at all.

## The technique

The challenge leans on a [key-management weakness (CWE-320)](https://cwe.mitre.org/data/definitions/320.html):
RSA's private material — the primes `p`, `q` and the CRT exponents `dp = d mod (p-1)`
and `dq = d mod (q-1)` — is shipped *alongside* the ciphertext, merely encoded as a
Brainfuck program. Encoding is not confidentiality. Once those values are in hand, the
[Chinese Remainder Theorem](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm)
recovers the plaintext directly — the public exponent `e` and full private exponent `d`
are never needed, because `dp`/`dq` already *are* the per-prime private exponents.

## Solution

Running the Brainfuck program prints the parameter blob:

```
{p:..., q:..., dp:..., dq:..., c:...}
```

We get `p`, `q`, `dp`, `dq` and the ciphertext `c` — but neither `e` nor `d`. That's
fine. Decrypt each residue per prime and recombine with Garner's formula.

Create `solve.py`:

```python
#!/usr/bin/env python3
# 1) Brainfuck interpreter -> emits the RSA parameter blob.
src = open("brainy.txt").read()
tape = bytearray(30000); ptr = 0; out = []
stk = []; jm = {}
for i, ch in enumerate(src):                     # precompute matching-bracket jumps
    if ch == '[': stk.append(i)
    elif ch == ']':
        j = stk.pop(); jm[i] = j; jm[j] = i
ip = 0
while ip < len(src):
    ch = src[ip]
    if   ch == '>': ptr += 1
    elif ch == '<': ptr -= 1
    elif ch == '+': tape[ptr] = (tape[ptr] + 1) & 0xff
    elif ch == '-': tape[ptr] = (tape[ptr] - 1) & 0xff
    elif ch == '.': out.append(tape[ptr])
    elif ch == '[' and tape[ptr] == 0: ip = jm[ip]
    elif ch == ']' and tape[ptr] != 0: ip = jm[ip]
    ip += 1
blob = bytes(out).decode('latin1')               # {p:..,q:..,dp:..,dq:..,c:..}

# 2) RSA-CRT decrypt — no e, no d needed.
import re
v = {k: int(val) for k, val in re.findall(r'(\w+):(\d+)', blob)}
p, q, dp, dq, c = v['p'], v['q'], v['dp'], v['dq'], v['c']
n = p * q
mp = pow(c, dp, p)                               # message mod p
mq = pow(c, dq, q)                               # message mod q
qinv = pow(q, -1, p)
m = (mq + q * ((qinv * (mp - mq)) % p)) % n       # Garner recombination
print(m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('latin1'))
```

```bash
python3 solve.py
# ch1n3z_r3m4ind3r_the0rem_r0ck$$$_...
```

The recovered password is a Chinese-Remainder-Theorem pun; wrapping it in the flag
format gives `HTB{...}` (value redacted).

## Why it worked

RSA's security model assumes `p`, `q`, `d` (and the CRT cache `dp`, `dq`, `qinv`) stay
secret. Here every CRT private component was handed over with the ciphertext. Any single
one is as sensitive as the whole private key — leaking just `p` factors `n` and yields
`d` outright; leaking `dp`/`dq` skips even that step. The Brainfuck layer was obfuscation,
not encryption.

## Fix / defense

- Publish only the **public** key `(n, e)`. Keep `p`, `q`, `dp`, `dq`, `qinv` in an
  HSM or private keystore and never serialize them next to ciphertext.
- Don't treat base64, packing, or esoteric-language encodings as a security boundary.
- This is [CWE-320 (Key Management Errors)](https://cwe.mitre.org/data/definitions/320.html) /
  A02:2021 Cryptographic Failures.
