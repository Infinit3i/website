---
title: "sekur julius"
date: 2026-12-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, caesar, rot13, classical-cipher, brute-force]
description: "A Very Easy crypto challenge that 'secures' a message by Caesar-shifting it 1337 times with random shifts — but additive shifts compose modulo 26, so a thousand rounds collapse to a single shift. Brute all 26 and the answer falls out as ROT13."
---

## Overview

`sekur julius` is a Very Easy HackTheBox **Crypto** challenge. It ships a `source.py` and an
`output.txt`. The script "hardens" a Caesar cipher by applying it 1337 times with a fresh
random shift each round (`os.urandom(1337)`). The whole gimmick is a fallacy: additive shifts
compose, so the 1337 rounds reduce to one equivalent shift in `0..25`. Brute all 26 and read off
the English plaintext.

## The technique

A Caesar (additive) shift is rotation by `k mod 26`. Applying shifts `k1, k2, ..., kN` in
sequence is identical to a single shift of `(k1 + k2 + ... + kN) mod 26`, because modular
addition is associative and commutative. The cipher's effective keyspace is therefore the
alphabet size (26) — completely independent of how many rounds you stack or how large the key
is. This is a [monoalphabetic substitution weakness](https://cwe.mitre.org/data/definitions/327.html):
a broken/linear primitive gains nothing from repetition.

The provided `source.py`:

```python
def julius_encrypt(msg, shift):
    ct = ''
    for p in msg:
        if p == ' ':                       # space -> '0'
            ct += '0'
        elif not ord('A') <= ord(p) <= ord('Z'):
            ct += p                          # non A-Z passes through unchanged
        else:
            o = ord(p) - 65
            ct += chr(65 + (o + shift) % 26)
    return ct

def encrypt(msg, key):
    for shift in key:                        # key = os.urandom(1337)
        msg = julius_encrypt(msg, shift)     # all additive -> they sum mod 26
    return msg
```

Note the two quirks to mirror on decrypt: a space is encoded as `'0'`, and any non-`A-Z`
character passes through verbatim.

## Solution

There is no key to recover — just try every effective shift and pick the readable one.

Create `solve.py`:

```python
ct = open('files/crypto_sekur_julius/output.txt').read().strip()

def dec(ct, shift):
    out = ''
    for c in ct:
        if c == '0':            out += ' '                       # undo space->'0'
        elif 'A' <= c <= 'Z':   out += chr(65 + (ord(c)-65-shift) % 26)
        else:                   out += c                         # passthrough
    return out

for s in range(26):                          # brute all 26 effective shifts
    p = dec(ct, s)
    if 'HTB{' in p.upper() or 'THE' in p[:20].upper():
        print(f"[shift {s}] {p}")
```

```bash
python3 solve.py
```

The hit is shift 13 (ROT13). The decrypted message is an English note that ends:

> ...MAKE SURE YOU WRAP THE FOLLOWING TEXT WITH THE HTB FLAG FORMAT
> THEEFFECTIVEKEYSPACEOFCAESARDEPENDSONTHESIZEOFTHEALPHABET.

Wrapping that trailing string in the flag format gives `HTB{...}`.

## Why it worked

The effective keyspace of any additive cipher is the alphabet size, full stop. Round-stacking
and large random keys are irrelevant when every round is the same linear operation — they all
collapse into one equivalent shift, and 26 guesses always wins.

## Fix / defense

Never use substitution/shift ciphers for confidentiality. Use a vetted authenticated cipher
(AES-GCM, ChaCha20-Poly1305) with a proper random key and nonce. Adding "more rounds" only helps
when each round is non-linear and key-mixed, as in a real block cipher's round function —
repeating a weak linear primitive buys nothing.
