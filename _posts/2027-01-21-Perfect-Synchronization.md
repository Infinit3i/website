---
title: "Perfect Synchronization"
date: 2027-01-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ecb, substitution-cipher, frequency-analysis, hill-climbing]
description: "A Very Easy Crypto challenge that encrypts the flag one character at a time under AES-ECB with a fixed key and salt. Because each character always maps to the same block, AES collapses into a plain monoalphabetic substitution cipher — solvable as a classic cryptogram with frequency analysis and a dictionary hill-climb, no key recovery needed."
---

## Overview

`Perfect Synchronization` is a Very Easy HackTheBox **Crypto** challenge. You get a
short Python source file and an `output.txt` full of hex blocks — no server, no
network target, fully offline. The source encrypts a secret message (containing the
flag) with AES in [ECB mode](https://cwe.mitre.org/data/definitions/327.html), but it
makes one fatal choice: it encrypts **one character at a time** under a **fixed key and
salt**. That turns AES-256 into a glorified [monoalphabetic substitution cipher](https://cwe.mitre.org/data/definitions/327.html),
which we break with nothing more than frequency analysis and a dictionary.

## The technique

Here is the relevant part of `source.py`:

```python
class Cipher:
    def __init__(self):
        self.salt = urandom(15)
        key = urandom(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, message):
        return [self.cipher.encrypt(c.encode() + self.salt) for c in message]
```

Two things are set **once** in `__init__` and never change for the whole message: the
`key` and the 15-byte `salt`. Encryption then runs per-character: each plaintext char
`c` becomes `AES-ECB(c || salt)` — a single 16-byte block (1 byte of `c` + 15 bytes of
salt = exactly one AES block).

ECB is deterministic: the same input block always produces the same output block. Since
both the key and the salt are constant, **every occurrence of a given character yields
the exact same 16-byte ciphertext block.** The character `'A'` is always one fixed
block, `'E'` is always another, and so on. AES adds no secrecy here beyond hiding which
block corresponds to which letter — it is a 1-to-1 symbol map, i.e. a substitution
cipher.

The plaintext charset is constrained by an assertion at the top of the file:

```python
assert all([x.isupper() or x in '{_} ' for x in MESSAGE])
```

So the alphabet is `A`–`Z`, plus space, `{`, `_`, and `}` — 30 symbols total. Crucially,
**space is its own symbol**, so word boundaries survive into the ciphertext. That makes
this a textbook cryptogram with spacing intact, which is the easy kind to solve.

## Solution

The whole solve is offline. Counting the unique blocks pins down the structural symbols
immediately:

- **30 unique blocks** = 26 letters + space + `{` + `_` + `}`.
- **Space** is the most frequent block by far (English text).
- The two blocks that appear **exactly once** are `{` and `}` (they bracket the flag).
- The block that appears **only between those braces** is `_` (the flag's word separator).
- The remaining 26 blocks are the letters.

After mapping blocks to placeholder tokens, we recover the substitution with a
dictionary-scored **hill-climb**: score a candidate key by English quadgram frequencies
(built from the system word list) plus a bonus for every real dictionary word — the
preserved word boundaries make this converge in a few seconds.

Here is the full working `solve.py`:

```python
#!/usr/bin/env python3
# Perfect Synchronization (HTB Crypto) — AES-ECB with a FIXED salt+key = monoalphabetic substitution.
# Each plaintext char is encrypted as ECB(char||salt) with salt/key set once => every occurrence of a
# char yields the same 16-byte block. output.txt is therefore a substitution cryptogram WITH word
# boundaries (space is its own symbol), broken with a dictionary-scored hill-climb.
import re, random, string, math
from collections import Counter

random.seed(1337)

blocks = [l.strip() for l in open(
    "files/crypto_perfect_synchronization/output.txt") if l.strip()]
c = Counter(blocks)

space   = c.most_common(1)[0][0]                       # 230 = ' '
singles = [b for b, n in c.items() if n == 1]          # the two count-1 blocks = '{' and '}'
lo, hi  = sorted([blocks.index(singles[0]), blocks.index(singles[1])])
lbrace, rbrace = blocks[lo], blocks[hi]
region  = blocks[lo + 1:hi]
outside = set(blocks[:lo]) | set(blocks[hi + 1:])
underscore = [b for b in set(region) if b not in outside and b not in (lbrace, rbrace)][0]

specials = {space: " ", lbrace: "{", rbrace: "}", underscore: "_"}
letters_syms = [b for b in c if b not in specials]     # exactly 26 letter symbols
order = sorted(letters_syms, key=lambda b: -c[b])
tok = {b: chr(ord('a') + i) for i, b in enumerate(order)}
cipher = "".join(specials.get(b, tok.get(b)) for b in blocks)

# english quadgram model + word list from the system dictionary
words = [w.strip().upper() for w in open("/usr/share/dict/american-english")
         if re.fullmatch(r"[a-zA-Z]+", w.strip()) and len(w.strip()) > 2]
quad = Counter()
for w in words:
    for i in range(len(w) - 3):
        quad[w[i:i + 4]] += 1
total = sum(quad.values())
floor = math.log10(0.01 / total)
logq = {k: math.log10(v / total) for k, v in quad.items()}
DICT = set(words)

def apply(key, text):
    table = {chr(ord('a') + i): key[i] for i in range(26)}
    return "".join(table.get(ch, ch) for ch in text)

def score(text):
    s = 0.0
    for w in text.split(" "):
        w = w.strip("{}_")
        if not w:
            continue
        for i in range(len(w) - 3):
            s += logq.get(w[i:i + 4], floor)
        if w in DICT:
            s += 8.0
    return s

alpha = list(string.ascii_uppercase)
best, best_key = None, alpha[:]
for restart in range(40):
    key = alpha[:]; random.shuffle(key)
    cur = score(apply(key, cipher)); improved = True
    while improved:
        improved = False
        for i in range(26):
            for j in range(i + 1, 26):
                key[i], key[j] = key[j], key[i]
                sc = score(apply(key, cipher))
                if sc > cur:
                    cur = sc; improved = True
                else:
                    key[i], key[j] = key[j], key[i]
    if best is None or cur > best:
        best, best_key = cur, key[:]

plain = apply(best_key, cipher)
m = re.search(r"\{[^}]*\}", plain)
print(plain[:200])
print("HTB" + (m.group(0) if m else ""))
```

Running it recovers the plaintext — which turns out to be an essay *about* frequency
analysis — and the flag right out of the `{...}` region:

```text
FREQUENCY ANALYSIS IS BASED ON THE FACT THAT IN ANY GIVEN STRETCH OF WRITTEN LANGUAGE ...
... CRYPTANALYSIS FREQUENCY ANALYSIS GENERALLY HTB{...} CARD TYPE ...
```

Flag value redacted — render as `HTB{...}`.

## Why it worked

ECB has no diffusion between blocks and no per-message randomization once the key and
salt are fixed, so identical plaintext units always produce identical ciphertext units.
Encrypting **per character** takes that property to its logical extreme: the scheme is a
deterministic 1-to-1 map from 30 symbols to 30 blocks — a substitution cipher wearing an
AES costume. Keeping space as its own symbol preserves word boundaries, which downgrades
the cryptogram from "hard" to "trivially dictionary-solvable." The salt being secret and
random is irrelevant: we never need to know the key, the salt, or break AES at all.

## Fix / defense

Never encrypt data unit-by-unit with a fixed key, and never use [ECB](https://cwe.mitre.org/data/definitions/327.html)
for anything but key wrapping. Encrypt the **whole** message at once under an
authenticated mode with a fresh random nonce per encryption:

```python
from Crypto.Cipher import AES
nonce = os.urandom(12)
ct = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(MESSAGE.encode())
```

With AES-GCM and a per-message nonce, identical plaintext produces different ciphertext
every time and block boundaries leak nothing, so no substitution map exists to recover.
