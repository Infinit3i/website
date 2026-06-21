---
title: "Classic, yet complicated!"
date: 2027-02-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, vigenere, classical-cipher, known-plaintext, crib]
description: "An Easy Crypto challenge whose ciphertext is an English description of the Vigenère cipher. Use a guessed phrase as a known-plaintext crib to peel off the repeating key, and the key itself is the flag."
---

## Overview

**Classic, yet complicated!** is an Easy HackTheBox **Crypto** challenge. You get a
single `ciphertext.txt` and the hint *"Find the plaintext, the key is your flag!"*.
The text is a [Vigenère](https://cwe.mitre.org/data/definitions/327.html)-encrypted
English paragraph that happens to *describe the Vigenère cipher itself* — which gives
you a free known-plaintext crib to recover the repeating key in one step.

## The technique

Vigenère encrypts with `c = p + k (mod 26)`, where the key repeats over the letters
of the message. The fatal weakness here is twofold: the key is short and repeating,
and the plaintext is *predictable* (it is a writeup of the cipher). If you can guess
any phrase that appears in the message, subtracting that known plaintext from the
ciphertext (`k = c − p mod 26`) leaks the keystream at that position. Because the key
repeats, the minimal repeating unit of the leaked keystream reconstructs the whole
key — this is a classic **known-plaintext crib** attack, the same idea that breaks
repeating-key XOR.

## Solution

The ciphertext preserves spaces and punctuation, so it is a substitution cipher on
letters only. Reading the shape of the words, a 14-letter word followed by a 6-letter
word is almost certainly **"polyalphabetic cipher"**:

```
ciphertext : lccjdstslpahzn fptspf
plaintext  : polyalphabetic cipher
```

Subtracting plaintext from ciphertext over that span recovers the keystream
`worldhello worl...` — a rotation of `helloworld`. Two details matter: the key index
advances **only on alphabetic characters** (spaces/punctuation are skipped), and the
crib starts at an unknown offset so the recovered unit is the key *up to rotation* —
resolve it by brute-forcing the rotations and keeping the one that decrypts to English.

Save the solver as `solve.py`:

```python
import sys, re
ct = open(sys.argv[1] if len(sys.argv) > 1 else "files/ciphertext.txt").read()

def dec(text, key):                       # Vigenere decrypt; key advances on letters only
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            k = ord(key[ki % len(key)]) - 97
            out.append(chr((ord(ch.lower()) - 97 - k) % 26 + 97)); ki += 1
        else:
            out.append(ch)
    return "".join(out)

ctl = re.sub('[^a-z]', '', ct.lower())                 # letter-only stream
crib_ct, crib_pt = "lccjdstslpahznfptspf", "polyalphabeticcipher"
idx = ctl.find(crib_ct)
ks = "".join(chr((ord(c) - ord(p)) % 26 + 97)          # keystream leaked by the crib
             for c, p in zip(ctl[idx:], crib_pt))

def min_period(s):                                     # minimal repeating unit = key (rotated)
    for L in range(1, len(s) + 1):
        if len(s) % L == 0 and all(s[i] == s[i % L] for i in range(len(s))):
            return s[:L]
    return s

unit = min_period(ks)
common = "the and that with cipher key was used century polyalphabetic flag".split()
best = max((unit[r:] + unit[:r] for r in range(len(unit))),   # pick the English rotation
           key=lambda k: sum(dec(ct, k).count(w) for w in common))
print("key:", best)
print(dec(ct, best))
print("FLAG: HTB{%s}" % best.lower())
```

Running it recovers the key and the plaintext:

```bash
python3 solve.py files/ciphertext.txt
# key: helloworld
# the vigenere cipher, was invented by a frenchman, blaise de vigenere in the 16th
# century. it is a polyalphabetic cipher because it uses two or more cipher alphabets
# to encrypt the data. ... the key is the flag.
# FLAG: HTB{...}
```

The decrypted text spells out the rule directly: *"the key is the flag."*

## Why it worked

A repeating key over a long, guessable plaintext leaks itself. One correct crib of a
few letters is enough: subtracting it from the ciphertext exposes the keystream, and
since the key repeats, that fragment reconstructs the entire key. Choosing a weak,
guessable key (`helloworld`) only makes it easier — but Vigenère is broken even with a
strong key once any plaintext is known.

## Fix / defense

Vigenère offers no real confidentiality. Use a modern authenticated cipher such as
AES-GCM or ChaCha20-Poly1305 with a random key per message. If a stream/one-time-pad
construction is genuinely required, the key must be cryptographically random, **at
least as long as the message**, and **never reused** — the moment a repeating or
predictable key meets known plaintext, the scheme falls.
