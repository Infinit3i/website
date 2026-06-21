---
title: "Initialization"
date: 2026-12-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ctr, keystream-reuse, nonce-reuse, known-plaintext, cwe-323]
description: "A Very Easy Crypto challenge that looks like it uses fresh per-message AES keys but doesn't: an aliased Python list and a nonceless counter force every message to share one keystream, so a single known plaintext decrypts the flag."
---

## Overview

`Initialization` is a Very Easy HackTheBox **Crypto** challenge. You get `source.py`, `messages.txt` (four plaintexts, three known, one is the flag), and `output.txt` (four AES-CTR ciphertexts). The encryption *looks* careful — it even comments `# nonce reuse : avoided!` — but two ordinary Python bugs force every message to be encrypted under the **same keystream**. With three plaintexts handed to you, recovering that keystream and decrypting the flag is one XOR away.

## The technique

AES in CTR mode is a stream cipher: `ciphertext = plaintext XOR keystream`, where the keystream depends only on `(key, nonce/counter)` — never on the plaintext. The cardinal rule is that a `(key, nonce)` pair must never be reused. If it is, then for any two messages `ct1 XOR ct2 = pt1 XOR pt2`, and a single known plaintext leaks the whole keystream. This is a [reuse of a key/nonce pair in encryption](https://cwe.mitre.org/data/definitions/323.html) ([CWE-323](https://cwe.mitre.org/data/definitions/323.html)).

Here the source contains two bugs that combine to guarantee reuse:

```python
class AdvancedEncryption:
    def __init__(self, block_size):
        self.KEYS = self.generate_encryption_keys()
        self.CTRs = [Counter.new(block_size) for i in range(len(MSG))]  # "nonce reuse : avoided!"

    def generate_encryption_keys(self):
        keys = [[b'\x00']*16] * len(MSG)        # bug 1: all rows are the SAME list object
        for i in range(len(keys)):
            for j in range(len(keys[i])):
                keys[i][j] = os.urandom(1)      # writes through that one shared object
        return keys
```

- **Bug 1 — aliased key list.** `[[b'\x00']*16] * len(MSG)` does *not* create independent rows. `list * int` repeats the *reference*, so every `keys[i]` is the same underlying list. The nested loop that fills in `os.urandom(1)` writes through that single shared object, so when it finishes, **all per-message keys are byte-identical** despite looking randomized.
- **Bug 2 — nonceless counter.** PyCryptodome's `Counter.new(128)` builds a full 128-bit counter with **no random prefix**, so it starts at `0` for every message — equivalent to a hardcoded IV.

Same key + same starting counter for all four messages = one shared keystream. The reassuring comment is a red herring.

## Solution

Because the keystream is independent of the plaintext, any known message leaks it:

```
keystream = ct_known XOR pad(pt_known, 16)
flag      = ct_flag  XOR keystream
```

`messages.txt` gives plaintexts 0, 1, and 3 verbatim; message 2 is the flag (`'HTB{?????...}'`). The full solve script:

```python
#!/usr/bin/env python3
from Crypto.Util.Padding import pad

MSG = [
    'This is some public information that can be read out loud.',
    'No one can crack our encryption algorithm.',
    'HTB{?????????????????????????????????????????????}',   # unknown = flag (index 2)
    'Secret information is encrypted with Advanced Encryption Standards.',
]
ct = [bytes.fromhex(l) for l in open('output.txt').read().split()]

def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

# Build the longest keystream possible from every KNOWN plaintext.
ks = bytearray(max(len(c) for c in ct))
for i, m in enumerate(MSG):
    if i == 2:
        continue
    stream = xor(ct[i], pad(m.encode(), 16))
    for j, b in enumerate(stream):
        ks[j] = b

flag = xor(ct[2], ks)
print(flag.split(b'}')[0] + b'}')   # strip PKCS7 padding
```

Running it prints the flag:

```
HTB{...}
```

## Why it worked

Neither bug "breaks" AES — the cipher is fine. The failure is upstream: the key-generation routine produces identical keys (aliased list), and the counter carries no nonce, so the `(key, counter)` pair repeats across every message. A stream cipher under a repeated keystream offers no confidentiality once any single plaintext is known, and here three of the four were published in the challenge files.

## Fix / defense

- **Use a fresh random nonce per message** and bind it into the counter: `Counter.new(64, prefix=os.urandom(8))` for AES-CTR, or a random 12-byte nonce with AES-GCM.
- **Never build mutable structures with `list * int`** for independent elements — use `keys = [os.urandom(16) for _ in range(len(MSG))]` so each key is its own object.
- **Prefer an authenticated AEAD** (AES-GCM, ChaCha20-Poly1305) over raw CTR, and never reuse a `(key, nonce)` pair.
- Don't trust a comment that claims reuse is "avoided" — assert it: `assert len(set(keys)) == len(MSG)`.
