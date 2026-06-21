---
title: "Ancient Encodings"
date: 2026-11-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, encoding, base64, hex, cwe-261]
description: "A Very Easy Crypto challenge that hands you a single hex blob and a source file. There is no key and no real cipher — just base64, bytes_to_long, and hex stacked on top of each other. The whole solve is to peel each reversible layer off in reverse order to recover the flag."
---

## Overview

`Ancient Encodings` is a Very Easy HackTheBox **Crypto** challenge. You get `source.py` and an `output.txt` holding one long `0x...` hex string. The name is the hint: this is **encoding, not encryption**. Every transform the challenge applies is a public, reversible function with no key, so the flag is recovered by simply inverting each layer.

## The technique

The source defines a single transform:

```python
from Crypto.Util.number import bytes_to_long
from base64 import b64encode

def encode(message):
    return hex(bytes_to_long(b64encode(message)))
```

Three reversible operations are stacked: `b64encode` (bytes → base64 ASCII), `bytes_to_long` (a byte string → a big-endian integer), and `hex` (integer → hex string). None of them involve a secret. [Relying on encoding for confidentiality](https://cwe.mitre.org/data/definitions/261.html) is the entire weakness — anyone with the output can walk the chain backwards. The tell in any challenge like this is a `source.py` that pipes data through `base64` / `bytes_to_long` / `hex` (or `rot13`, `urlsafe_b64encode`, etc.) with no key material anywhere.

## Solution

Invert the chain from the outside in:

1. `int(hexstr, 16)` undoes `hex()`.
2. `long_to_bytes(n)` undoes `bytes_to_long()` and recovers the raw base64 ASCII string.
3. `b64decode(...)` undoes `b64encode()` and yields the flag.

Create `solve.py`:

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from base64 import b64decode

n = int(open("output.txt").read().strip(), 16)   # undo hex()
b64 = long_to_bytes(n)                            # undo bytes_to_long() -> base64 ASCII
print(b64decode(b64).decode())                    # undo b64encode() -> flag
```

Run it against the provided output:

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

Each layer is a bijection with a publicly known inverse, and the challenge ships the exact recipe in `source.py`. With no key in the pipeline there is nothing to brute-force or attack — reading the source and applying the matching inverse in reverse order is the complete break. This is the canonical "encoding is not encryption" lesson.

## Fix / defense

Encoding provides zero confidentiality; base64 and hex are transport representations, not protection. To actually keep a message secret, encrypt it with authenticated encryption (e.g. AES-GCM) under a real, secret key, and treat any base64/hex around it as packaging rather than security.
