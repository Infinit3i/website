---
layout: post
title: "HTB Challenge: Up a Stream"
date: 2027-06-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, java, java-streams, decompilation, jadx, arithmetic-obfuscation, cwe-656, bijection, reverse-engineering]
---

An Easy Reversing challenge whose entire "encryption" is the source code — decompile the JAR, read the math, invert it.

## Overview

**Up a Stream** is an Easy HackTheBox Reversing challenge. You receive a `stream.jar` and an `output.txt`. The description hints at Java Stream API abuse: a 67-character one-liner that encodes the flag through a chain of arithmetic operations.

The technique is [reliance on obfuscation](https://cwe.mitre.org/data/definitions/656.html) ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)): every transform in the pipeline is a pure mathematical bijection with no secret key. Decompiling the JAR with `jadx` immediately reveals the algorithm; inverting it is straightforward algebra.

## The Technique

The JAR contains one class, `Challenge`. The `dunkTheFlag(str)` method chains Java Stream API calls into a single expression that:

1. **Reverses** the input string via `reduce("", (a, b) -> b + a)` (prepending each element flips the order).
2. Applies three helper methods per character ASCII value `c`:
   - `moisten`: even `c` → `c`; odd `c` → `c²`
   - `drench`: `n` → `n << 1` (multiply by 2)
   - `dilute`: `n` → `n/2 + n` (multiply by 3/2, which with always-even input = multiply by 3)
   - Net result: **even `c` → `3c`**, **odd `c` → `3c²`**
3. Hex-encodes each result and joins them with `O` as a delimiter.
4. Calls `.repeat(5)` on the final string.

Two additional calls (`peek(hydrate)` and `peek(waterlog)`) look suspicious but are dead code — `peek` consumes the consumer's return value, and both methods return a type that doesn't match the stream's element type, so their output is silently discarded.

## Solution

### Step 1 — Decompile the JAR

```bash
jadx -d out stream.jar
```

Open `out/sources/defpackage/Challenge.java` and trace the `dunkTheFlag` pipeline. The four helper methods reduce to the net transforms above.

### Step 2 — Identify the one-repetition boundary

`output.txt` is the encoded string repeated five times. Split on `O`, count the total tokens, divide by 5 to isolate one cycle:

```python
data = open('output.txt').read().strip()
tokens = [t for t in data.split('O') if t]
n = len(tokens) // 5          # 33 tokens per repetition (= flag length)
cycle = tokens[:n]
```

### Step 3 — Invert the transform and recover the flag

For each hex token `v`:
- Compute `q = v // 3` (assert no remainder — every value must be divisible by 3)
- If `q` is **even**: the original char was even, so `c = q`
- If `q` is **odd**: the original char was odd, so `c = √q` (integer square root, must be exact)
- After all chars are recovered, **reverse** the list (the string was reversed before encoding)

```python
#!/usr/bin/env python3
"""
Up a Stream — HTB Reversing (Easy)
Reverse the Java stream pipeline in output.txt to recover the flag.

Pipeline (from Challenge.java):
  1. String -> reversed string  (via reduce: str3+str2 prepends each element)
  2. Each char x:
       moisten(x): even x -> x,  odd x -> x^2
       drench(y):  y -> y*2
       waterlog:   via peek -> DISCARDED (no effect)
       dilute(z):  z -> z + z//2   (since z always even: 3x or 3x^2)
  3. toHexString each, join with 'O', .repeat(5)

Inversion:
  - Take 1/5 of output (one repeat)
  - Split by 'O', hex -> val
  - q = val // 3  (r must == 0)
  - q even -> x = q  (was even char)
  - q odd  -> x = isqrt(q)  (was odd char, q = x^2)
  - Reverse the collected chars (string was reversed before encoding)
"""
from math import isqrt
import sys

fname = "files/rev_up_a_stream/output.txt"
if len(sys.argv) > 1:
    fname = sys.argv[1]

with open(fname) as f:
    output = f.read().strip()

segment = output[:len(output) // 5]
tokens = [t for t in segment.split("O") if t]

chars = []
for token in tokens:
    val = int(token, 16)
    q, r = divmod(val, 3)
    assert r == 0, f"val={val:#x} not divisible by 3"
    if q % 2 == 0:
        x = q
    else:
        x = isqrt(q)
        assert x * x == q, f"q={q} not a perfect square"
    chars.append(chr(x))

flag = "".join(reversed(chars))
print(flag)
```

Running it:

```
$ python3 solve.py
HTB{...}
```

## Why It Worked

Every step in `dunkTheFlag` is a bijection — a one-to-one mapping with a known inverse:

| Forward | Inverse |
|---------|---------|
| String reversal | String reversal again |
| Even `c` → `3c` | `3c` → `c` (divide by 3) |
| Odd `c` → `3c²` | `3c²` → `c` (divide by 3, take integer square root) |
| Hex-encode + `O`-join | Split on `O`, `int(tok, 16)` |
| `.repeat(5)` | Take the first 1/5 of tokens |

None of these steps involve a secret key. The `repeat(5)` serves no cryptographic purpose (five copies of the same ciphertext adds no information). The entire "security" of the scheme is that the source is compiled — one `jadx` invocation removes that protection entirely.

The two `peek` calls (`hydrate` and `waterlog`) are decoys worth noting. In Java, `Stream.peek(consumer)` is designed for debugging side-effects; the stream element is passed unchanged. Here, `hydrate` and `waterlog` return `Integer` and `byte` respectively, but the stream carries `Character` / `Integer` objects — the return values are discarded. A reader unfamiliar with `peek`'s semantics might try to account for them; recognising them as no-ops saves significant time.

## Fix / Defense

Relying on [CWE-656](https://cwe.mitre.org/data/definitions/656.html) — security through obscurity via compiled bytecode — provides no real protection. If the goal is to keep a secret confidential:

- Use an **authenticated cipher** (AES-GCM, ChaCha20-Poly1305) with a randomly-generated key that **never appears in the output**.
- Never ship the encoding algorithm as recoverable bytecode if the secret must stay hidden.
- Arithmetic bijections are encoding, not encryption. Anyone who can read the source — which `jadx` provides for free — can recover the plaintext.
