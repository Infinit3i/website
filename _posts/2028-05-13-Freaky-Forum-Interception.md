---
layout: post
title: "Freaky Forum Interception"
date: 2028-05-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, ffi, golang, rust, python, java, jni, cwe-656]
description: "One binary, four language runtimes. A Go/cgo ELF links CPython, a JVM, and a Rust static lib, then splits the flag into four underscore-separated segments — each guarded by a different language. The trick is to stop tracing one giant control flow and instead reverse each segment in its own native tooling."
---

## Overview

Freaky Forum Interception is a **Hard** HackTheBox **Reversing** challenge. You get a single ELF, `ffi` — a Go 1.13 `cgo` binary that links **libpython3.10**, **libjvm**, and a **Rust static library** all at once. The C `main` reads `HTB{...}`, splits the inner text on `_` into four segments, and hands each segment to a checker written in a *different* language. Every checker must pass before it prints `Correct!`. The theme fits: *"make yourself heard above the babble"* — a forum of languages all shouting at once. The path is to reverse each runtime separately with the right tool for that language, and never try to follow one combined control-flow graph.

## The technique

The dispatcher is plain C:

```c
fgets(buf, 0x80, stdin);
sscanf(buf, "HTB{%[^}]}", inner);        // pull out what is between the braces
// require EXACTLY 3 underscores -> 4 segments
GoCheck(seg0)      || die("Golang says no!");
rust_check(seg1)   || die;
python_check(seg2) || die;
java_check(seg3)   || die;
puts("Correct!");
```

Segments split on `_` map one-to-one to languages: `seg0 -> Go`, `seg1 -> Rust`, `seg2 -> Python`, `seg3 -> Java`. This is textbook [reliance on security through obscurity](https://cwe.mitre.org/data/definitions/656.html) ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)): every constant — the seeds, the expected bytes, even the embedded Java class — ships inside the binary, so nothing is actually secret.

### seg0 — Go (`GoCheck`)

`GoCheck` spawns one goroutine per input character and collects them through channels with a `selectgo` and a 100 ms timer (`main.Oracle` / `main.Waiter`). That concurrency is a smokescreen. The real data is a global `main.g`: an array of `{index, char}` pairs that is deliberately **shuffled**. Read it straight and you get garbage; sort by the stored index and it spells the segment.

### seg1 — Rust (`rust_check`)

Six bytes, non-uppercase, constrained three ways, all read out of the disassembly:

- Pair sums (a forward/reverse zip): `b[i] + b[5-i]` = `{223, 221, 103}`
- A Horner base-3 digest: `243·b0 + 81·b1 + 27·b2 + 9·b3 + 3·b4 + b5 = 36307`
- A merge-sort that yields index order `[2,3,0,4,1,5]`

Brute-forcing printable bytes against all three gives a unique answer.

### seg2 — Python (embedded CPython)

The binary calls `random.seed(31337)`, registers a C method that returns `random.randrange(256)` on each call, and checks `secret[i] == input[i] ^ k[i]` with `secret = [34,175,45,38,59]`. Python's Mersenne-Twister plus `_randbelow` are version-stable, so a local interpreter reproduces the exact keystream:

```python
import random; random.seed(31337)
secret = [34,175,45,38,59]
print(''.join(chr(s ^ random.randrange(256)) for s in secret))
```

### seg3 — Java (embedded JVM)

`java_check` boots a JVM and **`DefineClass`** a `Checker` class whose bytecode is baked into `.rodata` as a `CAFEBABE` blob (its length lives in the symbol `Class_size`). Carve it by its magic and decompile with `javap`:

```sh
python3 -c "d=open('ffi','rb').read();i=d.find(b'\xca\xfe\xba\xbe');open('Checker.class','wb').write(d[i:i+4000])"
javap -c -p Checker.class
```

`hello_java(String)` requires, for every `i`, `s[i] + s[i+1] == arr[i]` with `arr = [219,227,209,154,104,97,158,163]` (length 9). That is 8 equations for 9 unknowns, so **many** strings pass the check — the intended one is the leetspeak word. Confirm the choice live against the real JVM:

```sh
javac -cp . TestJ.java && java -cp . TestJ   # Checker.hello_java("<seg3>") -> true
```

## Solution

The durable artifact is `solve.py`, which re-derives all four segments directly from the binary — the Go table, the Rust constraints, the Python keystream, and the Java pair-sum system:

```python
#!/usr/bin/env python3
import random, struct, sys

def read_go(raw, segs):                       # seg0: shuffled {index,char} table
    def rd(va, n):
        for v,o,s in segs:
            if v <= va < v+s: fo=o+(va-v); return raw[fo:fo+n]
    hdr = rd(0x2641f0, 16)
    ptr = struct.unpack_from('<Q', hdr, 0)[0]; ln = struct.unpack_from('<Q', hdr, 8)[0]
    arr = rd(ptr, ln*16); out = [None]*ln
    for i in range(ln):
        e = arr[i*16:i*16+16]
        out[struct.unpack_from('<Q', e, 0)[0]] = chr(e[8])
    return ''.join(out)

def solve_rust():                             # seg1: pair sums + Horner base-3 + sort order
    for b0 in range(0x20,0x7f):
      b5=223-b0
      for b1 in range(0x20,0x7f):
        b4=221-b1
        for b2 in range(0x20,0x7f):
          b3=103-b2
          b=[b0,b1,b2,b3,b4,b5]
          if any(not(0x20<=x<=0x7e) for x in b): continue
          if any(0x41<=x<=0x5a for x in b): continue
          if sum(b)!=547: continue
          h=0
          for x in b: h=h*3+x
          if h!=36307: continue
          if sorted(range(6), key=lambda i:(b[i],i))!=[2,3,0,4,1,5]: continue
          return ''.join(map(chr,b))

def solve_py():                               # seg2: random.seed(31337) keystream XOR
    random.seed(31337)
    secret=[34,175,45,38,59]
    return ''.join(chr(s ^ random.randrange(256)) for s in secret)

def solve_java():                             # seg3: s[i]+s[i+1]==arr[i], pick the leet word
    arr=[219,227,209,154,104,97,158,163]
    leet=str.maketrans("7105342","tiosea4")
    cands=[]
    for c0 in range(0x20,0x7f):
        cs=[c0]
        for a in arr: cs.append(a-cs[-1])
        if all(0x20<=c<=0x7e for c in cs): cands.append(''.join(map(chr,cs)))
    for s in cands:
        if s.isalnum() and s.translate(leet).lower()=="functions": return s
    return next((s for s in cands if s.isalnum()), cands[0])

def main():
    raw=open(sys.argv[1] if len(sys.argv)>1 else 'files/rev_ffi/ffi','rb').read()
    e_phoff=struct.unpack_from('<Q',raw,0x20)[0]; e_phnum=struct.unpack_from('<H',raw,0x38)[0]
    e_phentsize=struct.unpack_from('<H',raw,0x36)[0]; segs=[]
    for i in range(e_phnum):
        off=e_phoff+i*e_phentsize; t=struct.unpack_from('<I',raw,off)[0]
        o=struct.unpack_from('<Q',raw,off+8)[0]; v=struct.unpack_from('<Q',raw,off+16)[0]
        fs=struct.unpack_from('<Q',raw,off+32)[0]
        if t==1: segs.append((v,o,fs))
    print("HTB{%s_%s_%s_%s}"%(read_go(raw,segs), solve_rust(), solve_py(), solve_java()))

if __name__=="__main__": main()
```

Running it against the binary prints the four leetspeak words joined into `HTB{...}`, which submits successfully. The flag reads as a plain sentence about the challenge itself.

```
HTB{...}
```

## Why it worked

Foreign Function Interface (FFI) lets one process host several language virtual machines side by side. The challenge weaponizes that by giving each VM one slice of the secret, betting that an analyst will drown trying to follow control flow that hops between the Go scheduler, the CPython interpreter, the JVM, and Rust. But splitting the check across runtimes adds no secret — it only raises the effort. Once you reverse each segment in its own world (objdump for the Go and Rust native code, the CPython C-API plus a local `random` for Python, and a `DefineClass` carve plus `javap` for the JVM), each one falls to a small offline computation.

## Fix / defense

Client-side validation is never a security control, no matter how many languages it spans. Every constant an analyst needs — the PRNG seed, the shuffled table, the comparison arrays, the embedded `.class` — is right there in the file. A real integrity check has to depend on a **server-held secret** the client cannot read: verify the input against a signed server response, not against constants baked into a distributed binary.
