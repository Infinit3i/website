---
title: "Rebuilding"
date: 2027-09-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, crackme, init-array, constructor, xor, cwe-656]
description: "An Easy Reversing challenge: a crackme checks a 32-char password with a repeating-key XOR. The static key in .data is a decoy — an ELF .init_array constructor rebuilds it before main runs, so trusting the static bytes gives the wrong answer."
---

## Overview

**Rebuilding** is an Easy HackTheBox **Reversing** challenge: a small, not-stripped
x86-64 PIE ELF that validates a password passed as `argv[1]`. The check is a simple
repeating-key XOR, but the key you read out of the static binary is a decoy — an ELF
`.init_array` constructor *rebuilds* it before `main` ever runs. Account for the
constructor and the password (which is the flag) falls straight out.

## The technique

`main()` does three things:

1. Require `argc == 2`.
2. Require `strlen(argv[1]) == 0x20` (32 characters).
3. For each `i` in `0..31`, compare `argv[1][i] == encrypted[i] ^ key[i % 6]`,
   counting matches. All 32 must match → **"The password is correct"**.

So the password is just `encrypted[i] ^ key[i % 6]` — a 6-byte repeating-key XOR.
`encrypted` is 32 bytes in `.data` at `0x201020`.

The trap is the key. Reading `.data` statically shows:

```
201040  14 00 68 75 6d 61 6e 73 00      ..humans.
```

`key` at `0x201042` reads **`humans`** — and XOR-ing with that produces garbage. The
challenge's whole point is the **second `.init_array` constructor** at `0x84a` (the one
that prints *"Preparing secret keys"*), which overwrites the key byte-by-byte *before*
`main` executes:

```nasm
84e:  lea  rdi,[rip+0x24f]          ; "Preparing secret keys"
855:  call puts@plt
85a:  mov  BYTE PTR [rip+...],0x61  ; key[0]='a'
861:  mov  BYTE PTR [rip+...],0x6c  ; key[1]='l'
868:  mov  BYTE PTR [rip+...],0x69  ; key[2]='i'
86f:  mov  BYTE PTR [rip+...],0x65  ; key[3]='e'
876:  mov  BYTE PTR [rip+...],0x6e  ; key[4]='n'
87d:  mov  BYTE PTR [rip+...],0x73  ; key[5]='s'
```

`humans` is **rebuilt** into **`aliens`** — that's the challenge name, and the flag
text spells out exactly what to look for. This kind of static-analysis decoy is a clean
example of [security through obscurity](https://cwe.mitre.org/data/definitions/656.html)
(CWE-656).

## Solution

First, find and disassemble the constructors — never trust a static global in a crackme
until you've checked what runs before `main`:

```bash
objdump -s -j .init_array ./rebuilding
objdump -d -M intel ./rebuilding | grep -iE 'mov +BYTE PTR \[rip'
objdump -s -j .data ./rebuilding | grep 201020
```

That confirms the key is rebuilt to `aliens` and gives the 32 `encrypted` bytes. Then
reverse the XOR offline:

Create `solve.py`:

```python
import subprocess

encrypted = bytes([
    0x29,0x38,0x2b,0x1e, 0x06,0x42,0x05,0x5d, 0x07,0x02,0x31,0x10, 0x51,0x08,0x5a,0x16,
    0x31,0x42,0x0f,0x33, 0x0a,0x55,0x00,0x00, 0x15,0x1e,0x1c,0x06, 0x1a,0x43,0x13,0x59,
])
key = b"aliens"  # rebuilt from "humans" by the .init_array constructor @0x84a

pw = bytes(encrypted[i] ^ key[i % 6] for i in range(32)).decode()
print("password:", pw)

out = subprocess.run(["./rebuilding", pw], capture_output=True, text=True).stdout
print(out.strip().splitlines()[-1])
```

```bash
python3 solve.py
# password: HTB{h1d1ng_c0d3s_1n_c0nstruct0r5
# The password is correct
```

The recovered 32-char password *is* the flag content. The `strlen == 32` gate truncates
the trailing brace, so the submitted flag appends `}`: `HTB{...}` **(redacted)**.

If you'd rather not reason about the constructor at all, just snapshot the key at runtime
after it has been rebuilt:

```bash
gdb -q -batch -ex 'b main' -ex run -ex 'x/6cx &key' ./rebuilding
```

## Why it worked

ELF `.init_array` constructors run **before `main`**. Any tool that reads only the static
`.data` image — `objdump -s`, `readelf -x`, a Ghidra listing — sees the *pre-rebuild*
value. A constructor that writes to the same address the check later reads silently
invalidates that static view. These constructors are normal compiled functions (often
named `frame_dummy`, `FUN_xxxx`, or `_GLOBAL__sub_*`) and are easy to miss because
nothing in `main`'s call graph reaches them.

## Fix / defense

Rebuilding a constant key from another constant is trivial anti-static-analysis — a
single dynamic snapshot at a `b main` breakpoint defeats it. For a real check, the key
must be derived from a runtime secret or validated by a remote service; a constant
transformed by a constant carries no security value, only obscurity.
