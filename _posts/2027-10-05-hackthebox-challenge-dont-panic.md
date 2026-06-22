---
layout: post
title: "HackTheBox Challenge: Don't Panic"
date: 2027-10-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, rust, crackme, static-analysis, objdump, closures, cwe-602]
---

Don't Panic is an Easy Rust reversing challenge whose whole gimmick is in the name.
The binary asks for a "message", and either panics (`😱 You made me panic!`) or stays
calm (`😌 All is well`). The message that keeps it calm **is** the flag — and you never
have to run or brute-force it, because the flag is sitting in plain sight inside a chain
of single-byte compare instructions.

## Overview

- **Category:** Reversing · **Difficulty:** Easy
- **Binary:** 64-bit PIE ELF, written in Rust (`rustc 1.78.0`), not stripped, debug info present.
- **One-line path:** the flag check is one tiny closure per character, each doing
  `cmp dil, CONST` and panicking unless the byte matches — read the 35 constants in
  dispatch order and you have the flag.

This is a textbook [reliance on a client-side check / secret embedded in the shipped
binary](https://cwe.mitre.org/data/definitions/602.html) — the "secret" never leaves the
executable, so static analysis recovers it completely.

## The technique

Running the binary shows the gate but nothing useful:

```bash
$ echo AAAA | ./dontpanic
🤖💬 < Have you got a message for me? > 🗨️ 🤖: 😱😱😱 You made me panic! 😱😱😱
```

In the disassembly, `src::check_flag(buf, len)` does three things:

1. Builds an on-stack array of **35 function pointers** at `rsp+0x10 + 8*i`, each pointing
   at a distinct `core::ops::function::FnOnce::call_once` closure.
2. Asserts `len == 0x23` (35); a wrong length hits `core::panicking::assert_failed`
   (the "You made me panic!" path via a custom panic hook).
3. Loops `i = 0..35`: loads `dil = buf[i]` then `call [rsp + 8*i + 0x10]` — dispatching the
   *i-th* input byte to the *i-th* closure.

Every closure is the same shape:

```nasm
push rax
cmp  dil, 0x48        ; the expected byte for this position ('H')
jb   panic
jne  panic            ; mismatch -> falls through to a panic!() call
pop  rax
ret                   ; match -> returns quietly
```

So the program is literally: *for each position, is this byte the one I want?* Survive all
35 panic-gates and you win. There are only 22 distinct closures for 35 slots, because
repeated letters reuse the same closure.

The flag therefore equals the 35 `cmp` immediates **in dispatch order**. The only twist
versus a flat compare-chain is that you must recover the *order the closures are stored
into the array* (`rsp+0x10 + 8*i`), not just the constants.

## Solution

`solve.py` recovers both halves statically from `objdump` — no execution, no brute force:

```python
#!/usr/bin/env python3
"""Don't Panic (HTB Reversing, Easy) — static solver.
check_flag(buf,len) asserts len==0x23 (35), then for each index i calls a
per-character closure[i](buf[i]). Every closure is `cmp dil, CONST; je pass; <panic>`
i.e. it panics unless the byte equals CONST. So the 35-byte input that does NOT panic
IS the flag. We recover it by (1) reading each closure's compare constant and (2) reading
the order closures are stored into the on-stack array (rsp+0x10 + 8*i)."""
import subprocess, re, sys
B = sys.argv[1] if len(sys.argv) > 1 else "dontpanic"

# 1) closure addr -> expected byte  (cmp dil,0xNN)
d = subprocess.check_output(
    ['objdump','-d','--start-address=0x8a40','--stop-address=0x8fc0','-M','intel',B]).decode()
closure, cur = {}, None
for ln in d.splitlines():
    m = re.match(r'^([0-9a-f]+) <', ln)
    if m: cur = int(m.group(1),16)
    c = re.search(r'cmp\s+dil,0x([0-9a-f]+)', ln)
    if c and cur is not None and cur not in closure:
        closure[cur] = int(c.group(1),16)

# 2) check_flag: emulate `lea REG,[rip..] # ADDR` then `mov [rsp+off],REG`
cf = subprocess.check_output(
    ['objdump','-d','--start-address=0x9120','--stop-address=0x9320','-M','intel',B]).decode()
reg, slots = {}, {}
for ln in cf.splitlines():
    m = re.search(r'lea\s+(\w+),\[rip\+0x[0-9a-f]+\]\s+#\s+([0-9a-f]+)\s+<', ln)
    if m: reg[m.group(1)] = int(m.group(2),16); continue
    m = re.search(r'mov\s+QWORD PTR \[rsp(?:\+0x([0-9a-f]+))?\],(\w+)', ln)
    if m and m.group(2) in reg:
        slots[int(m.group(1),16) if m.group(1) else 0] = reg[m.group(2)]

# array base rsp+0x10, stride 8, 35 entries
flag = ''.join(chr(closure[slots[0x10+8*i]]) for i in range(35))
print(flag)
```

Run it, then verify live against the binary — the flag is only trusted once the binary
itself stays calm:

```bash
$ python3 solve.py dontpanic
HTB{...}
$ printf 'HTB{...}' | ./dontpanic
🤖💬 < Have you got a message for me? > 🗨️ 🤖: 😌😌😌 All is well 😌😌😌
```

`All is well` and a clean exit means every panic-gate passed — the recovered string is the
flag.

## Why it worked

The flag-check is pure data. The compiler lowered "compare each character to a constant"
into a table of single-byte-compare closures, and the constants are the plaintext flag.
No transform, no key, no server round-trip — the only mild obfuscation is the indirect
call table, which just means the dispatch order must be reconstructed alongside the
constants. This is the [secret-in-the-client](https://cwe.mitre.org/data/definitions/602.html)
anti-pattern: anything the client can assemble at runtime, an analyst can assemble
statically.

## Fix / defense

Don't compare user input against plaintext constants. Compare a hash/HMAC of the input,
or derive a key from it and use that key to decrypt the protected content — so the secret
never appears as `cmp` operands. Stripping the binary and removing debug info raises the
bar for analysis, but per-character immediate compares leak the secret to anyone with
`objdump` regardless.
