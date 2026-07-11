---
layout: post
title: "Pneumatic Validator"
date: 2028-04-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, gdb, oracle, hill-climbing, pie, crackme, cwe-1254]
description: "A stripped crackme validates the flag by running a pneumatic-circuit simulation and accepting only when the final pressure stays under 15.0. Instead of reversing the physics, we turn that single float into a distance oracle in GDB and greedy hill-climb the flag one byte at a time."
---

## Overview

Pneumatic Validator is a Hard HackTheBox Reversing challenge (originally HTB Uni CTF 2021 Quals). You get a single stripped 64-bit PIE ELF that asks for the flag and prints `Correct /o/` or `Wrong \o\`. Under the hood it runs a 1024-step **pneumatic-circuit simulation** seeded from your input and only accepts when the final maximum node pressure stays below a threshold. The whole solve hinges on one observation: that threshold check leaks a *continuous* distance-to-solution, so we never reverse the simulation — we treat the binary as an oracle and climb the hill.

## The technique

Disassembling `main` gives the entire acceptance logic:

- The flag is read from **`argv[1]`** (not stdin — there's an `argc == 2` gate), and must be exactly **20 bytes** (`strlen == 0x14`, else "Wrong length").
- Each byte is parsed into the initial valve state of a pneumatic simulation, which is stepped **1024 times** (a `0x3ff` loop counter).
- The finalizer reduces the circuit to a single `float` via `fmaxf` over several node-pressure globals, then:

```
movss  xmm0, [rel 0x60ec]   ; 0x41700000 = 15.0
comiss xmm0, [rbp-4]        ; compare 15.0 with the sim result
jbe    Wrong               ; if 15.0 <= result -> "Wrong \o\"
...    Correct /o/         ; else result < 15.0 -> "Correct /o/"
```

So **acceptance means the final max pressure is `< 15.0`**. Each flag byte drives its own valve, and a wrong byte over-pressures its node *monotonically*. That makes the final float a smooth "how wrong are you" signal — exactly the thing you can hill-climb. This is an [incorrect-comparison-granularity weakness](https://cwe.mitre.org/data/definitions/1254.html): the check leaks partial-match information instead of a single yes/no.

## Solution

The plan: break in GDB just before the `comiss`, read the result float at `[rbp-4]`, and greedily pick, for each unknown byte position, the character that minimizes that float. Iterate a couple of passes because the `fmaxf` coupling lets one dominant node mask the others.

Because the binary is PIE, a breakpoint set on a bare file offset is **not** relocated automatically. `or.gdb` fixes the address against the runtime load base:

```gdb
set pagination off
set disable-randomization on
starti
python
base = int(gdb.execute("info proc mappings", to_string=True).splitlines()[4].split()[0], 16)
gdb.execute("break *%d" % (base + 0x5640))
end
continue
printf "RESULT=%f\n", *(float*)($rbp-4)
kill
quit
```

`solve.py` drives it — greedy per-position minimization, parallelized across GDB runs:

```python
import subprocess, string, concurrent.futures

BIN = "./pneumaticvalidator"

def oracle(flag):
    out = subprocess.run(["gdb","-q","-batch","-ex",f"set args {flag}","-x","or.gdb",BIN],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("RESULT="):
            return float(line[7:])
    return float("inf")

CHARSET = string.ascii_letters + string.digits + "_-{}!?@#$%^&*()+=."
flag = list("HTB{" + "a"*15 + "}")          # 20 bytes; only 4..18 unknown

def best_char(pos):
    cur = flag[:]
    res = {}
    for c in CHARSET:
        cur[pos] = c
        res[c] = oracle("".join(cur))
    return pos, min(res, key=res.get)

for _ in range(4):
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        picks = dict(ex.map(lambda p: best_char(p), range(4, 19)))
    for p, c in picks.items():
        flag[p] = c
    if oracle("".join(flag)) < 15.0:
        break
print("".join(flag))
```

Convergence is quick — the second pass cleans up the bytes the first pass's dominant node hid:

```
pass 0: HTB{PN7Um4t1C_l0g1C}  result=131.6465
pass 1: HTB{pN3Um4t1C_l0g1C}  result=11.9336   <-- < 15.0
```

Verified live against the binary:

```bash
./pneumaticvalidator HTB{...}   # -> Correct /o/
```

## Why it worked

The author exposed a continuous, monotone distance signal all the way through to a single floating-point compare. Any check that leaks a *graded* "closeness" — a simulation energy, a match count, an early-exit `strcmp` timing — turns the keyspace into a hill you can climb. The search collapses from `95^20` brute force to roughly `20 * 95 * passes` oracle queries, with zero understanding of the pneumatic math. The `fmaxf` coupling only forces a couple of iterations; it never hides the gradient.

## Fix / defense

- **Never leak a graded distance.** Compare a constant-time hash of the *whole* input so a wrong guess is indistinguishable from any other wrong guess:

```python
import hashlib, hmac
accept = hmac.compare_digest(hashlib.sha256(flag).digest(), EXPECTED)
```

- If a simulation must gate on a threshold, derive its initial state from `SHA256(flag)` so no single byte has an independent, minimizable contribution.
- Stripping symbols doesn't help here — the weakness is the observable scalar, not the names.
