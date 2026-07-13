---
layout: post
title: "Reflection"
date: 2028-05-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, memory-forensics, reflective-dll-injection, volatility, stack-strings, powershell, cwe-506]
description: "A reflectively-injected DLL builds its PowerShell launcher one byte at a time on the stack — so strings, malfind, and even Volatility come up empty. The fix is to carve the mov-byte instructions straight out of the raw dump."
---

## Overview

Reflection is a **Medium** HackTheBox **Forensics** challenge. You get a single
1 GB Windows 7 SP1 x86 memory dump (`memory.raw`) and nothing else. A
reflectively-injected DLL hid in `notepad.exe` and built an encoded PowerShell
command on the stack byte-by-byte, so none of the usual string- or module-based
techniques find it. The flag falls out only after you carve the `mov`
instructions out of the raw image and reassemble the command yourself.

## The technique

A **reflective DLL** maps itself into a process without the Windows loader — no
`LoadLibrary`, no on-disk file, no module-list entry. That alone defeats
disk-based and module-list forensics. What makes this one *Medium* is the second
layer: the injected payload never stores its command as a string constant. It
writes each character as an **immediate operand inside an instruction**:

```asm
mov byte [ebp-0x40], 'p'     ; C6 45 C0 70
mov byte [ebp-0x3f], 'o'     ; C6 45 C1 6F
mov byte [ebp-0x3e], 'w'     ; C6 45 C2 77
```

`C6 45 <off> <imm>` is `mov byte [ebp+off], imm8`. Because the characters live
inside instructions, **no contiguous copy of the string exists anywhere in
memory**, which is exactly what an [obfuscated-payload evasion](https://cwe.mitre.org/data/definitions/506.html) is
designed to achieve. So:

- `strings` / `grep` for `HTB{`, `powershell`, or the base64 → nothing.
- Volatility `malfind` would flag the injected RWX region, but it still can't
  hand you the assembled string.

## Solution

Volatility was also a dead end here for a very practical reason — the analysis
box was offline with no Windows symbol pack and no way to download one:

```bash
vol -f memory.raw banners.Banners      # empty
vol -f memory.raw windows.info
# Unsatisfied requirement plugins.Info.kernel.symbol_table_name
# A symbol table requirement was not fulfilled ...
```

When Volatility has no symbols and no network, stop fighting it and carve the raw
image directly. Find every run of consecutive `C6 45 <off> <imm>` mov-byte
instructions, take the immediates, **reorder them by their signed stack offset**
(the compiler may emit them out of order — sorting by stack slot reassembles the
real string), then decode. The recovered command is a standard encoded
PowerShell launcher whose `-enc` argument is base64 of **UTF-16LE**.

Create `solve.py`:

```python
import re, base64, sys

data = open(sys.argv[1] if len(sys.argv) > 1 else "memory.raw", "rb").read()

pat = re.compile(rb'(?:\xc6\x45.[\x20-\x7e]){10,}')
for m in pat.finditer(data):
    blk = m.group()
    pairs = []
    for i in range(0, len(blk), 4):
        off = blk[i + 2]
        so = off - 256 if off > 127 else off      # signed stack offset
        pairs.append((so, blk[i + 3]))
    pairs.sort(key=lambda x: x[0])                 # reorder by stack slot
    s = bytes(c for _, c in pairs)
    if b"powershell" in s.lower():
        b64 = s.split(b"-enc ", 1)[1]
        print(base64.b64decode(b64).decode("utf-16-le"))
        break
```

Run it:

```bash
python3 solve.py memory.raw
# powershell -ep bypass -enc ZQBjAGgAbwAgAEgAVABCAHsA...
# echo HTB{...}
```

The flag is the string echoed by the reconstructed PowerShell command.

## Why it worked

The injected code still has to materialize its command line in memory at some
point — and it did, as instruction immediates. Those are just as recoverable as
a plaintext string once you know the instruction pattern to scan for. Sorting by
stack offset is the crux: without it the bytes are scrambled and the string looks
like garbage. And PowerShell `-enc` / `-encodedcommand` base64 is **always
UTF-16LE**, so decoding it as ASCII would fail.

## Fix / defense

- Detect reflective injection at runtime: watch for RX/RWX private memory in a
  process with no backing file (EDR, or `malfind` when symbols are available).
- Alert on `powershell.exe -enc` command lines via Script Block Logging
  (Event ID 4104), which records the decoded script regardless of stack-string
  construction.
- Signature on the assembled behavior, not the static string — stack-string
  construction (MITRE **T1027**) and reflective DLL injection (**T1055.001**) are
  known techniques whose whole purpose is to leave no literal string to match.
