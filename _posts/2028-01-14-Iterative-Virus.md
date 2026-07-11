---
layout: post
title: "Iterative Virus"
date: 2028-01-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, malware, self-decrypting, polymorphic, pe-infector]
---

## Overview

Iterative Virus is a Medium **Reversing** challenge. The file `HELLO_WORLD_INFECTED_!!!.exe`
is a self-replicating PE64 file-infector: its virus body lives in a custom `.ivir` section
and the flag is stored under a per-generation cipher that only decodes to valid code after
the virus has "matured" through five generations. The trick is that you never have to run
the malware — you can replay its own transform offline and read the flag straight out of
the decrypted stage.

## The technique

The PE `AddressOfEntryPoint` points **inside** `.ivir` (RVA `0x1c000`), so the virus stub
runs before any real program. Reversing that stub shows three relevant pieces:

1. **A generation-counter byte** at `.ivir+5` (value `1` in the sample). The stub branches on
   it: at `counter == 5` it executes the payload; otherwise it decrypts one more round.
2. **A per-round multiplicative decrypt loop** at `.ivir+0x743` that multiplies each qword of
   a fixed `0x198`-byte region (`.ivir[0x7e4 : 0x7e4+0x198]`, 51 qwords) by `keys[counter]`
   mod 2^64, then writes `counter+1` into each newly infected file:

   ```asm
   mov  rax, rbx                       ; rbx = keys[counter]
   imul rax, QWORD PTR [rdx+rcx*1]     ; ciphertext_qword *= key   (mod 2^64)
   mov  QWORD PTR [rdx+rcx*1], rax
   add  rdx, 8
   cmp  rdx, 0x198                     ; region length
   jl   ...
   ```

3. **The five round-keys**, shipped in `.ivir` as the `movabs` constants selected by a
   `cmp r14b, {0..4}` ladder:

   | gen | key (× mod 2^64)    |
   |----:|---------------------|
   | 0   | `0x28C8AA0746A75909` |
   | 1   | `0x6E2368B9C685770B` |
   | 2   | `0xEB7FD64E061C1A3D` |
   | 3   | `0xCB8FF2D53D7505A1` |
   | 4   | `0x0F1EF554206DCE4D` |

Because multiplication by an odd constant mod 2^64 is a bijection and the round keys are in
the binary, the "polymorphism" is just a reversible key schedule. Since the sample sits at
generation 1, applying keys 1 → 2 → 3 → 4 reproduces exactly what the virus would write by
the time the counter reached 5 — the executable stage-5 code. This is a textbook
[embedded self-decrypting payload](https://cwe.mitre.org/data/definitions/506.html); you
defeat it by replaying the transform, not by executing a self-replicating sample.

## Solution

Replay the remaining generations over the region, then read the flag out of the decrypted
stage. The stage-5 code assembles the flag on the stack with `mov [rsp+off], imm` stores,
so it never appears as a contiguous string in the file — you order the immediates by their
`rsp` offset.

Create `solve.py`:

```python
import struct

MASK = (1 << 64) - 1
PATH = "HELLO_WORLD_INFECTED_!!!.exe"

IVIR_RAW = 0x18400                       # .ivir raw file offset (from section header)
REGION_OFF = IVIR_RAW + 0x7e4            # encrypted stage payload inside .ivir
REGION_LEN = 0x198                       # 51 qwords
KEYS = [0x28C8AA0746A75909, 0x6E2368B9C685770B, 0xEB7FD64E061C1A3D,
        0xCB8FF2D53D7505A1, 0x0F1EF554206DCE4D]

d = open(PATH, "rb").read()
magic = d[IVIR_RAW + 5]                  # generation counter == 1
region = bytearray(d[REGION_OFF:REGION_OFF + REGION_LEN])

for m in range(magic, 5):                # drive the counter 1 -> 5
    for i in range(0, REGION_LEN, 8):
        q = struct.unpack_from("<Q", region, i)[0]
        struct.pack_into("<Q", region, i, (q * KEYS[m]) & MASK)
open("stage5.bin", "wb").write(region)

# stage-5 builds the flag on the stack: replay each mov [rsp+off], imm (verified via objdump)
writes = [(0x20, 0x7b425448, 4), (0x24, 0x33563166, 4), (0x28, 0x5f, 1),
          (0x29, 0x52337469, 4), (0x2d, 0x4f695461, 4), (0x31, 0x5f6e, 2),
          (0x33, 0x56, 1), (0x34, 0x73757231, 4), (0x38, 0x7d, 2)]
flag = bytearray(0x40)
for off, val, n in writes:
    flag[off:off + n] = val.to_bytes(n, "little")
print(flag[0x20:0x40].split(b"\x00")[0].decode())
```

```bash
python3 solve.py
# HTB{...}
```

To recover the stack stores yourself, disassemble the decrypted region and read the
immediates in offset order:

```bash
objdump -D -b binary -m i386:x86-64 -M intel stage5.bin | grep 'rsp'
```

## Why it worked

The scheme mislabels a reversible operation as encryption. Multiplying by an odd constant
mod 2^n is invertible (odd numbers are units mod a power of two), so each "generation" can
be undone — and here the forward multipliers are shipped inside the binary, so you don't
even need the modular inverses. The generation counter is *data*, not control flow you must
trigger: because every round is deterministic arithmetic on section bytes, all remaining
generations can be fast-forwarded statically. The stage-5 payload building the flag on the
stack only hides it from a naive `strings` — it falls out the moment you order the stores.

## Fix / defense

- Never rely on self-modification or a multiplicative "cipher" for secrecy — if the keys
  and schedule ship with the sample, the payload is fully recoverable offline.
- Treat an entry point that lands **outside** `.text`, in a writable/executable *last*
  section, as an infection indicator.
- Signature the infection artifacts: the appended `.ivir` section name and the infection
  marker (`TimeDateStamp == 0x53494854`, ASCII `"THIS"`), plus CRC32 PEB-walk API resolution
  with no import table, are strong dropper signals for YARA.
- Analyze self-replicating malware statically in an isolated VM — never by executing it.
