---
layout: post
title: "HackTheBox: QuickScan"
date: 2027-10-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, elf, pwntools, static-analysis, rip-relative]
---

QuickScan is an Easy **Reversing** challenge that tests whether you can *automate* analysis instead of doing it by hand. A TCP service streams 128 freshly-generated x86-64 ELF binaries, each of which loads a 24-byte value onto the stack, and demands you return that value as hex for every one — all in under 120 seconds. No human can disassemble 128 binaries that fast, so the real task is to recognise the fixed instruction layout and parse it statically in a loop.

## Overview

Connect to the service and it explains the rules:

> I am about to send you 128 base64-encoded ELF files, which load a value onto the stack. You must send back the loaded value as a hex string. You must analyze them all in under 120 seconds.

Each round prints `ELF: <base64>` and asks `Bytes? `. Every binary is a tiny x86-64 ELF whose entry code is essentially:

```nasm
sub  rsp, 0x18
lea  rsi, [rip+0x259]     ; address of a 24-byte blob baked into the binary
mov  rdi, rsp
mov  ecx, 0x18
rep  movsb               ; copy 24 bytes onto the stack
```

The "loaded value" is just the 24 bytes that `lea` points at. Win all 128 rounds and the service prints the flag.

## The technique

You don't need to run or emulate anything. The data location is fully determined by the `lea` instruction's displacement, which is RIP-relative:

1. The `lea rsi, [rip+disp]` sits **4 bytes** after the entry point (after the `sub rsp, 0x18`).
2. The encoding is `48 8D 35 <disp32>` — **7 bytes total**, with the **signed 32-bit displacement at offset +3**.
3. RIP-relative addressing resolves against the address of the *next* instruction, so `target = lea_addr + 7 + disp`.
4. Read 24 (`0x18`) bytes at `target` — that's the answer.

pwntools' `ELF` object handles the virtual-address-to-file translation for you, so the whole parser is a few lines. This is just [static binary analysis](https://cwe.mitre.org/data/definitions/1006.html) — read the operands of a known instruction directly rather than disassembling each sample.

## Solution

Loop the static parser over the network rounds with pwntools. A single warmup round comes first, then the 128 scored rounds:

`solve.py`:

```python
from pwn import *
import tempfile, base64, sys, os
context.log_level = 'warn'

def get_loaded_value(elf_path):
    e = ELF(elf_path, checksec=False)
    lea_addr = e.entrypoint + 4                              # skip the `sub rsp,0x18`
    lea_off  = u32(e.read(lea_addr + 3, 4), sign='signed')  # disp32 inside the lea
    target   = lea_addr + 7 + lea_off                       # rip-relative: next insn + disp
    return e.read(target, 0x18)                             # the 24-byte blob

def do_round(r):
    r.recvuntil(b"ELF: ")
    elf = base64.b64decode(r.recvline().strip())
    with tempfile.NamedTemporaryFile(delete=False, suffix='.elf') as t:
        t.write(elf); t.flush(); path = t.name
    val = get_loaded_value(path); os.unlink(path)
    r.sendlineafter(b"Bytes? ", val.hex().encode())

host, port = sys.argv[1].split(':')
r = remote(host, int(port))
do_round(r)                              # warmup
for i in range(128):
    do_round(r)
print(r.recvall(timeout=5).decode(errors='replace'))
```

Run it against the spawned instance:

```bash
python3 solve.py <ip:port>
```

It clears all 128 binaries in roughly 20 seconds, comfortably inside the 120-second window, and the service responds:

```
Wow, you did them all. Here's your flag: HTB{...}
```

## Why it worked

The generated binaries are uniform: same prologue, same instruction at the same offset — only the displacement and the 24 data bytes vary between samples. Once you realise the data offset is **encoded in a fixed instruction layout, not random**, the "fast reversing under pressure" framing collapses into a one-time static parse repeated in a loop. Recognising a constant structure across a family of near-identical binaries is the entire skill being tested.

## Fix / defense

There's nothing to "patch" — it's a CTF exercise. The inverse lesson for analysts is the takeaway: **automated structural recognition beats sample-by-sample analysis** for families of templated binaries (think polymorphic-but-templated malware). Parse the known layout once and batch it, rather than opening each sample in a disassembler.
