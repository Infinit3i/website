---
layout: post
title: "Alien Saboteur"
date: 2028-04-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, virtual-machine, bytecode, self-modifying-code, emulator, xor]
description: "A custom bytecode VM guards two access codes. Recover its instruction set from the interpreter's own symbols, emulate it so a self-modifying decrypt stage runs itself, and beat a data-independent flag check by probing it as an affine map instead of inverting the rounds."
---

## Overview

Alien Saboteur is a Medium HackTheBox Reversing challenge. You get two files: `vm`, an ELF64 interpreter, and `bin`, a program written in the VM's own bytecode (it begins with the magic `UwU`). The machine wants two access codes — a keycode and a secret phrase. The path is to recover the instruction set from the interpreter, write an emulator, and invert the checks. The second check turns out to be data-independent, so a handful of oracle probes recovers the answer without reversing its 36 rounds.

## The technique

The heart of the challenge is that the flag is verified by a **custom virtual machine**, not native code — a common reversing obfuscation. Three observations flatten it:

1. **The interpreter leaks its own instruction set.** `vm` is *not stripped*, so `nm vm` lists every handler (`vm_add`, `vm_xor`, `vm_load`, `vm_store`, `vm_je`, `vm_input`, `vm_putc`, …) and the dispatch table `original_ops` in `.data` maps each opcode byte to its handler. `objdump` on each handler reveals a fixed 6-byte instruction encoding.
2. **A store-into-code emulator handles self-modification for free.** After the first code is accepted, the VM XOR-decrypts a hidden region of its *own* bytecode and falls through into it. If your emulator's `store` opcode writes back into the same buffer it executes from, this decrypt just happens — no manual patching.
3. **A data-independent check is affine.** The phrase check permutes the input with a constant table and XORs it with a constant keystream. Since neither depends on the data, the whole transform is `out = Perm(in) ^ K` — recoverable by probing.

## Solution

**Recover the VM model.** Instructions are 6 bytes; the code pointer is `filebuf + 3` (past the `UwU` magic); `ip` counts instructions, so a jump target of N is byte offset `N*6`; `putc` takes an immediate character (the banner is a run of `putc` immediates). With the opcode table in hand, a small Python disassembler prints `bin`.

**Stage 1 — the keycode.** The first check reads 18 characters and compares `code[0x1004 + i] ^ 0xA9 == input[i]`. So the keycode is just the stored bytes XORed with `0xA9`:

`c0d3_r3d_5hutd0wn`

**Stage 2 — the self-decrypt.** On success the VM runs `code[0x77*6 : +1501] ^= 0x45` in place — the `0x55` (`'U'`) filler bytes decrypt into real opcodes — then falls through into the newly-revealed stage.

**Stage 2 — the phrase.** The 36-character phrase is run through a constant permutation plus an XOR keystream (36 rounds) and compared to a fixed target. Because the transform ignores its input, it's affine, so probe the emulated transform `T` to lift it:

Create `solve2.py` (probe recovery):

```python
K = T(bytes(N))                       # transform of zeros = the constant XOR
dest = []
for j in range(N):                    # find where each input byte lands
    out = T(bytes(0xff if k == j else 0 for k in range(N)))
    dest.append(next(i for i in range(N) if out[i] != K[i]))
phrase = bytes(target[dest[j]] ^ K[dest[j]] for j in range(N))
assert T(phrase) == target            # forward-verify
```

The recovered phrase *is* the flag. Confirm live against the real interpreter:

```bash
printf 'c0d3_r3d_5hutd0wn\nHTB{...}\n' | ./vm bin
# [Main Vessel Terminal]
# < Enter keycode
# > < Enter secret phrase
# > Access granted, shutting down!
```

The flag reads `HTB{...}` (redacted — and note that public writeups quote a stale value, so always re-derive it from your own solve).

## Why it worked

A custom VM is obscurity, not security. The interpreter's symbol table hands over the whole ISA; a store-to-code emulator makes the self-modifying decrypt stage a non-event; and the final gate is a reversible, key-independent transform — so it leaks its own answer to `N` oracle queries. Nothing about the check is one-way.

## Fix / defense

Don't rely on interpreter obscurity to protect a secret, and never gate on a reversible transform. If a program must verify a passphrase, compare a one-way KDF/hash of the input against a stored digest — a data-independent, invertible check ([CWE-656](https://cwe.mitre.org/data/definitions/656.html), security through obscurity) always falls to probing.
