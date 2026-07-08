---
layout: post
title: "Bombs Landed"
date: 2027-12-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, crackme, self-modifying-code, anti-debug, xor, cwe-656]
---

A 32-bit Linux crackme that asks for a password. Nothing about it is hard once you stop trying to *run* it and start reading it — but it stacks four layers of obfuscation, each designed to waste a few minutes: stripped sections, a decoy main, self-decrypting code, and a fake `strncmp`. Every layer is just a constant baked into the binary, so the whole thing falls statically. This is textbook [security through obscurity](https://cwe.mitre.org/data/definitions/656.html) ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)).

## Overview

`BombsLanded` is an `ELF 32-bit LSB executable, Intel i386, dynamically linked, no section header`, using `ptrace` and `dlsym`. The goal is to recover the password it checks. The path: peel an XOR-encrypted code blob out of the binary, disassemble it, and notice that its "`strncmp`" is a custom wrapper that XOR-transforms the stored secret before comparing.

## The technique

Four obstacles, all defeated on paper:

1. **No section headers.** `objdump -d` needs sections and shows nothing. Use a disassembler that walks the program headers instead (`r2 -A`, Ghidra). The binary also resolves libc through `dlsym` and runs a `ptrace` anti-debug check, so dynamic tracing is a dead end — read it statically.

2. **A decoy `main`.** The visible code prints `input password:`, reads one char with `getchar`, compares it to `'X'`, and prints `Bad luck dude.`. The real check is gated behind argument count — it only runs when `argc >= 5`:

   ```nasm
   cmp dword [edx], 4
   jg  0x8048a18        ; real branch only when argc > 4
   ```

   So you have to run it as `./BombsLanded a b c d`.

3. **Self-decrypting code.** The real branch `mmap`s a read-write-execute page, copies `0x197` (407) bytes from virtual address `0x80491a0`, XORs each byte with `0x63`, then `call`s the page. The "real" logic never exists on disk in runnable form.

4. **A fake `strncmp`.** The decrypted code decodes its own prompt (XOR `0x14`), reads your input, then calls a function that *looks* like `strncmp(input, target, 10)` but is hand-rolled: it `dlsym`-resolves the real `strncmp`, builds a temp buffer `tmp[i] = target[i] ^ 0x0a`, and compares your input against `tmp`. The transform lives one stack frame deeper than the compare you'd naturally breakpoint.

## Solution

Recover the encrypted code blob without running anything. Map the virtual address to a file offset using the second `LOAD` segment (`Offset 0x1000` ↔ `VirtAddr 0x8049000`), so `0x80491a0` lives at file offset `0x11a0`. XOR-decrypt and disassemble:

Create `decrypt.py`:

```python
d = open("BombsLanded", "rb").read()
blob = bytes(b ^ 0x63 for b in d[0x11a0:0x11a0 + 0x197])
open("decrypted.bin", "wb").write(blob)
```

```bash
python3 decrypt.py
r2 -2 -q -e scr.color=0 -c 'e asm.arch=x86; e asm.bits=32; pd 200' decrypted.bin
```

Inside the decrypted code, the comparison target `strB` is stored as:

```
73 65 7f 64 6f 7c 6f 78 6d 65 63 64 6d 7e 65 6c 63 64 6e 67 6f
```

Note the unprintable `0x7f` — that's the tell that the stored bytes are *not* the password directly. The custom wrapper compares your input against `strB XOR 0x0a`, so apply that:

Create `solve.py`:

```python
raw = bytes.fromhex("73657f646f7c6f786d6563646d7e656c63646e676f")
password = bytes(c ^ 0x0a for c in raw).decode()
print(password)          # younevergoingtofindme
```

Verify live against the binary — remember the `argc >= 5` gate:

```bash
printf 'younevergoingtofindme\n' | ./BombsLanded a b c d
# input password: you win.
```

The flag is `HTB{...}` built from that password.

## Why it worked

Obfuscation is not encryption. Every "lock" here ships with its own key embedded in the binary: the XOR constants (`0x63`, `0x14`, `0x0a`), the argc gate, and the custom compare are all readable in the disassembly. The single most effective trap is the fake `strncmp` — an analyst who breakpoints the visible compare and dumps its second argument reads scrambled bytes (with an unprintable `0x7f`) and concludes the secret is garbage, because the real comparand is computed inside the callee. The fix is to disassemble the function being called, not to trust its name.

## Fix / defense

[Security through obscurity](https://cwe.mitre.org/data/definitions/656.html) is not a control. Self-decrypting blobs, `dlsym` indirection, and `ptrace` anti-debug only cost an analyst minutes. A password check that must survive a local attacker can't store the secret (even transformed) in the binary at all — it should compare against a salted hash, or move the secret server-side where the client never sees it.
