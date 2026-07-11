---
layout: post
title: "BioBundle"
date: 2028-02-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, memfd_create, dlopen, packer, xor, in-memory]
description: "A reversing challenge that hides its flag checker inside an XOR-encoded shared object, loaded entirely in memory via memfd_create + dlopen(/proc/self/fd). The packer looks clever but leaks its own offset, length, and key in the decode loop — carve the ELF statically and read the flag from the checker's immediates."
---

## Overview

BioBundle is a Medium reversing challenge. The outer binary shows almost nothing under `strings` or `objdump` — its real logic (a flag checker) is an ELF shared object that only ever exists in RAM. It is built at runtime with `memfd_create`, decoded with a one-byte XOR, and loaded with `dlopen("/proc/self/fd/<fd>")`. The trick is convincing-looking but self-defeating: everything you need to carve the payload offline is spelled out in the decode loop.

## The technique

`main` calls `get_handle()`, which does the packing:

- `memfd_create("", 0)` — an anonymous, in-memory file descriptor.
- A loop over `i = 0 .. 0x3e07` that `write(fd, embedded[i] ^ 0x37, 1)` — copying an embedded blob (virtual address `0x4080`, length `0x3e08`) into the memfd, one XOR-decoded byte at a time. The result is a valid ELF shared object.
- `sprintf(path, "/proc/self/fd/%d", fd)` then `dlopen(path)`.

`main` then `dlsym`s the exported checker (its symbol is literally `_`), reads a line from stdin with `fgets`, and calls `checker(input)`. On a match it prints `[*] Untangled the bundle`; otherwise `[x] Critical Failure`. The input string that satisfies the checker is the flag.

## Solution

No need to run or trace anything — the outer binary's decode loop hands you the blob's address (`lea rdx,[rip+..] # 0x4080`), its length (`cmp qword, 0x3e07`), and the XOR key (`xor eax, 0x37`). Translate the virtual address to a file offset with the section headers, read `0x3e08` bytes, XOR each with `0x37`, and you have the real shared object to analyze offline.

Create `solve.py`:

```python
#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
import subprocess
BIN = 'biobundle'
e = ELFFile(open(BIN, 'rb')); data = open(BIN, 'rb').read()

def v2o(v):
    for s in e.iter_sections():
        a, sz = s['sh_addr'], s['sh_size']
        if a <= v < a + sz and s['sh_type'] != 'SHT_NOBITS':
            return s['sh_offset'] + (v - a)

off = v2o(0x4080)
so = bytes(b ^ 0x37 for b in data[off:off + 0x3e08])
open('embedded.so', 'wb').write(so)          # valid ELF64 shared object

# checker "_" is strcmp(input, flag); flag = movabs immediates concatenated:
frag = [0x743474737b425448, 0x5f3562316c5f6331, 0x6c3030635f747562, 0x7d7233]
flag = b''.join(x.to_bytes(8, 'little') for x in frag).split(b'\x00')[0].decode()

out = subprocess.run(['./' + BIN], input=(flag + '\n').encode(),
                     capture_output=True).stdout.decode()
assert 'Untangled' in out                     # live-confirm against the real binary
print(flag)
```

`nm embedded.so` shows a single export `_`, and its disassembly builds the flag from `movabs` immediates before a `strcmp` against your input:

```
0x743474737b425448 -> "HTB{st4t"
0x5f3562316c5f6331 -> "1c_l1b5_"
0x6c3030635f747562 -> "but_c00l"
0x00007d7233       -> "3r}"
```

Feeding the reassembled string back into the real binary prints `[*] Untangled the bundle`, confirming the flag live.

```
HTB{...}
```

## Why it worked

The packer's whole premise is that the payload never touches disk, so static tooling on the outer binary sees nothing useful. But the decoder is part of that same static binary, and it exposes the three facts that fully define the payload — offset, length, and key. Once carved, the "in-memory only" library is an ordinary ELF, and this one hard-codes its flag as stack-string immediates compared with `strcmp`.

## Fix / defense

In-memory loading (`memfd_create` + `dlopen`) is an anti-analysis convenience, not a secret — anything the process can decode from its own image, an analyst can decode too. If a checker must live client-side, don't compare against a plaintext flag: derive a key from the input and decrypt a payload with it (so no correct string exists in the binary), and use a strong KDF/authenticated cipher rather than a single-byte XOR wrapper.
