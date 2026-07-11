---
layout: post
title: "Indefinite"
date: 2028-02-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, anti-debug, ptrace, self-modifying, zlib, crc32, keystream]
description: "A reversing challenge that hides its real code behind a ptrace-driven self-decompressing packer, then encrypts the flag with a CRC32-derived keystream. Both defenses collapse statically: inflate the hidden stubs from the binary, and break the cipher with zero key material using a palindrome invariant."
---

## Overview

Indefinite is a Medium reversing challenge. You get a small x86-64 ELF (`indefinite`) and an encrypted file (`flag.txt.enc`). The binary refuses to give up its logic to a debugger — it materializes its real code at runtime and wipes it again — and it encrypts with a per-run random key. Both obstacles fall to pure static analysis: extract and inflate the hidden code from the file, recover the cipher, then break it without ever knowing the key.

## The technique

**1 — A ptrace self-decompressing packer.** `main` marks the page holding `child()` as RWX with `mprotect`, then `fork`s. The child calls `ptrace(PTRACE_TRACEME)`, traps, and runs; the parent `wait`s, `PTRACE_CONT`s, and enters `tracer()`. The real bodies of `do_encrypt_file`, `do_encryption`, and the file helpers are not present in the binary as code — each is a **zlib-compressed blob** sitting behind a `ud2` instruction (`0f 0b`). Executing `ud2` raises `SIGILL`; the parent tracer catches it, reads a little header `[0f0b][compressed_len u16][uncompressed_len u16]` and the zlib stream via `PTRACE_PEEKTEXT`, `inflate`s it, and writes the real machine code back over the `ud2` with `process_vm_writev` before continuing. A single-stepping debugger sees only the trap — the code isn't there yet.

Defeating it needs no debugger at all. Every hidden stub begins with the zlib magic `78 9c` immediately after its `0f 0b`. Scan the ELF for `78 9c`, `zlib.decompress` each stream, and disassemble the inflated bytes at the `ud2`'s virtual address. The plaintext functions appear instantly.

**2 — A CRC32 palindrome keystream.** The recovered `do_encryption` is a keystream XOR cipher:

```
state = key            # 8 bytes from /dev/urandom, NOT stored in the .enc file
for each 8-byte block:
    state = advance(state)
    block ^= state     # little-endian u64 XOR
```

`advance(x)` computes a reflected **CRC32** over the 8 state bytes (polynomial `0xEDB88320`, init/final `0xFFFFFFFF`) to get a 32-bit `crc`, then returns `crc | bswap64(crc)`. That fold makes every keystream word an 8-byte **palindrome**: bytes `[c0,c1,c2,c3,c3,c2,c1,c0]`.

## Solution

The palindrome structure is the whole game. Because the keystream word is a palindrome, inside any block `ct[i] ^ ct[7-i] == pt[i] ^ pt[7-i]` — the keystream cancels. If that mirror-XOR has bit 7 set, the block cannot be all-ASCII (two ASCII bytes always XOR below `0x80`), which tells you which blocks are text and which are binary. The flag lives in the ASCII region.

Pick an ASCII block as an anchor. Each of its four mirror keystream bytes is constrained to the handful of values `k` that keep both `ct[i]^k` and `ct[7-i]^k` printable. Brute those few palindrome candidates, and for each one chain `advance` **forward** to decrypt the entire tail. The candidate that yields all-printable text containing `HTB{` is the answer. The random 8-byte key never enters the recovery — one recovered keystream word fixes everything after it.

Create `solve.py`:

```python
#!/usr/bin/env python3
import zlib, itertools
ct = open('flag.txt.enc', 'rb').read()
nb = (len(ct) + 7) // 8

def advance(x):
    crc = zlib.crc32(x.to_bytes(8, 'little')) & 0xffffffff
    mb = int.from_bytes(crc.to_bytes(8, 'little'), 'big')   # bswap64(crc)
    return (mb | crc) & 0xffffffffffffffff

def pr(v):
    return 0x20 <= v < 0x7f or v in (9, 10, 13)

A = 1                                    # block 1 is ASCII text
c = ct[A*8:A*8+8]
cn = [[k for k in range(256) if pr(c[i]^k) and pr(c[7-i]^k)] for i in range(4)]

for a, b, e, f in itertools.product(*cn):
    s = int.from_bytes(bytes([a, b, e, f, f, e, b, a]), 'little')
    ws = [s]
    for _ in range(A+1, nb):
        s = advance(s); ws.append(s)
    pt = b''.join(bytes(x ^ y for x, y in zip(ct[(A+k)*8:(A+k)*8+8], w.to_bytes(8, 'little')))
                  for k, w in enumerate(ws))
    if b'HTB{' in pt and all(pr(x) for x in pt[:150]):
        print(pt.decode('latin1')); break
```

The decrypted message is a set of rendezvous instructions ending in `... the password for the bunker door is HTB{...}`, and the flag is rendered live from that plaintext.

```
HTB{...}
```

## Why it worked

Two design mistakes stack. The packer only ever *hides* code — at some instant the real bytes exist in the binary as a zlib stream, so extracting and inflating them offline sidesteps the entire anti-debug dance. The cipher then throws away its own key strength: folding the 32-bit CRC output into a 64-bit value with `crc | bswap64(crc)` produces a palindrome, and chaining the state means a single recovered keystream word regenerates the rest. A [predictable / low-entropy keystream](https://cwe.mitre.org/data/definitions/330.html) combined with a [reversible, guessable cryptographic construction](https://cwe.mitre.org/data/definitions/327.html) lets known/guessed plaintext in one block unravel the whole message.

## Fix / defense

Don't rely on runtime code materialization for secrecy — anything the process can decompress, an analyst can decompress from the same bytes. For the cipher, use a real authenticated construction (e.g. AES-GCM) with a key derived from a proper KDF, never a CRC (CRC is an error-detecting checksum, not a PRNG), and never fold PRNG output into a structure that leaks its own bytes. Store nothing that lets one recovered keystream word regenerate the stream.
