---
layout: post
title: "SatelliteHijack"
date: 2028-03-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, ifunc, memfrob, self-modifying-code, backdoor, xor]
description: "A stripped shared library hides its real logic behind a GNU IFUNC resolver that decrypts its own code at runtime with memfrob (XOR 42). Reproduce the decryption straight from the file, read the flag-checker, and invert its per-index XOR — no debugging, no running the backdoor."
---

## Overview

SatelliteHijack is a Medium reversing challenge. You get two files: `satellite`, an
ordinary-looking PIE, and `library.so`, a stripped shared object. Run `satellite` and it
just reads a line, echoes it, and "sends a satellite message" — there is no visible check
anywhere. The whole puzzle is three nested layers of concealment inside the library, which
is exactly what the flag teases: *layers on layers on more layers.*

## The technique

`main` never validates anything — it calls `send_satellite_message(0, input)`, and that
symbol lives in `library.so`. Three layers hide the real check:

1. **A GNU IFUNC resolver.** `send_satellite_message` isn't a normal function — it's an
   [IFUNC](https://cwe.mitre.org/data/definitions/506.html), a symbol whose address is
   chosen at load time by a small resolver the dynamic linker runs *before* `main`
   (`nm -D library.so` shows it with type `i`). The resolver builds a 20-byte stack string,
   subtracts 1 from each byte to get `SAT_PROD_ENVIRONMENT`, and `getenv()`s it. If that
   variable is set it installs a **backdoor**; otherwise a harmless message buffer.

2. **Self-decrypting code.** The installer does classic runtime patching: `mmap` an RWX
   page, `memcpy` an *encrypted* code blob out of the library's own `.text`
   (`0x1195..0x2195`), then `memfrob` it. `memfrob(3)` is glibc's toy "obfuscator" — it XORs
   every byte with `0x2A` (42). One XOR reveals the real flag-checker, which is then
   installed as `send_satellite_message`.

3. **A reversible check.** The decrypted checker looks for the `HTB{` dword (`0x7b425448`),
   then validates the 33 body bytes against a hardcoded stack key with
   `input[i] XOR key[i] == i`. That's trivially invertible: **`flag[i] = key[i] ^ i`**.

Because the executable segment loads at file-offset == virtual-address, you can slice the
`.so` on disk directly instead of running anything.

## Solution

Recognize the pattern, reproduce the `memfrob` decryption on the file bytes, pull the key
immediates out of the decrypted blob, and invert the check:

```python
#!/usr/bin/env python3
import sys

LIB = sys.argv[1] if len(sys.argv) > 1 else "library.so"
data = open(LIB, "rb").read()

# reproduce the installer's memfrob (XOR 42) over the checker blob (vaddr == file offset)
BLOB_LO, BLOB_HI = 0x1195, 0x2195
dec = bytes((b ^ 42) & 0xFF for b in data[BLOB_LO:BLOB_HI])
off = lambda v: v - BLOB_LO

# the 33 key bytes are the little-endian movabs/mov immediates loaded onto the stack;
# they sit contiguously and are read as key[0..32] by the checker
key = (dec[off(0x1223):off(0x1223) + 8] + dec[off(0x122d):off(0x122d) + 8] +
       dec[off(0x1241):off(0x1241) + 8] + dec[off(0x124b):off(0x124b) + 8] +
       dec[off(0x1262):off(0x1262) + 1])

assert dec[off(0x11e0):off(0x11e0) + 4] == b"HTB{"      # magic sanity check

# the check is input[i] ^ key[i] == i, so flag[i] = key[i] ^ i
flag = "HTB{" + bytes((key[i] ^ i) & 0xFF for i in range(len(key))).decode()
print(flag)     # HTB{...}
```

Running it against the provided `library.so` prints the flag, `HTB{...}` (redacted here).
To confirm the decryption is right, dump and disassemble the blob yourself:

```bash
nm -D library.so | grep ' i '
python3 -c "d=open('library.so','rb').read();open('dec.bin','wb').write(bytes((x^42)&0xff for x in d[0x1195:0x2195]))"
objdump -D -b binary -m i386:x86-64 -M intel --adjust-vma=0x1195 dec.bin
```

## Why it worked

Every layer is defensively hollow. IFUNC resolvers run before `main`, so a resolver that
inspects `getenv()` and swaps in a second implementation is invisible to anyone who only
reads `main` or the normal export. `memfrob` is a single-byte XOR, so "encrypting" the
backdoor with it protects nothing once you notice the `mmap`+`memcpy`+`memfrob` sequence.
And the final check embeds the flag *in the key* — `input[i]^key[i]==i` means the only
accepted input is `key[i]^i`, recoverable with zero brute force.

## Fix / defense

- Treat an IFUNC resolver that calls `getenv`/`getauxval` and branches into a freshly
  `mmap`'d RWX page as a backdoor indicator in code review and supply-chain scanning.
- Enforce W^X and sign shared objects; ship no writable-executable mappings and no
  `memcpy`-from-own-`.text` + `memfrob` decryption stubs.
- `memfrob` / single-byte-XOR "encryption" provides no confidentiality — never rely on it,
  and never ship de-obfuscation code beside the ciphertext it "protects."
