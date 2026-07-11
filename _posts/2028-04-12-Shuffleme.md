---
layout: post
title: "Shuffleme"
date: 2028-04-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, obfuscation, got-shuffling, aes, pyelftools, static-analysis, cwe-656]
description: "A Hard reversing crackme wraps a simple AES enc-compare check in GOT-shuffling obfuscation that only lies to the decompiler. The symbol table is intact, so you read the real logic by name, pull the baked key and ciphertext out of two named symbols, and decrypt the flag offline without ever running the binary."
---

## Overview

Shuffleme is a Hard HackTheBox Reversing challenge. The binary "validates" your input by AES-256-CBC encrypting it and comparing the result to a ciphertext baked into the file — so the correct input is simply the decryption of that ciphertext. The only real obstacle is a layer of [obfuscation through GOT shuffling](https://cwe.mitre.org/data/definitions/656.html) that mislabels the imported functions in any decompiler. Because the binary is not stripped, you read the true logic by symbol name, extract the key and ciphertext from two named symbols, and decrypt the flag statically.

## The technique

The binary uses **GOT/PLT shuffling**: its `.rela.plt` relocation table is tampered so a decompiler assigns the wrong names to imported functions. A call that appears to be `EVP_CIPHER_CTX_free@plt` is really a different function. On top of that, `main` re-executes itself once with the environment variable `LD_BIND_NOT=1` set — it reads the variable with `getenv`, and if it is missing, calls `setenv` then `execv` on its own path — forcing the dynamic loader to resolve every import eagerly so the shuffled table works at runtime.

None of this changes what the code computes. The binary is **not stripped**, so its symbol table still holds the real names (`go`, `extract_blob`, `get_byte`, `key_blob`, `data_blob`). Reading the disassembly by symbol name and ignoring the bogus PLT labels defeats the obfuscation for free.

The real logic lives in `go(argv[1])`:

```
extract_blob(key_blob,  0x20, keybuf)   ; 32-byte AES-256 key
extract_blob(data_blob, 0x50, ctbuf)    ; 80-byte ciphertext
AES-256-CBC, IV = 16 zero bytes
compare AES_encrypt(input) to ctbuf
```

`extract_blob` looks complex — opaque predicates and a `get_byte` helper that reads `/dev/urandom` — but its net effect is a single line: `out[i] = blob[i*4]`. The tell is the source index being scaled by four (`shl eax, 2`): the real bytes are stored spread out, every fourth byte. `get_byte` is a decoy that never influences the output.

## Solution

Read the raw bytes of the two named symbols with pyelftools, take every fourth byte to rebuild the 32-byte key and 80-byte ciphertext, and decrypt with a zero IV. The binary is never executed.

Create `solve.py`:

```python
import sys
from elftools.elf.elffile import ELFFile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BIN = sys.argv[1] if len(sys.argv) > 1 else "shuffleme"

def sym_bytes(elf, name, n):
    sym = elf.get_section_by_name(".symtab").get_symbol_by_name(name)[0]
    vaddr = sym["st_value"]
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD":
            start = seg["p_vaddr"]
            if start <= vaddr < start + seg["p_filesz"]:
                elf.stream.seek(seg["p_offset"] + (vaddr - start))
                return elf.stream.read(n)
    raise RuntimeError("symbol not in a loadable segment")

with open(BIN, "rb") as f:
    elf = ELFFile(f)
    key = sym_bytes(elf, "key_blob",  0x20 * 4)[::4][:32]
    ct  = sym_bytes(elf, "data_blob", 0x50 * 4)[::4][:80]

pt = AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(ct)
print(unpad(pt, 16).decode())
```

Run it against the shipped binary and the flag drops out:

```bash
python3 solve.py shuffleme
# HTB{...}
```

## Why it worked

Obfuscation that only fools static analysis is inert. Shuffled GOT entries, mangled relocations, and an `LD_BIND_NOT` self-re-exec all exist to break a decompiler's naming — they do not change the computation. Reading the intact symbol table sidesteps every one of them. And a checker that AES-encrypts your input to compare against a stored ciphertext is a decrypt problem, not a brute-force one: when the binary ships both the key and the expected ciphertext, the correct input *is* the plaintext.

## Fix / defense

Obfuscation is not a secret-storage mechanism. Anything embedded in an offline binary — including the material needed to recover a secret — is recoverable; treat client-side binaries as fully readable by the attacker. Don't ship the key and the expected ciphertext together. Validate input against a keyed hash or a server-side check instead of a local symmetric encrypt-and-compare, and strip symbols so at least the free win of named functions is gone.
