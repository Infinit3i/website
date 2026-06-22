---
layout: post
title: "HTB Challenge: Sekure Decrypt"
date: 2027-07-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, core-dump, aes, heap-forensics, pycryptodome, cwe-226]
---

## Overview

**Sekure Decrypt** is an Easy HTB Reversing challenge. You're given a C binary (`dec`) that uses `mcrypt` (AES-128-CBC) to decrypt a 16-byte `flag.enc` file and print the result — but the binary crashes before it ever prints anything. A `fclose(&fp)` typo passes `FILE**` instead of `FILE*`, triggering `abort()` inside glibc's stream cleanup. The provided `core` dump preserves everything needed: the `$KEY` environment variable survives verbatim in the process's env block (recoverable with `strings`), and the 16-byte ciphertext lives in a malloc'd heap chunk that survives the crash intact. One parse of the ELF core segments, one AES-CBC call, and the flag is out.

---

## The Technique

### The bug — `fclose(&fp)` instead of `fclose(fp)`

The provided `src.c` is the full source. The crash is in `read_file()`:

```c
void* read_file(char* filename, int len) {
  FILE *fp = fopen(filename, "rb");
  void* data = malloc(len);
  fread(data, 1, len, fp);
  fclose(&fp);   // BUG: passes FILE** (address of local ptr) instead of FILE*
  return data;   // never reached
}
```

`fclose(&fp)` hands glibc the address of the *pointer variable* `fp` on the stack, not the `FILE*` it points to. glibc reads what it thinks is a `FILE` struct starting at that address, which is actually the pointer value itself, trashing stream fields and triggering heap-corruption detection → `SIGABRT`. This is [CWE-664](https://cwe.mitre.org/data/definitions/664.html) (improper control of resource lifetime) combined with undefined behaviour from a type mismatch.

The sequence in `main()` means `fread` already ran successfully before the crash:

```c
void *ciphertext = read_file("flag.enc", 16);  // crash inside here
decrypt(ciphertext, 16, IV, key, 16);          // never reached
printf("Decrypted contents: %s\n", ciphertext); // never reached
```

So the ciphertext is in the heap, and the key is in the environment — both frozen into the core dump.

### Step 1 — Recover the key from the environment block

Linux core dumps preserve the full process environment. A single `strings` call extracts it:

```bash
strings core | grep 'KEY='
# KEY=VXISlqY>Ve6D<{#F
```

This is [CWE-226](https://cwe.mitre.org/data/definitions/226.html): sensitive information in a core dump. The `$KEY` env var is passed in cleartext, lives in the process's address space, and lands verbatim in the dump.

### Step 2 — Extract the ciphertext from the heap

The 16-byte `flag.enc` buffer was allocated with `malloc(16)`. In glibc on x86-64, a 16-byte user request produces a chunk with a `size` field of `0x21` (32 bytes total: 16 header + 16 data, with the `PREV_INUSE` bit set). By parsing the ELF core's `PT_LOAD` segments and scanning the heap for a `size=0x21` chunk, we find the ciphertext at heap offset `+0x490`:

```python
import struct

with open('core', 'rb') as f:
    data = f.read()

e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum     = struct.unpack_from('<H', data, 0x38)[0]

for i in range(e_phnum):
    off    = e_phoff + i * e_phentsize
    p_type = struct.unpack_from('<I', data, off)[0]
    p_vaddr  = struct.unpack_from('<Q', data, off+0x10)[0]
    p_offset = struct.unpack_from('<Q', data, off+8)[0]
    p_filesz = struct.unpack_from('<Q', data, off+0x20)[0]

    # PT_LOAD heap segment: writable, in 0x562e...  range
    if p_type == 1 and 0x5620000000000 <= p_vaddr < 0x5630000000000:
        seg = data[p_offset : p_offset + p_filesz]
        for j in range(0, len(seg) - 24, 8):
            if struct.unpack_from('<Q', seg, j)[0] == 0x21:   # size=0x21 → 16B alloc
                ct = seg[j+8 : j+24]
                print(f"ciphertext @ +0x{j:x}:", ct.hex())
                break
```

This yields the 16-byte ciphertext: `3226 08db ef90 0b1e bcd3 a058 7191 4883`.

### Step 3 — AES-128-CBC decryption

The IV is hardcoded in `src.c` as `"AAAAAAAAAAAAAAAA"` (sixteen `A` characters, ASCII `0x41`):

```c
char* IV = "AAAAAAAAAAAAAAAA";
```

Decrypt with `pycryptodome`:

```python
from Crypto.Cipher import AES

KEY = b'VXISlqY>Ve6D<{#F'
IV  = b'AAAAAAAAAAAAAAAA'
CT  = bytes.fromhex('3226 08db ef90 0b1e bcd3 a058 7191 4883'.replace(' ',''))

cipher = AES.new(KEY, AES.MODE_CBC, IV)
print(cipher.decrypt(CT).decode())
```

---

## Solution

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

KEY = b'VXISlqY>Ve6D<{#F'
IV  = b'AAAAAAAAAAAAAAAA'
CT  = bytes.fromhex('322608dbef900b1ebcd3a058719148 83'.replace(' ',''))

cipher = AES.new(KEY, AES.MODE_CBC, IV)
flag = cipher.decrypt(CT)
print(flag.decode())
```

Flag: `HTB{...}`

---

## Why It Worked

Two independent bugs combined: a type-confusion crash ([CWE-664](https://cwe.mitre.org/data/definitions/664.html)) let the program die before printing its own output, and [CWE-226](https://cwe.mitre.org/data/definitions/226.html) (sensitive information in core dump) meant the key and ciphertext both survived the crash. The decryption key, passed via `$KEY`, is stored verbatim in the process's environment block — a region that Linux always includes in core dumps. The ciphertext, heap-allocated before the crash, lands in a standard glibc malloc chunk whose layout is fully documented: a `size=0x21` field followed immediately by 16 bytes of user data. With both pieces recovered offline, the AES-128-CBC call is a one-liner.

---

## Fix / Defense

**Fix the immediate bug:**

```c
fclose(fp);   // not fclose(&fp)
```

**Prevent key exposure in core dumps:**

```c
#include <sys/prctl.h>
prctl(PR_SET_DUMPABLE, 0);   // disable core dumps for this process
```

Or at the shell level:

```bash
ulimit -c 0
```

**Zero key material immediately after use:**

```c
explicit_bzero(key, key_len);
```

**Prefer the kernel keyring over environment variables** for secrets — env vars are world-readable to any process running as the same UID and survive into core dumps. `keyctl` or `libsecret` keep the secret outside the normal address space.
