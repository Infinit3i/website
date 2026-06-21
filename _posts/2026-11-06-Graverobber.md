---
title: "Graverobber"
date: 2026-11-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, static-analysis, data-section, syscalls]
description: "A Very Easy Reversing challenge where the flag is stored as a table of integers in the binary's data section and 'validated' with stat() instead of strcmp — read the table, never run the check."
---

## Overview

Graverobber is a Very Easy HackTheBox **Reversing** challenge. You get a single x86-64 ELF (`robber`) that prints either `We took a wrong turning!` or `We found the treasure!`. There is no password prompt and no obvious string comparison — the flag is hidden in plain sight inside the binary's data section and is "checked" by an unusual filesystem trick. The whole solve is static: read the data table, don't run the check.

## The technique

The binary never compares your input against the flag. Instead, the flag is stored as a table of 32 little-endian 4-byte integers in the `.data` section (a global array named `parts`). Each integer's **low byte** is one flag character; the upper three bytes are zero. `main()` walks that table and, for each entry, builds a filesystem path one character per directory — `c0/c1/c2/.../c31/` — then calls [`stat()`](https://cwe.mitre.org/data/definitions/367.html) on it. If every directory level exists, you "found the treasure"; if any level is missing, you "took a wrong turning."

In other words, the flag is simultaneously the embedded data **and** the validation key: the program only succeeds if a directory tree named after the flag characters already exists on disk. So we don't need to run or satisfy the check at all — the flag bytes are sitting in the data table.

## Solution

Confirm it's a non-stripped x86-64 ELF and that `strings` gives nothing useful:

```bash
file robber
strings -n 6 robber    # only "We found the treasure!" — no flag
```

Disassemble `main`. The loop reads the global `parts` array as 4-byte DWORDs and uses only the low byte (`dl`) of each, writing it into a stack buffer interleaved with `/` (0x2f), then calls `stat`:

```text
lea    rax,[rip+0x2e63]   # parts
mov    edx,DWORD PTR [rdx+rax*1]   # parts[i] as a DWORD
mov    BYTE PTR [rbp+rax-0x50],dl  # store LOW byte -> flag char
mov    BYTE PTR [rbp+rax-0x50],0x2f # store '/'
call   stat@plt
```

Dump the data table and read the low byte of every DWORD:

```bash
objdump -s -j .data robber   # parts @ 0x4040: 48 00 00 00 54 00 00 00 42 00 00 00 ... -> H T B ...
```

Because each character is stored as `printable-byte + \x00\x00\x00`, the table is byte-for-byte identical to a UTF-32LE string — so a one-line extractor recovers it directly. The script below parses the 32 DWORDs out of the ELF, takes each low byte, strips the trailing null padding entry, and **proves** the flag by building the exact directory tree the binary `stat()`s and running it:

Create `solve.py`:

```python
#!/usr/bin/env python3
import struct, subprocess, os, sys
from pathlib import Path

BIN = Path(__file__).parent / "robber"
N = 32   # 32 DWORD entries (128 bytes) in the `parts` array

def read_parts():
    data = BIN.read_bytes()
    off = data.find(b"\x48\x00\x00\x00\x54\x00\x00\x00\x42\x00\x00\x00")  # 'H','T','B'
    dwords = struct.unpack_from("<%dI" % N, data, off)
    return bytes(d & 0xFF for d in dwords).rstrip(b"\x00")  # last DWORD is null padding

flag = read_parts().decode()
print(flag)

if "--verify" in sys.argv:
    root = Path("/tmp/graverobber_proof")
    subprocess.run(["rm", "-rf", str(root)])
    root.joinpath(*list(flag)).mkdir(parents=True)   # one dir per flag char
    os.chmod(BIN, 0o755)
    out = subprocess.run([str(BIN.resolve())], cwd=root,
                         capture_output=True, text=True).stdout.strip()
    print("[binary]", out)
```

Run it:

```bash
python3 solve.py --verify
# HTB{...}
# [binary] We found the treasure! (I hope it's not cursed)
```

The binary itself confirms the recovered flag is correct.

## Why it worked

The "encryption" was pure misdirection. The flag bytes are stored in cleartext inside the binary — only lightly obscured by spreading one character per 4-byte slot and by replacing the obvious `strcmp(input, flag)` with a `stat()` on a path built *from* the flag. A `strings` sweep or a search for a comparison function finds nothing, but the data table is right there for anyone who dumps `.data`. This is [cleartext storage of sensitive information](https://cwe.mitre.org/data/definitions/312.html): a secret embedded in a shipped artifact is recoverable regardless of how cleverly the program consumes it.

## Fix / defense

Never embed a secret in a binary and treat the binary as the guard — anything shipped to the client can be extracted statically. If a value must be verified client-side, compare a salted hash of the user's input rather than storing the secret itself, and keep the real secret server-side behind an authenticated check. For CTF-style integrity checks, the lesson generalizes: obfuscating *how* a secret is used does not protect the secret if the bytes still live in the file.
