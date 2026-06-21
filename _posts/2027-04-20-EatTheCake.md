---
title: "Eat the Cake!"
date: 2027-04-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, upx, crackme, objdump, static-analysis, wine]
description: "An Easy Reversing challenge: a UPX-packed Windows crackme validates a 15-character password one byte at a time with cmp instructions, so the password is literally spelled out by the immediate operands in the disassembly. Unpack, read the compares off objdump in stack-offset order, mind the four positions hidden inside an atoi/isdigit helper, and the on-screen prompt that lies about the charset."
---

## Overview

Eat the Cake! is an Easy HackTheBox **Reversing** challenge. You get a single Windows console
binary, `cake.exe`, that asks for a password and prints *"Congratulations! Now go validate your
flag!"* when you get it right. The whole thing is a static [client-side enforcement](https://cwe.mitre.org/data/definitions/602.html)
crackme: the expected password sits in the binary as the immediate operands of a chain of `cmp`
instructions, and the flag is just `HTB{<that password>}`.

## The technique

The validator never hashes or transforms your input — it compares it to the real password **one
byte at a time**, position by position, using `cmp BYTE PTR [esp+offset], imm`. Because the input
buffer lives at a fixed stack offset, each character's index is pinned by *which* stack slot the
compare reads, and the accepted byte is the `imm` it compares against. Read those pairs off the
disassembly, sort by offset, and you have the password — no execution, no brute force.

Two pieces of misdirection:

- The binary is **UPX-packed**, so static tools see nothing useful until you decompress it.
- The on-screen prompt insists on *"10/15-digit password (Only numbers and capital letters)"* — a
  **decoy**. The real answer contains lowercase letters and symbols.

## Solution

**1. Unpack the UPX stub.** `file` shows the binary is UPX-compressed; decompress it to restore the
real sections:

```sh
file cake.exe                       # PE32 ... UPX compressed
cp cake.exe cake_unpacked.exe
upx -d cake_unpacked.exe
```

**2. Disassemble and look at the validator.** The 15-char password is checked by a run of
positional byte compares (buffer base is stack offset `0x24`, so `index = offset - 0x24`):

```sh
objdump -D -Mintel -b pei-i386 cake_unpacked.exe > cake.asm
```

```asm
cmp BYTE PTR [esp+0x24], 0x68   ; index 0  = 'h'
cmp BYTE PTR [esp+0x25], 0x40   ; index 1  = '@'
cmp BYTE PTR [esp+0x26], 0x63   ; index 2  = 'c'
cmp BYTE PTR [esp+0x27], 0x6b   ; index 3  = 'k'
...
```

**3. Mind the four hidden positions.** Indices 4, 6, 7 and 12 aren't direct compares — they're
validated inside helper subroutine `0x4012f0` using `isdigit`/`atoi`:

```asm
cmp BYTE PTR [ebx+4], 0x74      ; index 4  = 't'
atoi(&buf[6]) == 3              ; index 6  = '3'   (buf[7] is non-digit, terminates the parse)
cmp BYTE PTR [ebx+7], 0x70      ; index 7  = 'p'
atoi(&buf[12]) == 1             ; index 12 = '1'   (buf[13] = '$' terminates the parse)
```

**4. Reassemble the password.** The `solve.py` below scrapes every direct compare from the objdump
output and hand-fills the four helper-checked indices, then emits the characters in index order:

Create `solve.py`:

```python
import re
asm = open("cake.asm").read()
BASE = 0x24
chars = {}
for m in re.finditer(r'cmp\s+BYTE PTR \[esp\+0x([0-9a-f]+)\],0x([0-9a-f]+)', asm):
    chars[int(m.group(1), 16) - BASE] = int(m.group(2), 16)
chars[4], chars[6], chars[7], chars[12] = 0x74, ord('3'), 0x70, ord('1')  # sub 0x4012f0
pw = ''.join(chr(chars[i]) for i in range(15))
print("password:", pw)
print("flag:     HTB{%s}" % pw)
```

```sh
python3 solve.py
# password: h@ckth3parad1$E
# flag:     HTB{...}
```

**5. Confirm it live.** Feed the recovered password back to the binary under Wine:

```sh
printf 'h@ckth3parad1$E\n' | wine cake_unpacked.exe   # -> "Congratulations! Now go validate your flag!"
```

The flag is `HTB{` + the password + `}` (value redacted).

## Why it worked

The secret is never derived or hashed — it ships in plaintext as the immediate operands of the
comparison instructions, with positions keyed by stack offset. Recovering it is just reading the
disassembly in the right order; UPX packing and the misleading prompt only slow you down.

## Fix / defense

Don't compare against the raw secret in the shipped client. Compare a **salted hash** of the user's
input against a stored hash so the binary never carries the answer, and remember that packing
(UPX) and confusing prompts are obfuscation, not protection — a determined reverser strips both in
seconds.
