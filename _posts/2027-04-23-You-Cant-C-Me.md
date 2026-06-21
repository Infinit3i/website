---
title: "You Cant C Me"
date: 2027-04-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, security-through-obscurity, radare2, decoy-string, rodata]
description: "An Easy Reversing challenge built on security-through-obscurity: a stripped ELF hides its password as an obfuscated .rodata blob, decrypts it at runtime with a trivially reversible byte-shift over a strings-visible decoy, then prints HTB{<your input>} on a match — so recovering the secret and feeding it back makes the binary print its own flag."
---

## Overview

**You Cant C Me** is an Easy Reversing challenge: a single stripped x86-64 ELF, `auth`, that taunts you no matter what you type. Its "password" is hidden as an obfuscated constant in `.rodata` and de-obfuscated at runtime with a trivially reversible per-byte transform — a textbook case of [reliance on security through obscurity](https://cwe.mitre.org/data/definitions/656.html). Read the transform out of the disassembly, invert it over the `.rodata` bytes, and the binary prints the flag itself.

## The technique

Run it and it just refuses you:

```bash
$ ./auth
Welcome!
I said, you can't c me!
```

`strings` is already loud — and that loudness is the trap:

```bash
$ strings auth | grep -iE 'HTB|password'
HTB{%s}
this_is_the_password
```

Two tells: a flag **template** `HTB{%s}` (note: *no literal flag string* — the "you can't *c* me" joke) and a password `this_is_the_password`. The password is a **decoy**: it's copied onto the stack and then immediately overwritten by the real decrypt loop. The accept path does `printf("HTB{%s}\n", your_input)`, so the only way to print the flag is to satisfy the comparison — which means **the password equals the flag body**.

## Solution

Disassembling `main` in radare2 (`r2 -A auth`, then `s main; pdf`) reveals the whole logic. The system `objdump` may lack a target arch on some binaries, so radare2's `-A` analysis is the reliable read:

```text
; copy decoy "this_is_the_password" onto the stack at rbp-0x20  (about to be clobbered)
mov rdx, [0x402030]            ; "this_is_"
mov [rbp-0x20], rdx
...

; 20-byte obfuscated blob copied from .rodata 0x402050 to rbp-0x40
mov rax, [0x402050]            ; "m^&&fi\x17U..."
mov [rbp-0x40], rax
...

; decrypt loop: for i in 0..19  ->  out[i] = enc[i] + 0x0a, written OVER the decoy
loop:
  cmp dword [rbp-0x8], 0x14         ; i < 20
  jge done
  movsx ecx, byte [rbp+rax-0x40]    ; enc[i]
  add   ecx, 0xa                    ; + 10   <-- the reversible transform
  mov   byte [rbp+rax-0x20], cl     ; overwrite decoy buffer
  ...

done:
  fgets(input, 0x15, stdin)
  if strcmp(decrypted, input) == 0:
      printf("HTB{%s}\n", input)    ; prints the flag = whatever you typed
  else:
      printf("I said, you can't c me!\n")
```

So the secret is the 20 `.rodata` bytes at `0x402050`, each shifted `+0x0a`. The binary is No-PIE, so the virtual address maps straight to a file offset (`0x402050 - 0x400000 = 0x2050`). The `solve.py` slices those bytes, applies the inverse, then **pipes the result back into the binary** so the flag is derived live, never hardcoded:

Create `solve.py`:

```python
#!/usr/bin/env python3
import subprocess
BIN = "files/auth"

# 20 obfuscated bytes live at vaddr 0x402050 -> file offset 0x2050 (No-PIE, 1:1 mapped)
data = open(BIN, "rb").read()
enc = data[0x2050:0x2050 + 20]

# decrypt: the loop does `add ecx, 0xa`  ->  password[i] = enc[i] + 10
password = bytes((b + 0x0a) & 0xff for b in enc).decode()
print("[*] password :", password)

# feed it back so the BINARY prints the flag (live derivation, never hardcode)
out = subprocess.run([f"./{BIN}"], input=(password + "\n").encode(),
                     capture_output=True).stdout.decode()
print(out.strip())
```

```bash
$ python3 solve.py
[*] password : wh00ps!_y0u_d1d_c_m3
Welcome!
HTB{...}
```

## Why it worked

The de-obfuscation routine ships inside the binary, so the obscurity *is* the only barrier — reading the `add ecx, 0xa` and the source pointer is enough to invert it offline. The `strings`-visible decoy burns analyst time but adds no security, and because the success path echoes your own input through `printf("HTB{%s}")`, satisfying the `strcmp` and printing the flag are the same action.

## Fix / defense

- Never derive an access decision from a reversible constant baked into a client binary — anything shipped to the user is recoverable. Authenticate server-side against a salted hash.
- If a local check is unavoidable, compare a salted hash of the input (`argon2`/`bcrypt`) against a stored hash, never the plaintext — and never echo the accepted secret back into output.
- Reversible obfuscation (add/xor/sub over a constant blob) is not encryption, and decoy strings don't impede an analyst who reads the de-obfuscation loop.
