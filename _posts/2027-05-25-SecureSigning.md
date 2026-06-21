---
title: "Secure Signing"
date: 2027-05-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, hash-oracle, prefix-oracle, sha256, xor]
description: "An Easy Crypto challenge whose 'unbreakable' signing oracle returns sha256(message XOR FLAG). Because Python's zip() truncates the XOR to the message length and XOR with zero is the identity, sending all-zero messages of growing length leaks sha256(FLAG[:n]) — letting us recover the flag one byte at a time with no key knowledge at all."
---

## Overview

Secure Signing is an Easy [Crypto](https://cwe.mitre.org/data/definitions/327.html) challenge. The service advertises a "Super Secure Signing service which uses an unbreakable hash function", combining your message with a secret key before hashing. The catch is that the "signature" is just `sha256(message XOR FLAG)`, and a quirk of how the XOR is implemented turns that signature into a tunable-length **prefix oracle** over the secret. No SHA-256 is ever reversed — we simply ask the oracle for `sha256(FLAG[:n])` for every `n` and brute one byte at a time.

## The technique

The whole challenge is the signing function:

```python
def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])   # zip stops at the SHORTER input

def H(m):
    return sha256(m).digest()

# menu option 1 ("Sign"):
hsh = H(xor(message, FLAG))      # sha256( (message XOR FLAG) truncated to len(message) )
print(f"Hash: {hsh.hex()}")
```

Two facts collapse the "you can't reverse SHA-256" assumption:

1. **`zip(a, b)` truncates to the shorter operand.** A message of length `n` makes the XOR — and therefore the hash — cover only the first `n` bytes: `sha256((message XOR FLAG)[:n])`. We fully control `n`.
2. **XOR with a zero byte is the identity.** Send `message = b"\x00" * n` and the hashed value becomes exactly `FLAG[:n]`. The secret key never enters the computation — the oracle hands us `sha256(FLAG[:n])` directly.

A keyed hash like this is **not** a MAC: it has no per-message binding and leaks a prefix hash for every chosen length.

## Solution

This is a classic byte-at-a-time prefix oracle. Knowing `FLAG[:n-1]`, recover `FLAG[n-1]`:

- Ask the oracle for `sha256(FLAG[:n])` by signing `b"\x00" * n`.
- Locally brute the 256 possible last bytes — the `c` where `sha256(FLAG[:n-1] + bytes([c]))` equals the leaked hash is `FLAG[n-1]`.

Each byte costs one network query plus at most 256 local SHA-256s. Stop at the closing brace.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from hashlib import sha256
from pwn import remote, context

context.log_level = "error"

def sign(io, msg):
    io.recvuntil(b"> "); io.sendline(b"1")
    io.recvuntil(b"Enter your message: "); io.sendline(msg)
    io.recvuntil(b"Hash: ")
    return bytes.fromhex(io.recvline().strip().decode())

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    io = remote(host, port)
    flag = b""
    while not flag.endswith(b"}"):
        n = len(flag) + 1
        target = sign(io, b"\x00" * n)              # == sha256(FLAG[:n])
        for c in range(256):
            if sha256(flag + bytes([c])).digest() == target:
                flag += bytes([c]); break
        else:
            break                                    # zip truncated => flag complete
        print(f"[{n:2}] {flag!r}")
    print("FLAG:", flag.decode())
    io.close()

if __name__ == "__main__":
    main()
```

Running it recovers the flag one character per line:

```
$ python3 solve.py <host> <port>
[ 1] b'H'
[ 2] b'HT'
[ 3] b'HTB'
[ 4] b'HTB{'
...
FLAG: HTB{...}
```

## Why it worked

`sha256(message XOR key)` is not a message authentication code — it is a length-revealing, chosen-plaintext oracle. The `zip()` truncation turned "hash my whole message" into a knob that selects how many bytes of the secret get hashed, and choosing an all-zero plaintext cancelled the secret entirely. Recovering the flag then reduced to "brute one unknown byte against a known prefix", which is trivial for a fast hash like SHA-256.

## Fix / defense

- Use a real MAC: `HMAC(key, message)`, where the key is the HMAC key — never XOR'd into or concatenated with attacker-controlled data.
- Never expose a "signature" oracle that signs attacker-chosen, variable-length input against a secret combined by a reversible or length-revealing operation.
- If secret-derived data must be hashed, include a fixed-length domain separator or length prefix so prefixes of the secret can never be independently hashed.
