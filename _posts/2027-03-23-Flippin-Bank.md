---
title: "Flippin Bank"
date: 2027-03-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes, cbc, bit-flipping, malleable-ciphertext, auth-bypass, cwe-353, cwe-326]
description: "An Easy Crypto challenge: the server hands you the ciphertext of a known plaintext, encrypts in AES-CBC with no integrity check, then trusts whatever your ciphertext decrypts to. A textbook bit-flipping attack repairs a near-miss string into the magic admin token — no key required."
---

## Overview

`Flippin Bank` is an Easy HackTheBox **Crypto** challenge. A TCP service builds an
authentication string from your username and password, encrypts it with **AES-CBC** under a
fixed key/IV, and hands you back the ciphertext. When you resubmit a ciphertext, it decrypts it
and grants the flag if the result contains the magic string `admin&password=g0ld3n_b0y`. CBC is
malleable and the service never checks ciphertext integrity, so a one-block
[bit-flipping attack](https://cwe.mitre.org/data/definitions/353.html) forges that string without
ever knowing the key.

## The technique

CBC decryption is `P[i] = D(C[i]) ⊕ C[i-1]`. That means the previous ciphertext block is XOR-mixed
directly into the current plaintext block. If an attacker who controls the ciphertext flips a bit
in `C[i-1]`, the *exact same bit* flips in `P[i]` — block `i-1`'s own plaintext is destroyed, but
block `i` is mutated with surgical precision. No key is needed; this is pure
[missing-integrity malleability](https://cwe.mitre.org/data/definitions/353.html) (the encryption
also relies on a fixed IV, [CWE-326](https://cwe.mitre.org/data/definitions/326.html)).

The server's source shows the gate and the gotcha:

```python
msg = 'logged_username=' + user + '&password=' + passwd     # we control user + passwd
assert 'admin&password=g0ld3n_b0y' not in msg               # blocks the literal pre-encryption
ct = AES-CBC(key, iv, pad(msg))                             # fixed key+iv, ct leaked to us
# on resubmit: if 'admin&password=g0ld3n_b0y' in decrypt(our_ct): print FLAG
```

The `assert` inspects the *original* plaintext, so we can't send the magic string directly. But it
never re-validates the ciphertext we resubmit — so we smuggle a near-miss past the assert and then
bit-flip it into shape.

## Solution

`logged_username=` is exactly **16 bytes**, so it owns block 0 cleanly and our `user` starts at
block 1. We pick a username that begins with a 16-byte sacrificial block, followed by `aaaaa`:

```text
user   = b"A"*16 + b"aaaaa"     # 16 sacrificial + 5 bytes to flip
passwd = b"g0ld3n_b0y"
blk0 [ 0..15] logged_username=
blk1 [16..31] AAAAAAAAAAAAAAAA   <- corrupt THIS block's ciphertext (its plaintext is throwaway)
blk2 [32..47] aaaaa&password=g   <- flipping blk1's ct flips blk2's pt: aaaaa -> admin
blk3 [48.. ] 0ld3n_b0y + pad
```

The pre-encryption string is `...aaaaa&password=g0ld3n_b0y`, which does **not** contain
`admin&...`, so the assertion passes. We then XOR `'a' ^ 'admin'[i]` into ciphertext bytes 16–20,
turning block 2's leading `aaaaa` into `admin`. Block 3 is untouched, so padding stays valid and
the decrypted text now contains the full `admin&password=g0ld3n_b0y`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, socket, re
from binascii import unhexlify, hexlify

USER   = b"A" * 16 + b"aaaaa"     # 16 sacrificial + 5 to flip
PASSWD = b"g0ld3n_b0y"
HAVE   = b"aaaaa"                 # current bytes at plaintext pos 32..36
WANT   = b"admin"                 # desired bytes there

def recv_until(s, marker, timeout=10):
    s.settimeout(timeout); buf = b""
    while marker not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    return buf

def forge(ct_hex):
    ct = bytearray(unhexlify(ct_hex))
    # blk1 ciphertext is bytes 16..31; flipping byte (16+i) flips plaintext byte (32+i) of blk2
    for i in range(len(WANT)):
        ct[16 + i] ^= HAVE[i] ^ WANT[i]
    return hexlify(bytes(ct))

def solve(host, port):
    s = socket.create_connection((host, port), timeout=10)
    recv_until(s, b"username: ");        s.sendall(USER + b"\n")
    recv_until(s, b"password: ");        s.sendall(PASSWD + b"\n")
    data = recv_until(s, b"enter ciphertext: ")
    ct_hex = re.search(rb"Leaked ciphertext:\s*([0-9a-fA-F]+)", data).group(1)
    s.sendall(forge(ct_hex) + b"\n")
    print(s.recv(8192).decode(errors="replace"))
    s.close()

if __name__ == "__main__":
    solve(sys.argv[1], int(sys.argv[2]))
```

Run it against the live instance:

```bash
python3 solve.py <target-ip> <target-port>
```

The service responds `Logged in successfully!` followed by the flag `HTB{...}`.

## Why it worked

AES-CBC provides confidentiality but **no integrity or authentication**. A single-byte edit to a
ciphertext block is a controlled single-byte edit to the *next* plaintext block. The application
treated decrypted plaintext as if it were authentic and trustworthy, so a key-less attacker could
rewrite the authorization-bearing field at will.

## Fix / defense

- Use an **authenticated** cipher mode such as AES-GCM, or apply **encrypt-then-MAC** (HMAC over
  IV + ciphertext) and reject on MAC mismatch *before* decrypting or parsing.
- Never make an authorization decision from attacker-malleable ciphertext.
- Don't reuse a fixed IV, and don't place trust-bearing fields (like `admin`) in plaintext that
  sits adjacent to attacker-controlled data.
