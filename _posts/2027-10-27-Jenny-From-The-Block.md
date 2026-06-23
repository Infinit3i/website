---
layout: post
title: "HackTheBox: Jenny From The Block"
date: 2027-10-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, known-plaintext, block-cipher, broken-crypto, cwe-327]
---

Jenny From The Block is an Easy **Crypto** challenge: a TCP "debug terminal" runs a small allowlist of commands and returns the output encrypted with a hand-rolled block cipher. The twist is that the cipher reseeds its key on every block to *look* unpredictable — but it seeds on the plaintext, so a single known-plaintext block unwinds the entire ciphertext and leaks the flag in one response.

## Overview

You connect to the service, send one of `whoami`, `ls`, `cat secret.txt`, `pwd`, and get back a hex blob. The flag lives in `secret.txt`, so the goal is to decrypt the response to `cat secret.txt`. No key is ever sent to the client, and the first block's key is genuinely random — yet the design is fully broken because of how the per-block key is derived.

## The technique

The cipher works in 32-byte blocks. Each output byte is just the plaintext byte plus a key byte, and after each block the key is replaced by a hash of the ciphertext and plaintext just processed:

```python
BLOCK_SIZE = 32
def encrypt_block(block, secret):
    return bytes([(block[i] + secret[i]) % 256 for i in range(BLOCK_SIZE)])

def encrypt(msg, password):
    h = sha256(password).digest()              # password = os.urandom(32) — unknown
    ct = b''
    for block in [msg[i:i+32] for i in range(0, len(msg), 32)]:
        enc_block = encrypt_block(block, h)
        h = sha256(enc_block + block).digest() # next key chains on enc + PLAINTEXT
        ct += enc_block
    return ct.hex()
```

The plaintext is always `b"Command executed: " + command + b"\n" + output`. Two facts break it completely:

1. **Block 0 is fully known plaintext.** `"Command executed: "` is 18 bytes and `"cat secret.txt"` is 14 bytes, so `"Command executed: cat secret.txt"` is *exactly* 32 bytes — block 0 is entirely predictable.
2. **The next block's key is `sha256(enc_block + plaintext_block)`** — both of which you have once block *i* is known (the ciphertext is what you received; the plaintext you just recovered).

So the random first key `h0` is never needed. From block 0's known plaintext, compute `h1 = sha256(enc0 + pt0)`, subtract it from block 1's ciphertext (mod 256) to recover block 1, then chain forward to the end. A [broken cryptographic algorithm](https://cwe.mitre.org/data/definitions/327.html) ([CWE-327](https://cwe.mitre.org/data/definitions/327.html)): one captured response leaks everything.

## Solution

`solve.py` connects once, sends `cat secret.txt`, reads the hex ciphertext, and unwinds the chain offline:

```python
import sys, socket
from hashlib import sha256

HOST, PORT = sys.argv[1], int(sys.argv[2])
BLOCK = 32
KNOWN0 = b"Command executed: cat secret.txt"   # exactly 32 known bytes

def recvuntil(s, tok, timeout=10):
    s.settimeout(timeout)
    buf = b""
    while tok not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf

s = socket.create_connection((HOST, PORT))
recvuntil(s, b"> ")                              # banner + first prompt
s.sendall(b"cat secret.txt\n")
data = recvuntil(s, b"\n> ", timeout=10)

hexline = data.split(b"\n> ")[0].strip()
hexline = bytes(c for c in hexline if c in b"0123456789abcdefABCDEF")
ct = bytes.fromhex(hexline.decode())
blocks = [ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK)]

pt = bytearray(KNOWN0)
h = sha256(blocks[0] + KNOWN0).digest()          # key for block 1, from known data
for enc in blocks[1:]:
    blk = bytes((enc[i] - h[i]) % 256 for i in range(BLOCK))
    pt += blk
    h = sha256(enc + blk).digest()               # chain forward
print(pt.decode("latin1"))                        # contains HTB{...}
```

Run it against a spawned instance:

```bash
python3 solve.py <target-ip> <target-port>
```

The decrypted response contains the flag (`HTB{...}`, redacted here).

## Why it worked

An additive per-byte cipher is trivially invertible the moment you know the keystream. The author tried to make the keystream unpredictable by reseeding it each block with `sha256` — but seeded it on the *message*, which for a fixed-structure response is itself known. Generalising: any feedback cipher whose next-block key is derived from plaintext (or any attacker-recoverable data) is a known-plaintext break, no matter how random the initial seed.

## Fix / defense

- Use a real authenticated cipher (AES-GCM, ChaCha20-Poly1305) with a key the client never learns and a fresh nonce per message.
- Never derive subsequent key material from attacker-knowable plaintext. If you must chain, chain on a secret (e.g. HMAC keyed with a persistent server secret), not on the message.
- Don't echo a fixed, predictable prefix (`"Command executed: <known cmd>"`) alongside the ciphertext — it hands the attacker a known-plaintext crib for free.
