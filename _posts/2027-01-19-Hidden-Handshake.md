---
title: "Hidden Handshake"
date: 2027-01-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ctr, keystream-reuse, nonce-reuse, known-plaintext]
description: "A Very Easy Crypto challenge that hands you control of both the nonce and a field in front of the secret. Send the same access key twice to reuse the AES-CTR keystream, then slide a known plaintext over the flag's offset to XOR it straight out — no key recovery required."
---

## Overview

`Hidden Handshake` is a Very Easy HackTheBox **Crypto** challenge. A "secure comms"
service encrypts a message containing the flag with AES in CTR mode. The catch: the
client picks the value that becomes **both** the key input and the nonce, and the client
also controls a field that sits **in front of** the flag. That's everything needed for a
textbook [keystream reuse](https://cwe.mitre.org/data/definitions/323.html) attack — XOR
the flag out without ever knowing the key.

## The technique

A stream cipher (and CTR/OFB stream *modes* of a block cipher) encrypts by XOR-ing the
plaintext with a **keystream**:

```
ciphertext = plaintext XOR keystream
```

The keystream is a pure function of `(key, nonce)` and byte position — it does not depend
on the plaintext. So encrypting two messages under the **same key and nonce** reuses the
**identical keystream**, and any known plaintext cancels it:

```
keystream = known_plaintext XOR ciphertext_of_known
secret    = ciphertext_of_secret XOR keystream
```

## The vulnerable server

```python
def kdf(p1, p2): return hashlib.sha256(p1 + p2).digest()

def encrypt(p1, p2, pt):
    key = kdf(p1, p2)
    cipher = AES.new(key, AES.MODE_CTR, nonce=p2)   # nonce == p2
    return cipher.encrypt(pt)

# p1 = server_secret  -> random, but FIXED for the whole connection
# p2 = pass2          -> WE choose it (8 chars)
# pt = f"Agent {user}, your clearance ...: {FLAG}. ..."   -> WE choose `user`
```

Two design flaws combine:

1. **We control `pass2`, and it is both a key input and the nonce.** Sending the same
   `pass2` twice in one connection yields the same key *and* the same nonce → the same
   keystream.
2. **We control `user`, which precedes `{FLAG}`.** Its length decides where the flag
   lands in the keystream — so we can park *known* bytes at the exact offset the flag
   occupies in another request.

## Solution

Keep one connection open and reuse a fixed `pass2` for every request:

- **Request A** — `user = ""` → the flag sits at a low offset, still scrambled.
- **Request B** — `user = "B"*400` → our plaintext is now fully known well past that
  offset, so we recover the keystream there from `ctB XOR known_B`.
- **Decrypt A** — `FLAG = ctA XOR keystream`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, sys, re

HOST, PORT = sys.argv[1], int(sys.argv[2])
PASS2 = b"AAAAAAAA"          # any fixed 8-char key; reused both requests

def recvuntil(f, tok):
    buf = b""
    while tok not in buf:
        c = f.read(1)
        if not c: break
        buf += c
    return buf

def query(f, sock, user):
    recvuntil(f, b"secure access key: "); sock.sendall(PASS2 + b"\n")
    recvuntil(f, b"Agent Codename: ");    sock.sendall(user + b"\n")
    recvuntil(f, b"Encrypted transmission: ")
    hexline = b""
    while True:
        c = f.read(1)
        if c in (b"\n", b""): break
        hexline += c
    return bytes.fromhex(hexline.decode().strip())

s = socket.create_connection((HOST, PORT))
f = s.makefile("rb")
recvuntil(f, b"---\n")

ctA = query(f, s, b"")            # short user -> flag at a low offset
ctB = query(f, s, b"B" * 400)    # long user  -> known plaintext covers it
s.close()

known_B = b"Agent " + b"B" * 400 + b", your clearance for Operation Blackout is: "
n  = min(len(ctB), len(known_B))
ks = bytes(ctB[i] ^ known_B[i] for i in range(n))
ptA = bytes(ctA[i] ^ ks[i] for i in range(min(len(ctA), len(ks)))).decode("latin1")
print(ptA)
m = re.search(r"HTB\{[^}]*\}", ptA)
print("FLAG:", m.group(0) if m else "NOT FOUND")
```

Run it against the instance:

```bash
python3 solve.py <host> <port>
# Agent , your clearance for Operation Blackout is: HTB{...}. It is mandatory ...
# FLAG: HTB{...}
```

Flag value redacted.

## Why it worked

CTR keystream is deterministic in `(key, nonce)`. The server let the client fix both (via
`pass2`) *and* control where the secret sits in the stream (via `user`), so a single
connection gives one ciphertext with the flag at a known offset and a second ciphertext
whose plaintext is fully known at that same offset. Subtracting the keystream is just XOR
— no factoring, no oracle, no key recovery.

## Fix / defense

- Generate a **fresh random nonce per message** and transmit it with the ciphertext.
- Never let the client choose or fix the nonce, and don't fold a per-connection secret
  into the key while holding the nonce constant — the keystream still repeats.
- Prefer a misuse-resistant AEAD such as **AES-GCM-SIV**, which survives accidental nonce
  reuse, and authenticate the ciphertext so tampering is detectable.
