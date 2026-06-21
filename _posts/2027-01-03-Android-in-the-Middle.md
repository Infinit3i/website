---
title: "Android-in-the-Middle"
date: 2027-01-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, diffie-hellman, key-validation, aes-ecb]
description: "A Very Easy Crypto challenge built on a Diffie-Hellman handshake that never validates the public key it receives. Because we control one side of the exchange, sending a public key of 0 forces the shared secret to a constant the server can't change — so we derive the AES key ourselves and forge the encrypted message it's waiting for."
---

## Overview

Android-in-the-Middle is a Very Easy Crypto challenge. A TCP service runs a textbook
Diffie-Hellman (DH) key exchange, derives an AES key from the shared secret, and releases the
flag only if we send a ciphertext that decrypts to a specific fixed string. We never learn the
server's secret — but we don't need to. By sending a degenerate public key, we force the shared
secret to a value we know and forge the message. The weakness is [Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html) (CWE-322).

## The technique

The server publishes `g = 2` and a 2048-bit prime `p`, picks its own secret `c`, and asks us for
the other party's public key `M`. It then computes the shared secret as `pow(M, c, p)` and uses
its MD5 as an AES-ECB key:

```python
M = int(input("Enter The Public Key of The Memory: "))
shared_secret = pow(M, c, p)                       # M is ours, and never validated
key = hashlib.md5(long_to_bytes(shared_secret)).digest()
# flag released iff AES-ECB-decrypt(our ciphertext) == b"Initialization Sequence - Code 0"
```

The flaw: `M` is never range-checked. Certain values are **fixed points of modular
exponentiation** — `pow(0, c, p) == 0` and `pow(1, c, p) == 1` for *any* exponent `c`. Send
`M = 0` and the shared secret is `0` regardless of the server's secret. Now we know the key
exactly: `md5(long_to_bytes(0))`, and since `long_to_bytes(0)` is the empty byte string, that is
just MD5 of `b''`.

The target plaintext `Initialization Sequence - Code 0` is exactly 32 bytes — two AES blocks — so
we encrypt it directly with no padding and hand back the hex.

## Solution

Create `solve.py`:

```python
import sys, socket, hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

HOST, PORT = sys.argv[1], int(sys.argv[2])

M = 0                                              # force shared_secret = 0
key = hashlib.md5(long_to_bytes(0)).digest()       # long_to_bytes(0) == b''  ->  md5(b'')
plaintext = b"Initialization Sequence - Code 0"    # exactly 32 bytes (2 AES blocks)
ct = AES.new(key, AES.MODE_ECB).encrypt(plaintext)

s = socket.create_connection((HOST, PORT), timeout=10)

def recv_until(tok):
    buf = b""
    while tok not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf

recv_until(b"Public Key of The Memory:")
s.sendall(b"0\n")
recv_until(b"Encrypted Initialization Sequence:")
s.sendall(ct.hex().encode() + b"\n")
print(recv_until(b"}").decode(errors="replace"))
```

Run it against the spawned instance:

```bash
python3 solve.py <host> <port>
```

```
DEBUG MSG - Reseting The Protocol With The New Shared Key
DEBUG MSG - HTB{...}
```

`M = 1` is a drop-in fallback if the server ever rejects `0` (`long_to_bytes(1)` is `b'\x01'`).

## Why it worked

Diffie-Hellman's security rests on the discrete-logarithm problem protecting `g^x`. That
guarantee only holds if **both sides validate the public key they receive**. By accepting `0`
and `1`, the server let an attacker who controls one side of the exchange choose a value whose
exponentiation is constant — converting "I cannot know the shared secret" into "I get to choose
it." This is the trivial end of the small-subgroup / invalid-curve attack family: those recover
the secret from a confined subgroup, while here `0` and `1` collapse it to a constant outright.

## Fix / defense

Validate the peer public key before using it, and authenticate the exchange:

```python
if not (2 <= M <= p - 2):                  # reject 0, 1, p-1, p
    raise ValueError("invalid public key")
# for a safe-prime group also check subgroup membership: pow(M, q, p) == 1
shared_secret = pow(M, c, p)
```

Better still, don't hand-roll DH — use X25519 / ECDH from a vetted library (`cryptography`,
libsodium), which perform these checks internally, and use an authenticated key exchange (signed
keys or a PAKE) so a man-in-the-middle cannot substitute a key in the first place.
