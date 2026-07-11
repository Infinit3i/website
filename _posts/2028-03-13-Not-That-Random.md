---
layout: post
title: "Not that random"
date: 2028-03-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, hmac, sha256, distinguisher, prf, custom-crypto]
description: "A casino pays out only if you can repeatedly tell a home-rolled keyed hash from random bytes. The custom MAC leaks its own subkey to a chosen query, turning an intended PRF into a public function — a perfect distinguisher without the secret key."
---

## Overview

Not that random is a Medium crypto challenge wrapped in a casino. You start with 100 coins
and need 500 to buy the flag; the only way up is a game where the server shows a hash
output and you guess whether it came from its custom keyed hash or from random bytes. The
"impossible" game is trivial once you notice the custom MAC hands you its own subkey.

## The game

- **Play** (free): the server shows a random 32-byte input `m` and an output `o`, then asks
  hash-or-random. Right → +5, wrong → −10.
- **Buy hint** (−10): you send any input `x`; the server returns `custom_hmac(key, x)` OR 64
  random bytes, chosen by a coin flip.

The MAC:

```python
C = b"Improving on the security of SHA is easy"       # PUBLIC constant
def keyed_hash(k, m): return sha256(k + m).digest()
def custom_hmac(key, inp):
    H1 = keyed_hash(key, C)                            # subkey
    return keyed_hash(H1, inp) + keyed_hash(key, inp)  # sha256(H1||inp) || sha256(key||inp)
```

## The technique

The first half is keyed on `H1 = sha256(key ‖ C)`; the second half is `sha256(key ‖ inp)`.
Query the hint oracle with **`inp = C`** — the same public constant baked into the MAC:

```
custom_hmac(key, C) = sha256(H1 ‖ C) ‖ sha256(key ‖ C)
                                        └──────────────┘  == H1
```

The **second 32 bytes are exactly `H1`**. Once you have `H1` as a value, the first half of
the MAC for *any* message is computable yourself as `sha256(H1 ‖ m)` — no key required. That
is a perfect [distinguisher](https://cwe.mitre.org/data/definitions/327.html). In a play
round with input `m` and output `o`:

```
answer 0 (my hash)  iff  o[:32] == sha256(H1 ‖ m)     # a random impostor matches with prob 2^-256
answer 1 (random)   otherwise
```

To separate a genuine hint from the random impostor in a single query, note a real reply is
internally consistent: `sha256(reply[32:] ‖ C) == reply[:32]`. Random bytes satisfy that
only with probability `2^-256`, so the first self-consistent hint reveals `H1`.

## Solution

Create `solve.py`:

```python
#!/usr/bin/python3
import sys, re
from hashlib import sha256
from pwn import remote, context

context.log_level = "error"
HOST, PORT = sys.argv[1], int(sys.argv[2])
C = b"Improving on the security of SHA is easy"
io = remote(HOST, PORT)

def menu(opt):
    io.recvuntil(b"Option: "); io.sendline(str(opt).encode())

def buy_hint(inp):
    menu(2); io.recvuntil(b"hex :: "); io.sendline(inp.hex().encode())
    line = io.recvline_contains(b"Your output is").decode()
    return bytes.fromhex(re.search(r"::\s*([0-9a-f]+)", line).group(1))

def play(H1):
    menu(3)
    m = bytes.fromhex(re.search(r"input ([0-9a-f]+)", io.recvline().decode()).group(1))
    o = bytes.fromhex(re.search(r"output ([0-9a-f]+)", io.recvline().decode()).group(1))
    io.recvuntil(b":: "); io.sendline(b"0" if o[:32] == sha256(H1 + m).digest() else b"1")
    io.recvline()

# 1) recover the subkey H1 from a self-consistent hint
H1 = None
for _ in range(20):
    out = buy_hint(C)
    if len(out) == 64 and sha256(out[32:] + C).digest() == out[:32]:
        H1 = out[32:]; break
assert H1

# 2) grind coins with the perfect distinguisher, then buy the flag
for _ in range(100):
    play(H1)
menu(1)
print(io.recvall(timeout=5).decode())
```

```bash
python3 solve.py <host> <port>
```

One hint recovers `H1`, every play round is a guaranteed +5, and the balance blows past
500 for the flag:

```
HTB{...}
```

*(Practical note: the challenge's docker instance has a very short TTL and can die
mid-grind, so in practice the run is wrapped in a respawn-and-retry loop — each attempt is a
fresh connection with a fresh 100-coin balance, and one attempt lands inside a live
instance's lifetime.)*

## Why it worked

A home-rolled "improved HMAC" concatenated two keyed hashes that shared key material such
that one component's output *is* the other component's secret prefix. Feeding the public
domain-separation constant back in as the message dumped that subkey straight to the
attacker, collapsing an intended PRF into a publicly computable function.

## Fix / defense

- Never invent a MAC — use **HMAC-SHA256** or **KMAC**, which are proven and have no
  exploitable shared-subkey structure.
- Never concatenate keyed hashes that share key material across components.
- Never feed a public constant back in as an attacker-controllable message.
- Treat any "distinguish the MAC from random" game as broken the moment a chosen input can
  reveal internal state.
