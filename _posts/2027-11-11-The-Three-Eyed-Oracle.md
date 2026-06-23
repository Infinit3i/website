---
title: "The Three-Eyed Oracle"
date: 2027-11-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ecb, byte-at-a-time, oracle, cwe-327]
description: "An encryption service bolts a secret flag onto your own input and hands back the AES-ECB ciphertext — and because ECB encrypts every block the same way, you can read that flag back one byte at a time without ever touching the key."
---

## Overview

The Three-Eyed Oracle is an easy HackTheBox **Crypto** challenge. You connect to a
service that encrypts `prefix || your_input || FLAG` under **AES in ECB mode** and
returns the ciphertext as hex. ECB's fatal property — identical plaintext blocks
always produce identical ciphertext blocks — turns that service into a *byte-at-a-time
oracle*: by lining the secret up against attacker-controlled padding, the entire
flag falls out one character per query, with no key recovery at all. This is a
[use of a broken or risky cryptographic algorithm](https://cwe.mitre.org/data/definitions/327.html)
([CWE-327](https://cwe.mitre.org/data/definitions/327.html)).

## The technique

The server's encryption routine is the whole vulnerability:

```python
prefix = random.randbytes(12)     # module global -> set ONCE, before the fork
key    = random.randbytes(16)     # module global -> set ONCE, before the fork
def encrypt(key, msg):
    msg = bytes.fromhex(msg)
    crypto = AES.new(key, AES.MODE_ECB)               # ECB mode
    padded = pad(prefix + msg + FLAG, 16)             # secret appended to our input
    return crypto.encrypt(padded).hex()
```

Because `prefix` and `key` are created once before the `ForkingMixIn` server forks,
they are constant for every connection — the plaintext layout is fully deterministic:

```
 block0              block1               block2 ...
[ prefix(12) | P P P P ][ ....... FLAG ....... ]
```

The prefix is **12 bytes**, which we know. Send exactly **4 bytes** (`(-12) mod 16`)
and block 0 is filled to a clean boundary; everything after it is `our_bytes || FLAG`.
Now recover the flag one byte at a time:

1. Send `4 align bytes + 'A'*15`. The first unknown flag byte becomes the **16th byte**
   of the next block, so that block encrypts `AAAAAAAAAAAAAAA + FLAG[0]`. Save it as the
   *target*.
2. Send `4 + 'A'*15 + guess` for every printable `guess`. The guess whose ciphertext
   block equals the target **is** `FLAG[0]` — ECB block-equality confirms it.
3. Shrink the filler by one, append the recovered byte, repeat until `}`.

One unknown byte per query. No key, no math — just comparing 16-byte blocks.

## Solution

The durable solver. It keeps a single connection, sends input hex-encoded, and reads
responses with a buffered line reader (explained under *Why it worked*):

```python
import socket, sys
HOST, PORT = sys.argv[1], int(sys.argv[2])
BS = 16
ALIGN = 4            # (-len(prefix)) % 16  -> pad the 12-byte prefix to a block
SKIP  = 1            # drop the prefix block from each ciphertext
CHARSET = (b'HTB{}_' + bytes(range(0x21, 0x7f)))

class Oracle:
    def __init__(self):
        self.buf = b''
        self._connect()
    def _connect(self):
        self.s = socket.create_connection((HOST, PORT), timeout=12)
        self.s.settimeout(12); self.buf = b''
        while b'> ' not in self.buf:
            self.buf += self.s.recv(4096)
        self.buf = b''
    def _readline(self):
        while b'\n' not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk: raise ConnectionError('closed')
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b'\n')
        return line.replace(b'> ', b'').strip()
    def encrypt(self, msg):
        payload = (b'\x00' * ALIGN + msg).hex().encode() + b'\n'
        for _ in range(4):
            try:
                self.s.sendall(payload)
                return bytes.fromhex(self._readline().decode())[SKIP * BS:]
            except Exception:
                try: self.s.close()
                except Exception: pass
                self._connect()
        raise RuntimeError('oracle dead')

orc = Oracle()
known = sys.argv[3].encode() if len(sys.argv) > 3 else b''   # optional resume seed
while True:
    pre  = b'A' * (BS - 1 - (len(known) % BS))
    bidx = (len(pre) + len(known)) // BS
    target = orc.encrypt(pre)[bidx*BS:(bidx+1)*BS]
    found = next((g for g in CHARSET
                  if orc.encrypt(pre + known + bytes([g]))[bidx*BS:(bidx+1)*BS] == target),
                 None)
    if found is None: break
    known += bytes([found])
    if known.endswith(b'}'): break
print(known.decode())
```

Run it against the spawned instance:

```bash
python3 solve.py <host> <port>
```

It prints the flag, `HTB{...}`, recovered live from the oracle.

## Why it worked

ECB encrypts each 16-byte block independently with the same key, so two equal
plaintext blocks always yield equal ciphertext blocks. Appending a secret to
attacker-controlled input lets an attacker slide each unknown byte into the last
position of a known block and brute-force just that byte by comparison — the key is
never needed. The known prefix length is the only extra ingredient, and it's used
purely to align the secret to a block boundary.

Two practical notes that matter when you implement it:

- **Buffered line reads.** The server prints the ciphertext line then the next `> `
  prompt; `recv` often returns them coalesced as `"ct\n> "`. A naive
  `while not buf.endswith('\n')` reader hangs forever on that trailing space. Reading
  *until a newline is present* and then `partition`-ing fixes it — a reusable pattern
  for any line-oriented socket oracle.
- **Resume seed.** Short-lived instances can recycle mid-run, so the solver accepts a
  partial flag as a third argument and finishes only the unrecovered tail on a fresh
  connection.

## Fix / defense

- **Never use ECB** for structured data. Use an authenticated mode such as **AES-GCM**
  with a fresh random nonce per message — identical plaintext blocks then encrypt
  differently, which destroys the block-equality oracle.
- **Never concatenate a secret with attacker-controlled input** before encrypting under
  a deterministic cipher, regardless of mode.
