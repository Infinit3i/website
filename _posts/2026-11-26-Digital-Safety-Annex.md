---
title: "Digital Safety Annex"
date: 2026-11-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, dsa, nonce, weak-randomness, private-key-recovery, cwe-338]
description: "A Very Easy Crypto challenge: a DSA signing service draws its nonce from a tiny range. Brute-force the nonce from one captured signature, recover the private key, and read the flag back through the server's own download oracle."
---

## Overview

`Digital Safety Annex` is a Very Easy HackTheBox **Crypto** challenge. The name
"D.S.A" is the hint — it's a [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
signing service that stores secrets and signs messages, including the flag. The
implementation derives the per-signature nonce `k` from a tiny range, so a single
captured signature is enough to brute-force the nonce, recover the long-term
private key, and use the server's own "download" feature as a plaintext oracle.

## The technique

DSA signs a message hash `h` with a secret private key `x` and a per-signature
nonce `k`:

```
r = (g^k mod p) mod q
s = k^-1 * (h + x*r) mod q
```

The security of the whole scheme rests on `k` being **secret and uniformly
random** over `[1, q-1]`. Rearranging the second equation gives:

```
x = (s*k - h) * r^-1 mod q
```

So learning `k` for even one signature instantly yields the private key `x`. This
challenge breaks the nonce — a [use of a cryptographically weak / insufficiently
random value](https://cwe.mitre.org/data/definitions/338.html):

```python
# _account.py — nonce upper bound tied to username length
self.k_max = int(len(self.username) ** 6)      # 'ElGamalSux' (10 chars) -> 10**6

# _dsa.py
k = random.randint(self.k_min, k_max)          # k_min = 65500
```

The flag is signed as user `ElGamalSux` (10 characters), so `k_max = 1_000_000`
and `k ∈ [65500, 1_000_000]` — roughly 2²⁰ candidates. That is small enough to
enumerate every possible nonce.

Two extra design flaws hand us the inputs:

- The **Developer Note** menu prints the public params `p, q, g`, and after an
  Admin login — whose password `5up3r_53cur3_P45sw0r6` is hardcoded in the source
  — it dumps `user_log`, the list of every `(signature, h)` pair, including the
  flag's.
- The **Download** menu re-signs from a `(k, x)` pair you supply and prints the
  stored **plaintext** when the recomputed signature matches. This is what turns
  our recovered key into a flag-reading oracle (the log only leaks
  `h = sha256(FLAG)`, not the flag itself).

## Solution

The right `k` for the target signature `(r, s)` is the one with
`(g^k mod p) mod q == r`. Recomputing `g^k mod p` from scratch a million times is
slow, but consecutive powers differ by a single multiply
(`g^(k+1) = g^k * g`), so we walk the range with one modular multiply per step.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
from hashlib import sha256
import ast, re
from pwn import remote

HOST, PORT = sys.argv[1], int(sys.argv[2])

# 5 messages signed on boot besides the flag -> their hashes.
# The flag's log entry is the one whose h matches none of these.
KNOWN_H = {sha256(m.encode()).hexdigest() for m in [
    "DSA is a way better algorithm",
    "Testing signing feature",
    "I doubt anyone could beat it",
    "I should display the user log and make sure its working",
    "To prove it, I'm going to upload my most precious item! No one but me will be able to get it!",
]}
ADMIN_PW = "5up3r_53cur3_P45sw0r6"          # hardcoded in server.py

io = remote(HOST, PORT)

def menu(opt):
    io.recvuntil(b"[+] Option > ")
    io.sendline(opt.encode())

# 1) Developer Note: leak p, q, g and (Admin login) the full user_log.
menu("4")
io.recvuntil(b"p = "); p = int(io.recvline().strip())
io.recvuntil(b"q = "); q = int(io.recvline().strip())
io.recvuntil(b"g = "); g = int(io.recvline().strip())
io.recvuntil(b"Test user log (y/n): "); io.sendline(b"y")
io.recvuntil(b"Enter your password : "); io.sendline(ADMIN_PW.encode())
line = io.recvuntil(b"Welcome to the Digital Safety Annex", drop=True).strip()
log = ast.literal_eval(line[line.index(b"["):line.rindex(b"]") + 1].decode())

# 2) Pick the flag entry: the (r, s, h) whose h is not a known message.
r = s = h = None
for sig, hh in log:
    if hh not in KNOWN_H:
        r, s, h = int(sig[0]), int(sig[1]), int(hh, 16)
        break

# 3) Brute the nonce incrementally: one modmul per candidate.
cur = pow(g, 65500, p)
for k in range(65500, 1_000_001):
    if cur % q == r:
        break
    cur = (cur * g) % p

# 4) Recover the private key from the single signature.
x = ((s * k - h) * pow(r, -1, q)) % q

# 5) Download path re-signs from (k, x); on match it prints the flag plaintext.
menu("3")
io.recvuntil(b"stored the message: "); io.sendline(b"ElGamalSux")
io.recvuntil(b"request id: ");         io.sendline(b"3")
io.recvuntil(b"nonce value: ");        io.sendline(str(k).encode())
io.recvuntil(b"private key: ");        io.sendline(str(x).encode())
resp = io.recvuntil(b"[+] Option > ", drop=True)
print(re.search(rb"HTB\{[^}]+\}", resp).group().decode())
```

Run it against the live instance:

```bash
python3 solve.py <target-ip> <target-port>
```

The brute-force lands the nonce in a couple of seconds (`k = 426739` on the
solved instance), the private key follows by simple algebra, and the download
oracle prints the flag:

```
[+] recovered nonce k = 426739
[+] recovered private key x = ...
[+] Here is your super secret message: HTB{...}
```

## Why it worked

DSA's confidentiality of the private key depends entirely on the nonce being
unpredictable and never reused. Tying the nonce's upper bound to
`len(username)**6` shrank the search space to about 2²⁰ values — small enough to
test exhaustively. One known signature plus its recovered nonce pins the private
key `x` with a single modular equation, and the server then prints any stored
plaintext for a key it believes is legitimate.

## Fix / defense

- Generate `k` with a CSPRNG over the **full** `[1, q-1]`, or use
  [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) deterministic
  nonces — never bound or derive it from a small, observable quantity such as a
  username length.
- Don't expose oracles that dump signatures with their message hashes, or that
  re-sign from caller-supplied `(k, x)` values.
- Don't hardcode administrative credentials in source.

Related nonce failures collapse the same way: a *biased* nonce (a few leaked
bits across several signatures) is recovered with a lattice / Hidden Number
Problem, and a *reused* nonce (the same `r` on two messages) gives the key in
closed form via `k = (h1 - h2) * (s1 - s2)^-1 mod q`.
