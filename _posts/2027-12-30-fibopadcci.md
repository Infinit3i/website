---
layout: post
title: "Fibopadcci"
date: 2027-12-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, padding-oracle, aes, pcbc, cwe-347]
---

A crypto challenge that dresses up a classic padding-oracle attack in two disguises: a home-made *Fibonacci* padding scheme and a non-standard block-chaining mode. Neither disguise helps — a service that reveals whether a decrypted message is "correctly padded" is a full decryption oracle, and this one even decrypts with a hard-coded, known chaining value that hands you the AES block permutation directly.

## Overview

The service offers two options: **encrypt the flag** (returns the ciphertext plus two random 16-byte values `a` and `b`), and **send a message** (you supply a ciphertext and a `b`; it decrypts and tells you only whether the padding is valid). That yes/no padding leak is a [padding oracle](https://cwe.mitre.org/data/definitions/347.html) — enough to recover the flag with no key.

## The technique

**The cipher** is a PCBC variant built on AES-ECB:

```
encrypt block i:  C_i = E(C_{i-1} XOR P_i) XOR P_{i-1}      (C_-1 = b, P_-1 = a)
decrypt block i:  P_i = D(C_i XOR P_{i-1}) XOR C_{i-1}
```

Everything except the AES `E`/`D` is XOR with values we know or control, so if we can compute `D(V)` for an arbitrary block `V`, we can walk the decrypt recurrence and recover the plaintext.

**The padding** ("fibopadcci") uses `fib = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61]`. A valid length-`L` pad is the last `L` bytes being `[1, 2, 3, 5, ..., fib[L-1]]` — the last byte is the *largest* fib value and earlier bytes count *down* the sequence. The check reads the last byte, looks up its position to get the length, then verifies the preceding bytes. **A lone trailing `0x01` is always valid** (length 1, nothing else checked) — that is the wedge the whole attack turns on.

**The gift:** in the "send a message" path the chaining value `a` is *hard-coded to a known constant* (`HTB{th3_s3crt_A}`, shipped in the source). For a single block the oracle computes `P0 = D(ct XOR a) XOR b`. Choosing `ct = V XOR a` makes it compute `D(V)` for any `V` you like — the padding oracle becomes a direct AES-ECB decryption oracle.

## Solution

Recover `I = D(V)` byte-by-byte from position 15 down to 0. To find `I[p]` (with `L = 16 - p`): pin the already-known tail so `P0[q] = fib[q-p]` for every `q > p`, then scan `b[p]` until the oracle validates — that happens exactly when `P0[p] == 1` (the innermost pad byte), giving `I[p] = b[p] XOR 1`. The terminal byte needs a small disambiguation: a random longer pad can coincidentally validate, so re-test each hit with a neighbouring byte flipped — only the genuine `P[15] == 1` survives.

Then chain `D(...)` back through the mode from the revealed `a`, `b`, and ciphertext blocks:

```
P0 = D(C0 XOR a) XOR b
Pk = D(Ck XOR P_{k-1}) XOR C_{k-1}
```

The recovered plaintext ends in the fib pad `01 02 03 05 08 0d 15 22 37 59 90` — a free byte-perfect self-check.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, sys, threading

HOST, PORT = sys.argv[1], int(sys.argv[2])
FIB = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61]
A_ORACLE = b'HTB{th3_s3crt_A}'          # sendMessage()'s hard-coded secret A (16B)
NCONN = 32

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=15)
        self.buf = b""
        self.read_until(b"Your option: ")
    def read_until(self, marker):
        while marker not in self.buf:
            d = self.s.recv(4096)
            if not d:
                raise EOFError
            self.buf += d
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out
    def encrypt_flag(self):
        self.s.sendall(b"0\n")
        txt = self.read_until(b"Your option: ").decode(errors="replace")
        ef = a = b = None
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("encrypted_flag:"): ef = line.split(":", 1)[1].strip()
            elif line.startswith("a:"): a = line.split(":", 1)[1].strip()
            elif line.startswith("b:"): b = line.split(":", 1)[1].strip()
        return bytes.fromhex(ef), bytes.fromhex(a), bytes.fromhex(b)
    def oracle(self, ct, b):
        self.s.sendall(b"1\n")
        self.read_until(b"ciphertext in hex: ")
        self.s.sendall(ct.hex().encode() + b"\n")
        self.read_until(b"encryption in hex: ")
        self.s.sendall(b.hex().encode() + b"\n")
        return b"successfully" in self.read_until(b"Your option: ")

pool = [Conn() for _ in range(NCONN)]

def batch(queries):
    results = [None] * len(queries)
    lock = threading.Lock(); idx = [0]
    def worker(conn):
        while True:
            with lock:
                i = idx[0]
                if i >= len(queries): return
                idx[0] += 1
            ct, b = queries[i]
            results[i] = conn.oracle(ct, b)
    threads = [threading.Thread(target=worker, args=(c,)) for c in pool]
    for t in threads: t.start()
    for t in threads: t.join()
    return results

def recover_I(V):
    ct = xor(V, A_ORACLE)              # oracle then computes D(ct ^ a) = D(V)
    I = [0] * 16
    for p in range(15, -1, -1):
        L = 16 - p
        base = bytearray(16)
        for q in range(p + 1, 16):    # pin known tail to the fib pad
            base[q] = I[q] ^ FIB[q - p]
        res = batch([(ct, bytes(bytearray(base[:p]) + bytes([v]) + base[p+1:])) for v in range(256)])
        hits = [v for v in range(256) if res[v]]
        if p == 15:                   # disambiguate length-1 accidental pads
            dq = []
            for v in hits:
                b = bytearray(16); b[15] = v; b[14] ^= 0xff
                dq.append((ct, bytes(b)))
            hits = [v for v, ok in zip(hits, batch(dq)) if ok]
        I[p] = hits[0] ^ 1
    return bytes(I)

def main():
    ef, a_flag, b_flag = pool[0].encrypt_flag()
    blocks = [ef[i:i+16] for i in range(0, len(ef), 16)]
    plain = b""; prev_p, prev_c = a_flag, b_flag
    for C in blocks:
        I = recover_I(xor(C, prev_p))
        P = xor(I, prev_c)
        plain += P
        prev_p, prev_c = P, C
    import re
    m = re.search(rb"HTB\{[^}]*\}", plain)
    print("FLAG:", m.group().decode() if m else plain)

if __name__ == "__main__":
    main()
```

Run it against the instance:

```bash
python3 solve.py <target-host> <target-port>
```

The 32-socket pool tests all 256 candidates per byte in parallel, so the full three-block flag falls out in under a minute:

```
FLAG: HTB{...}
```

## Why it worked

A padding-oracle attack is a property of *observable padding validity*, not of PKCS#7 or CBC specifically. The custom Fibonacci scheme is just as attackable as any standard padding — the only requirement is a recognisable, position-dependent valid form. Rolling your own padding, or your own PCBC chaining mode, changed nothing. And shipping a *known* chaining constant `a` in the "send a message" path collapsed the whole thing further, turning the padding oracle into a direct block-decryption oracle.

## Fix / defense

Use authenticated encryption ([CWE-347](https://cwe.mitre.org/data/definitions/347.html) remediation): AES-GCM, or encrypt-then-MAC. Reject tampered ciphertext on the MAC check *before* any padding is examined, and return an identical response and timing for every failure so there is no valid/invalid distinction to observe. And never place a "secret" constant inside client-readable source.
