---
layout: post
title: "Oracle Leaks"
date: 2028-06-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rsa, manger, decryption-oracle, msb-oracle, malleability, side-channel]
description: "A Medium Crypto challenge that leaks only the byte-length of an RSA decryption. That single number is a Manger MSB oracle: combined with RSA malleability it recovers the full flag in ~1050 queries — and the live solve hinges on a 1-RTT trick to fit a hard 300-second instance window."
---

## Overview

*Oracle Leaks* is a Medium **Crypto** challenge. You connect to an RSA menu service that will
hand you the public key and the encrypted flag, and — critically — will decrypt *any* ciphertext
you send and tell you **only the byte-length of the resulting plaintext**. That one leaked number
is a [Manger](https://cwe.mitre.org/data/definitions/203.html) most-significant-bit oracle;
combined with RSA's malleability it recovers the entire flag in about 1050 queries.

## The technique

The service exposes three options: `1` returns the public key `(n, e)`, `2` returns the flag
encrypted under it (`ct0 = m^e mod n`), and `3` decrypts an attacker-supplied ciphertext with the
private key and prints `byte_length(pt)` — nothing else.

Two facts turn that trickle of information into full plaintext recovery:

1. **RSA is malleable.** `enc(a)·enc(b) = enc(a·b)`. Because you hold the public key, sending
   `c' = ct0 · s^e mod n` decrypts to `m·s mod n` for any integer `s` you choose. So option 3
   becomes an oracle you can evaluate on scaled copies of the secret plaintext.

2. **A byte-length is a most-significant-bit test.** For a 128-byte modulus,
   `byte_length(v) ≤ 127` is exactly `v < 256^127`. So option 3 answers *"is `m·s mod n` below
   `256^127`?"* — precisely [Manger's oracle](https://cwe.mitre.org/data/definitions/203.html),
   the RSA cousin of Bleichenbacher's padding oracle.

Choose multipliers `s`, watch the length flip between 127 and 128, and a continued-fraction
(Euclidean) interval-narrowing pins `m` in ~1050 queries.

## Solution

The solver pulls `(n, e)` and `ct0`, wraps option 3 as a length oracle, runs the interval
narrowing, and then recovers the exact plaintext. Two details are what actually make it land:

**Verify with the public key — don't trust the reconstructed bounds.** Interval narrowing gives
*approximate* bounds; they can be off by a few in a low-middle byte (a naive read produced a
corrupted `HTB{m4ng3q}`). The fix costs zero extra oracle queries: you already have
`ct0 = m^e mod n`, so re-encrypt each candidate and compare.

```python
for cand in range(minimum - 2**22, maximum + 2**22):
    if cand & 0xff != 0x7d:                 # the flag ends with '}'
        continue
    raw = int_to_bytes(cand)
    if raw.endswith(b'}') and b'HTB{' in raw and pow(cand, e, n) == ct0:
        print(raw[raw.index(b'HTB{'):])      # cryptographically certain
        break
```

**Fit the run inside one 300-second connection.** The instance has a hard ~300s lifetime and
regenerates the RSA key on every new connection (reconnecting gives a different `n` and `ct0`, so
you cannot resume). The whole ~1050-query attack must finish in one window. A normal two-round-trip
netcat query (~0.4–0.5s each) overruns it. The trick is a 1-RTT query: send the option, pause
**50 ms locally**, then send the ciphertext and read straight through to the length line.

```python
def test_num(x):
    # send option, tiny LOCAL delay so the remote pty reads it before the payload,
    # then the ciphertext, and read straight through to Length — one round trip.
    p.send(b'3\n'); time.sleep(0.05); p.send(int_to_bytes(x).hex().encode() + b'\n')
    p.recvuntil(b'Length:')
    return int(p.recvline().split()[0])
```

The local delay is mandatory: with *no* gap the remote pseudo-terminal misreads the option
(`Wrong option! → exit`). With it, the query drops to ~0.27s → 1053 queries in ~283s, comfortably
under the TTL. The flag lands on the first successful run:

```
HTB{...}
```

## Why it worked

The server returns a value that **depends on the decrypted plaintext** (its length) while
accepting an **attacker-chosen ciphertext**. That combination — a decryption result leaked back to
the caller plus ciphertext malleability — is the entire Bleichenbacher/Manger family. The PKCS#1
padding never has to be "cracked"; it is carried along and stripped at the end. This is an
[observable discrepancy](https://cwe.mitre.org/data/definitions/203.html) (CWE-203).

## Fix / defense

- Never let a decrypt/unwrap endpoint's response vary with the plaintext — not length, not
  padding valid/invalid, not timing. Return one constant response regardless of decode outcome.
- Use **RSA-OAEP**, not PKCS#1 v1.5, and treat every decode failure identically.
- Authenticate ciphertexts (AEAD / signed envelopes) so a mutated `ct0·s^e` is rejected before the
  private-key operation runs.
- Rate-limit decrypt calls against a single key — these attacks need hundreds to thousands of probes.
