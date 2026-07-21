---
layout: post
title: "Find Marher's Secret"
date: 2028-06-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, rc4, fms, wep, stream-cipher, key-recovery, chosen-plaintext, sockets, automation]
description: "A Medium Crypto challenge that hands you an RC4 encryption oracle whose key is your chosen IV prepended to a fixed secret — the WEP construction. It falls to the Fluhrer–Mantin–Shamir attack, recovering the 27-byte secret one byte at a time with only len*256 chosen-IV queries, then a resilient parallel collector beats the flaky instance."
---

## Overview

*Find Marher's Secret* is a Medium **Crypto** challenge. A TCP/JSON service encrypts your
chosen plaintext with RC4 using a key of `iv || secret`, where you fully control the `iv` and
it is **prepended** to a fixed 27-byte secret. That is exactly the WEP key schedule, and WEP
is broken by the **Fluhrer–Mantin–Shamir (FMS)** attack — so the secret can be recovered one
byte at a time from a small number of chosen-IV queries, then submitted to a `claim` option
that returns the flag.

## The technique

The server exposes two actions over a JSON socket:

```python
def encrypt(key, iv, pt):
    return ARC4.new(iv + key).encrypt(pt).hex()   # iv = attacker-chosen, key = secret (27 bytes)
```

- `encrypt` — you send `iv` and `pt` (both hex), you get `RC4(iv||secret).encrypt(pt)`.
- `claim` — you send a `key`; if `sha256(key) == sha256(secret)`, the server returns the flag.

RC4 turns its key into a keystream in two phases. The first phase (the KSA) is a deterministic
shuffle of a 256-entry array, stepping through the key bytes, and the very first keystream byte
is strongly influenced by the first few key bytes. Because your IV sits *in front of* the
secret, you can craft IVs so that, after the KSA has processed the known prefix (your `iv` plus
the secret bytes you have already recovered), the next unknown secret byte leaks into that first
keystream byte with a usable bias (~5%, versus 1/256 ≈ 0.4% for random guessing). This is the
classic RC4 key-schedule weakness — a [use of a broken cryptographic algorithm](https://cwe.mitre.org/data/definitions/327.html).

Encrypt a single `00` byte and the returned ciphertext byte **is** `keystream[0]`.

## Solution

Recover `secret[l]` (0-indexed), knowing `secret[0..l-1]`:

1. Send 256 "resolved" IVs of the form `(l+3, 255, x)` for `x` in `0..255`, each with `pt="00"`.
2. Locally run the KSA for the first `3+l` steps (fully known: `iv || recovered`).
3. Predict `guess = (Sinv[ks0] - j - S[3+l]) mod 256`, where `Sinv` is the inverse of the current
   array `S`, `j` the running index, `ks0` the observed keystream byte.
4. Each guess is right ~5% of the time — **vote** over all 256 samples; the true byte wins
   decisively (~13 votes vs ~1 for noise). Bytes are recovered in order (each depends on the last).

Plain per-byte argmax succeeds ~90% of the time, and one wrong byte poisons every later byte.
Two cheap fixes make it deterministic: a **DFS over the top-k vote candidates** per position, and
**verifying the full key** against ~60 random-IV keystream samples you also cached (a candidate is
correct only if a local `RC4(iv||key)` first keystream byte equals the oracle's for every sample).

The core of the working `solve.py`:

```python
import socket, json, collections
IVLEN = 3

def ks0(sock, iv):                      # pt="00" -> ct == keystream[0]
    sock.sendall((json.dumps({"option":"encrypt","iv":iv.hex(),"pt":"00"})+"\n").encode())
    b = b""
    while b'"ct"' not in b: b += sock.recv(4096)
    return int(json.JSONDecoder().raw_decode(b[b.index(b"{"):].decode("latin1"))[0]["ct"], 16)

def ksa_prefix(K, steps):               # deterministic KSA over the KNOWN prefix
    S = list(range(256)); j = 0
    for i in range(steps):
        j = (j + S[i] + K[i % len(K)]) % 256
        S[i], S[j] = S[j], S[i]
    return S, j

def votes(pos, prefix, cache):          # FMS vote for secret[pos]
    v = collections.Counter()
    for x in range(256):
        iv = bytes([pos+3, 255, x]); k = cache[iv]
        S, j = ksa_prefix(iv + bytes(prefix), IVLEN + pos)
        Sinv = [0]*256
        for idx, val in enumerate(S): Sinv[val] = idx
        v[(Sinv[k] - j - S[IVLEN + pos]) % 256] += 1
    return v
```

Once all 27 bytes are recovered, submit the key with the `claim` option and read the flag:

```bash
python3 solve.py <host> <port>
# [+] key a1dd...eace1
# {"response": "success", "flag": "HTB{...}"}
```

The interesting engineering wall is not the crypto but the infrastructure. The oracle is slow
(~185 ms/query) and you need `27 * 256 = 6912` queries, so a serial run takes ~21 minutes. The
server forks per connection, so you can parallelise — but ~40 connections overwhelm it, while
~10–12 is the sweet spot. The instance also died every few minutes, so the collector caches
every answer keyed by IV and, on container death, re-spawns the instance and resumes from the
cache. The full run completed in ~137 seconds across three auto-respawns.

## Why it worked

RC4's key setup is not designed to hide early key bytes when an attacker controls a known prefix
of the key. WEP made exactly this mistake — prepending a public IV onto a long-term key — and
FMS turned "one keystream byte per chosen IV" into a byte-at-a-time recovery of the secret. The
challenge reproduces the flaw faithfully: attacker-chosen IV, fixed secret, and an oracle that
returns raw keystream.

## Fix / defense

- **Never** prepend an attacker-known IV onto the key — that is WEP, and RC4 in this mode is dead.
  Do not use RC4 at all.
- Use an authenticated cipher (AES-GCM, XChaCha20-Poly1305) with a **random per-message nonce
  mixed through a KDF** (e.g. `HKDF(secret, salt=nonce)`), never concatenated onto the raw key.
- Do not expose an oracle that returns raw keystream for attacker-chosen plaintext under a fixed key.

The flag is recovered live by running the solver; its value is redacted here (`HTB{...}`).
