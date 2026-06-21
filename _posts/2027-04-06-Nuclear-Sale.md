---
title: "Nuclear Sale"
date: 2027-04-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, xor, three-pass-protocol, pcap, cwe-327]
description: "An Easy Crypto challenge handed out as a captured mail thread. Three hex blobs bounce a secret between two departments using a homemade key-exchange — but it's built on XOR, so XORing all three intercepted messages together makes both keys cancel and the plaintext falls out, no key recovery needed."
---

## Overview

**Nuclear Sale** is an Easy Crypto challenge. You're given a packet capture of Plutonium Labs' mail server, and the prompt says intelligence has *"intercepted the traffic of their mail server."* Following the SMTP stream reveals a thread between the Sales and Management departments in which a buyer's identity is exchanged as three hex blobs — and one email waves the answer in your face by spelling it *"we are very **XOR**ry."* The departments rolled their own "share a secret without sharing a key" scheme on top of XOR, which is fatally broken: capture all three passes, XOR them together, and both keys cancel. This is textbook [use of a broken/risky cryptographic algorithm](https://cwe.mitre.org/data/definitions/327.html) ([CWE-327](https://cwe.mitre.org/data/definitions/327.html)).

## The technique

The two departments use the **Shamir three-pass protocol**: a message bounces back and forth, each party adding then later removing its own key, so the plaintext is never sent in the clear and no key ever crosses the wire. That's secure with a proper commuting cipher. It collapses when the cipher is XOR, because XOR both commutes *and* is its own inverse.

With sender key `A`, receiver key `B`, and plaintext `P`, the three messages on the wire are:

- `C1 = P ^ A`            — Sales encrypts
- `C2 = C1 ^ B = P^A^B`   — Management encrypts
- `C3 = C2 ^ A = P^B`     — Sales removes its key

An eavesdropper who sees all three passes recovers the plaintext with no key recovery, no brute force, and no oracle — just XOR all three:

```
C1 ^ C2 ^ C3 = (P^A) ^ (P^A^B) ^ (P^B) = P
```

Every key term appears an even number of times, so it cancels.

## Solution

First pull the three ciphertext blobs out of the captured mail thread. The challenge ships a single `challenge.pcap` of SMTP traffic; the bodies decode as Internet Message Format (`imf`):

```bash
tshark -r challenge.pcap -Y "imf || smtp.data.fragment" -T fields -e text
```

That surfaces the three equal-length hex strings carried in the "His information is encrypted below", "Here is the ciphertext encrypted with our key", and "Encrypting again with our key" emails.

Create `solve.py`:

```python
#!/usr/bin/env python3
# XOR three-pass: C1=P^A, C2=P^A^B, C3=P^B  ->  C1^C2^C3 = P  (keys cancel)
m1 = bytes.fromhex("6b65813f4fe991efe2042f79988a3b2f2559d358e55f2fa373e53b1965b5bb2b175cf039")
m2 = bytes.fromhex("fd034c32294bfa6ab44a28892e75c4f24d8e71b41cfb9a81a634b90e6238443a813a3d34")
m3 = bytes.fromhex("de328f76159108f7653a5883decb8dec06b0fd9bc8d0dd7dade1f04836b8a07da20bfe70")
P = bytes(a ^ b ^ c for a, b, c in zip(m1, m2, m3))
print(P.decode())
```

Run it:

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

XOR is linear and self-inverse. Any protocol whose security depends on a key staying secret falls apart the moment that key is applied an even number of times across captured messages — the keys algebraically cancel. The three-pass protocol applies each key exactly twice across the three messages (once to add, once to remove), which is precisely that even-count condition. Reusing a fixed XOR key across passes is equivalent to publishing the key.

## Fix / defense

- Never implement the three-pass protocol over XOR (or any additive/linear operation). Use a commuting cipher that is *not* self-inverse and where intercepting all passes does not let the key terms cancel — e.g. Massey–Omura over a large prime field with secret exponents.
- For "share a secret without a shared key," use established key exchange (ECDH) plus authenticated encryption (AES-GCM), not a hand-rolled commuting cipher.
- Authenticate and integrity-protect every pass so a passive capture of all three messages is not by itself enough to derive the plaintext.
