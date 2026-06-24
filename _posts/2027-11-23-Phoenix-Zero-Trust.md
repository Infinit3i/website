---
title: "Phoenix Zero Trust"
date: 2027-11-23 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, mersenne-twister, schnorr, zkp, prng, mt19937, state-clone, zero-knowledge]
description: "Easy Crypto challenge: rand_mt::Mt is MT19937, not a CSPRNG. Collect 624 outputs, untemper, predict the next Schnorr challenge, forge the ZK proof with z=1."
---

## Overview

Phoenix Zero Trust is an easy Crypto challenge presenting a Schnorr Identification Protocol (zero-knowledge proof) login service written in Rust. The challenge generator is typed as `CSRNG` in the source but is actually `rand_mt::Mt` — `Mt19937GenRand32`, the textbook Mersenne Twister. Because MT19937 is [not a cryptographically secure PRNG](https://cwe.mitre.org/data/definitions/338.html), any 624 consecutive 32-bit outputs expose the full internal state. The attack collects ten Schnorr challenges (640 u32 outputs), reconstructs the MT state, predicts the eleventh challenge, and forges a valid Schnorr proof without the private key.

## The Technique

### Schnorr Identification (quick primer)

The server holds a public key `h = g^x mod p` (with `x` the private key). To log in:

1. Prover sends a commitment `u = g^r mod p` (random `r`).
2. Verifier sends a random challenge `c`.
3. Prover responds with `z = r + c*x mod q`.
4. Verifier checks `g^z == u * h^c mod p`.

The soundness of the scheme depends entirely on `c` being **unpredictable before** the prover sends `u`. If an attacker can predict `c` in advance, they can choose any `z`, compute a matching `u`, and pass the check without knowing `x`.

### Why MT19937 breaks this

MT19937 has a 624-word (19968-bit) internal state. The temper transform that converts raw state words to output is invertible — given any 624 consecutive 32-bit outputs, `untemper` recovers the raw state word-for-word. From there, `mt_generate` produces the next 624-word batch, and every future output is known.

The challenge's `gen_biguint_range(1, p)` call draws exactly **64 u32 values** per challenge (little-endian 32-bit digits of a 2048-bit value). Ten challenges → 640 u32 outputs: enough to clone state and predict challenge eleven.

### Forging the Schnorr proof

With `c_pred` known before we send `u`:

- Choose `z = 1`.
- Compute `u = g^1 · h^(-c_pred) mod p`.

Verifier check: `g^z = g^1 = g` and `u · h^c = g · h^(-c) · h^c = g`. ✓ No private key needed.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

N, M = 624, 397
MATRIX_A  = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff

def untemper(y):
    y &= 0xFFFFFFFF
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9d2c5680)
    y = tmp & 0xFFFFFFFF
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    return tmp & 0xFFFFFFFF

def temper(y):
    y &= 0xFFFFFFFF
    y ^= y >> 11
    y ^= (y << 7)  & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & 0xFFFFFFFF

def mt_generate(state):
    s = list(state)
    for i in range(N):
        y = (s[i] & UPPER_MASK) | (s[(i+1) % N] & LOWER_MASK)
        s[i] = s[(i+M) % N] ^ (y >> 1) ^ (MATRIX_A if y & 1 else 0)
    return s

# RFC 7919 2048-bit safe prime
p = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
q = (p - 1) // 2
g = 2
# overwatch's public key (2042 bits — verify h.bit_length() == 2042)
h = int("367B52629C047F43399DDA8553BC3B90B82DA68313A5609E00BD9CEFB88837D2"
        "3086C613711C774502547AC033E7BDF6FCF85861414238FBA83404BFD1EBB9AAC"
        "99F41B6E2F1670AF46759707521287164B713FC1068ACB2D2EC81D9FA548525B6"
        "583425054CD3B594A1ED358D98F04A96AFF6E9981F022FA99B4CADB98443AA72C"
        "8C07335D497B9FCB24FAE941ED60480D0632B720A6FF2A94E2443078055EB7C43"
        "51964BEF56228E59522DDC81D1EF515F85AF9A9A4F8D9248E9CC668B82C66B8BE"
        "82618739C360B318C9E38F1BE1AA2DE6679995EF6DF0F5BA7ABCD08D8C7DD6ACE"
        "B81D613E7C199BAD4423B1E0A02B00489BA5243CF4D38ECFC48BD36AC", 16)

HOST, PORT = "{{rhost}}", {{port}}

def do_login(conn, username, u_val, z_val):
    conn.recvuntil(b'\n> '); conn.sendline(b'2')
    conn.recvuntil(b'Username: '); conn.sendline(username.encode())
    conn.recvuntil(b'Commitment u (g^r mod p): '); conn.sendline(str(u_val).encode())
    line = conn.recvline().decode().strip()
    c = int(line.split('Challenge c: ')[1].strip())
    conn.recvuntil(b'Response z (r + c*x mod p): '); conn.sendline(str(z_val).encode())
    resp = conn.recvline().decode().strip()
    return c, resp

def challenge_to_words(c):
    v = c - 1   # gen_biguint_range(1,p) = 1 + raw; raw = c-1
    return [(v >> (32*i)) & 0xFFFFFFFF for i in range(64)]

def main():
    conn = remote(HOST, PORT, level='error')
    conn.recvuntil(b'*. exit\n')

    all_words = []
    for _ in range(10):
        c, _ = do_login(conn, 'overwatch', 2, 1)
        all_words.extend(challenge_to_words(c))

    # Reconstruct batch 1, generate batch 2
    batch1 = [untemper(all_words[i]) for i in range(624)]
    batch2 = mt_generate(batch1)

    # Challenge 11 uses batch2 indices 16..79
    c_pred = 1 + sum(temper(batch2[16+i]) << (32*i) for i in range(64))

    # Forge: z=1, u = g * h^(-c_pred) mod p
    z, h_inv = 1, pow(h, p-2, p)
    u = pow(g, z, p) * pow(h_inv, c_pred, p) % p

    conn.recvuntil(b'\n> '); conn.sendline(b'2')
    conn.recvuntil(b'Username: '); conn.sendline(b'overwatch')
    conn.recvuntil(b'Commitment u (g^r mod p): '); conn.sendline(str(u).encode())
    line = conn.recvline().decode().strip()
    c_recv = int(line.split('Challenge c: ')[1].strip())
    assert c_recv == c_pred, f"prediction mismatch: {c_recv} != {c_pred}"
    conn.recvuntil(b'Response z (r + c*x mod p): '); conn.sendline(str(z).encode())
    print(conn.recvline().decode().strip())
    conn.close()

if __name__ == '__main__':
    main()
```

Running against the live instance prints the flag.

## Why It Worked

The `rand_mt::Mt` type alias `CSRNG` in the source has no effect on the underlying algorithm — naming a [use of a cryptographically weak PRNG](https://cwe.mitre.org/data/definitions/338.html) something else does not make it secure. MT19937's temper transform is a bijection on 32-bit integers, so `untemper` recovers the raw state word exactly. Once the 624-word state is reconstructed, the deterministic `mt_generate` twist produces every future output.

The Schnorr scheme's [ZKP soundness](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/) relies on the challenge being chosen **after** the commitment is fixed. By predicting `c` before sending `u`, we decouple `u` from any secret and satisfy the verification equation with an arbitrary `z`.

### The bit-length footgun

When copying a long hex literal across Python string lines, silently dropping a hex nibble shifts every subsequent byte and produces a wrong `h` value. The MT prediction was correct (`c_recv == c_pred`), but authentication still failed — the only variable left was `h`. Fix: always verify `h.bit_length() == 2042` (matching the Rust source literal's bit length) before running the forge step.

## Fix / Defense

Replace `rand_mt::Mt` with a real CSPRNG:

```rust
// Vulnerable
use rand_mt::Mt as CSRNG;
let mut rng = CSRNG::from_entropy();

// Fixed
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
let mut rng = ChaCha20Rng::from_rng(OsRng).unwrap();
```

`ChaCha20Rng` (or `OsRng` directly) provides cryptographic security guarantees that MT19937 does not. No finite number of observed outputs can predict future outputs of a properly seeded ChaCha20 stream.
