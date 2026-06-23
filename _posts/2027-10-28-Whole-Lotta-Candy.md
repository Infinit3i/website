---
layout: post
title: "HackTheBox: Whole Lotta Candy"
date: 2027-10-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ctr, keystream-reuse, known-plaintext, broken-crypto, cwe-323]
---

Whole Lotta Candy is an Easy **Crypto** challenge: a TCP service lets you encrypt either a secret flag or your own plaintext under a per-connection AES key, in a cipher mode that is randomized for each connection. The catch is that the service lets *you* choose the mode, and its AES-CTR implementation restarts its counter at zero on every call — so the keystream repeats, and a single known plaintext peels the flag straight out with nothing but XOR.

## Overview

The server hands you a menu over a raw TCP socket. It builds one `Encryptor()` — one random 128-bit AES key — per connection and offers: (1) encrypt the `FLAG`, (2) encrypt an attacker-supplied plaintext, (3) change the AES mode. The mode is meant to be a surprise (`random.choice` of `ECB/CBC/CFB/OFB/CTR`), but option 3 reseeds it from a list **you** provide, so you can pin it to CTR. CTR is the one mode here whose keystream is reusable, and that reuse is a textbook [reused-keystream](https://cwe.mitre.org/data/definitions/323.html) ("two-time pad") failure. Recover the keystream from a known plaintext, XOR it into the flag ciphertext, done.

## The technique

A stream cipher (or a block cipher in a streaming mode like CTR) produces a **keystream** that is a pure function of `(key, nonce/counter)` and byte offset, then XORs it with the plaintext to make ciphertext:

```
ct = pt ⊕ KS        where  KS = AES_k(ctr0) || AES_k(ctr0+1) || ...
```

If two different messages are ever encrypted under the **same** `(key, nonce)`, they share the identical `KS`. XOR the two ciphertexts and the keystream cancels:

```
ct_known = known ⊕ KS   ⇒   KS   = ct_known ⊕ known
ct_flag  = FLAG  ⊕ KS   ⇒   FLAG = ct_flag  ⊕ KS
```

No key recovery, no factoring, no oracle — just a single known plaintext of sufficient length.

The bug that makes this exploitable here is in the CTR routine:

```python
def CTR(self, pt):
    counter = Counter.new(128)            # no nonce, no prefix → starts at 0 EVERY call
    cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(pad(pt, 16))
```

`Counter.new(128)` initializes the counter to `0` on every single encryption, and the key is fixed for the whole connection — so the keystream is byte-for-byte identical for every message you encrypt. (`CBC`/`CFB`/`OFB` each draw a fresh random IV, so their keystreams differ; CTR is the only reusable one, which is why we force it.)

## Solution

In one connection: force CTR via option 3, encrypt the flag, encrypt a long known plaintext, then XOR.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, json, sys

def recv_until(s, marker=b"> "):
    buf = b""
    while marker not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf

def get_ct(s, payload):
    s.sendall((json.dumps(payload) + "\n").encode())
    buf = b""
    while b"ciphertext" not in buf and b"error" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    for line in buf.split(b"\n"):
        line = line.strip().lstrip(b"> ").strip()
        if line.startswith(b"{"):
            try:
                j = json.loads(line)
            except Exception:
                continue
            if "ciphertext" in j:
                return bytes.fromhex(j["ciphertext"])
            if "error" in j or j.get("response") == "error":
                raise RuntimeError(j)
    raise RuntimeError("no ct in: " + repr(buf))

def main(host, port):
    s = socket.socket(); s.settimeout(10); s.connect((host, port))
    recv_until(s, b"> ")

    s.sendall(b'{"option": "3"}\n'); recv_until(s, b"modes: \n")
    s.sendall(b'{"modes": ["CTR"]}\n'); recv_until(s, b"> ")

    ct_flag = get_ct(s, {"option": "1"})

    known = b"A" * (len(ct_flag) + 16)
    s.sendall(b'{"option": "2"}\n'); recv_until(s, b"plaintext: \n")
    ct_known = get_ct(s, {"plaintext": known.decode()})

    keystream = bytes(c ^ p for c, p in zip(ct_known, known))
    flag = bytes(c ^ k for c, k in zip(ct_flag, keystream))
    print(flag.decode(errors="replace"))
    s.close()

if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
```

Run it against the instance:

```bash
python3 solve.py <ip> <port>
# HTB{...}
```

The flag prints from the live solve. (Value redacted here.)

## Why it worked

CTR confidentiality depends entirely on never reusing a `(key, nonce/counter)` pair. A fixed counter under a reused key *is* a repeated keystream, and a stream cipher with a repeated keystream offers zero secrecy against a known-plaintext attacker: one message of the right length exposes the full keystream and therefore every other message encrypted with it — including the flag. Letting the client choose the cipher mode just hands the attacker the ability to select the one mode where this holds.

## Fix / defense

- **Never reuse a `(key, nonce/counter)` pair** with CTR. Generate a fresh random nonce per message and transmit it with the ciphertext: `AES.new(key, AES.MODE_CTR, nonce=os.urandom(8))`, or `Counter.new(64, prefix=os.urandom(8))`.
- Prefer an **AEAD** mode (AES-GCM / ChaCha20-Poly1305) that binds a unique nonce and authenticates — misuse-resistant and tamper-evident.
- Don't let the client pick the cipher mode; and never let one party obtain both `E(secret)` and `E(chosen)` under a single key+nonce.

This is [CWE-323: Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html).
