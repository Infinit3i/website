---
layout: post
title: "Protein Cookies 2"
date: 2028-01-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, length-extension, merkle-damgard, mac-forgery]
---

## Overview

Protein Cookies 2 is a Medium **Crypto** challenge wrapped in a small Flask gym site.
Your session cookie is authenticated with a home-made keyed hash, and the flag PDF at
`/program` is only served to a logged-in member. The signing scheme is a custom
[Merkle–Damgård](https://cwe.mitre.org/data/definitions/345.html) hash used as
`MAC = hash(secret || data)` — the textbook setup for a **hash length-extension**
forgery, so we mint a `isLoggedIn=True` cookie without ever learning the secret.

## The technique

The cookie and its check:

```python
def create_cookie(username, is_logged_in=False):
    data = f'user_id={username}&isLoggedIn={is_logged_in}'
    signature = lj12_hash(SECRET + data.encode())     # secret-prefix MAC
    return data + '.' + signature

def verify_cookie(cookie_data):
    data, signature = cookie_data.split(".")
    if lj12_hash(SECRET + data.encode()) == signature:
        return {k: v[-1] for k, v in parse_qs(data).items()}.get('isLoggedIn','') == 'True'
```

`lj12_hash` is Merkle–Damgård: 32-byte blocks, a fixed IV, and a per-block compression
that is just `AES-ECB(block, chaining_state)` with a byte shuffle, chaining the output as
the next block's key — and crucially **no finalization step**. So the returned digest *is*
the raw final chaining state. Two facts make the forgery work:

1. Because the digest leaks the internal state, you can resume hashing from a known
   `(data, digest)` pair and append data — the definition of length extension.
2. `verify_cookie` builds a dict with `v[-1]`, keeping the **last** value of a repeated
   key. Appending a second `&isLoggedIn=True` overrides the original `False`.

Note the standard tools (`hashpumpy`, `hash_extender`) are useless here — they only know
MD5/SHA. You must reimplement the challenge's `compression_function` and `pad` from source.

## Solution

```python
from Crypto.Cipher import AES
import requests

BLOCK = 32
IV = b"@\xab\x97\xca..."                      # from cryptoutil.py

def pad(d):
    if len(d) % BLOCK == 0: return d
    return d + bytes([len(d) % 256]) * (BLOCK - len(d) % BLOCK)

def compress(block, key):
    e = AES.new(key, AES.MODE_ECB).encrypt(block)
    e = e[::-1]; e = e[::2]+e[1::2]; e = e[::3]+e[2::3]+e[1::3]
    return e

# 1. grab a valid guest cookie -> its tag is the chaining state over SECRET||data
c = requests.Session(); c.get(BASE + "/")
data, tag = c.cookies["login_info"].split(".")
state = bytes.fromhex(tag)

# 2. replicate the server's glue pad (SECRET is 50 bytes per source)
total = 50 + len(data)
glue  = bytes([total % 256]) * (BLOCK - total % BLOCK)
ext   = b"&isLoggedIn=True"

# 3. process the appended tail block from the known tag -> forged tag
forged = data.encode() + glue + ext
tail = pad(b"\x00"*50 + forged)[total + len(glue):]
for i in range(0, len(tail), BLOCK):
    state = compress(tail[i:i+BLOCK], state)

cookie = forged.decode("latin-1") + "." + state.hex()

# 4. the forged cookie unlocks the flag PDF
pdf = requests.get(BASE + "/program", cookies={"login_info": cookie}).content
open("flag.pdf", "wb").write(pdf)      # pdftotext -> HTB{...}
```

`GET /program` returns `flag.pdf`, and `pdftotext` reveals the flag.

## Why it worked

A MAC of the form `H(secret ‖ message)` over any Merkle–Damgård hash with no
length-binding finalization exposes its full internal state in the digest, so an
attacker who has one valid `(message, tag)` pair and the secret length can forge tags for
`message ‖ padding ‖ anything`. Rolling a "custom" compression function changes nothing —
it only means you re-implement it by hand instead of using an off-the-shelf tool.

## Fix / defense

Use **HMAC** (`hmac(key, data)`), which is provably immune to length extension, or bind
the total input length into a real finalization step. Never authenticate data with a bare
`hash(secret + data)`.
