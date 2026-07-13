---
layout: post
title: "Vessel Cartographer"
date: 2028-05-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, ransomware, aes-cbc, anti-debug, cwe-321]
description: "A tiny Windows encryptor locks a file to .owo with AES-128-CBC. The key is assembled at runtime and never appears as a string, and the recovered plaintext hides the flag inside an image whose extension lies about its type."
---

## Overview

Vessel Cartographer is a **Hard** HackTheBox **Reversing** challenge. You get a 12.8 KB Windows PE (`challenge.exe`) and one high-entropy blob, `vessel_map.jpeg.owo`. The `.owo` extension marks the binary as a ransomware-style **encryptor**: it locks a file and appends `.owo`. Reversing the cipher recovers the original file, and the flag is rendered inside it. The clean path is to identify the AES routine, recover the runtime-assembled key past the anti-debug, decrypt, and — crucially — trust the file's magic bytes over its lying extension.

## The technique

The encryptor uses **AES-128-CBC** with a **16-null-byte IV**. The giveaway is the AES **S-box** table sitting in the encrypt routine — a reliable fingerprint for AES in a stripped binary. The mode is CBC and the IV buffer is never initialised before the loop, so it is all zeroes.

The 16-byte key `mYq3s6v9y$B&E)H@` is **assembled one byte at a time into a stack buffer at runtime**, so it never exists as a contiguous string in the file — `strings | grep` finds nothing. You recover it by breaking at the AES call in a debugger and dumping the key buffer.

Two anti-debug layers guard that breakpoint:

- **TLS callback** — a function that runs *before* the entry point checks for a debugger. Patch its conditional jump (`jz` → `jnz`) to invert the check.
- **`NtQueryInformationProcess(ProcessDebugFlags)`** — this undocumented "alien" API returns `0` when a debugger is attached and `1` otherwise. The binary branches on it; flip the register so it takes the not-debugged path.

The leetspeak flag `4l13n_5h3llc0d3_d3c1ph3r1ng` is the author naming the lesson: deciphering shellcode that leans on alien/undocumented APIs.

## Solution

With the key recovered, decryption is a one-liner. The only trap left is the file type: the plaintext of `vessel_map.jpeg.owo` is **not a JPEG** — its magic bytes are `89 50 4e 47 0d 0a 1a 0a` = **PNG**. Always identify recovered plaintext with `file(1)`, never the filename.

Create `solve.py`:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

KEY = b'mYq3s6v9y$B&E)H@'
IV  = b'\x00' * 16

data = open('vessel_map.jpeg.owo', 'rb').read()
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(data[:len(data) - (len(data) % 16)])

assert pt[:8].hex() == '89504e470d0a1a0a'
open('vessel_map.png', 'wb').write(pt)
print('recovered PNG — open it and read the flag off the image')
```

```bash
python3 solve.py
```

The recovered PNG is a 1024×1024 image. The flag is **rendered as green "ERROR CODE:" text inside the picture** — not a string in the file — so `strings | grep HTB{` fails. Open the image and read it: `HTB{...}`.

## Why it worked

A "ransomware" whose file key is **recoverable from the sample itself** — baked in, or assembled at runtime and dumpable in a debugger — is not ransomware. It is a reversible symmetric cipher, [CWE-321](https://cwe.mitre.org/data/definitions/321.html) (Use of Hard-coded Cryptographic Key). Real ransomware generates a per-victim data key and seals it under the *attacker's* RSA public key, so possessing the binary tells you nothing. Skipping that step collapses the scheme: possession of the sample equals possession of the key equals decrypting every locked file offline. The anti-debug only slowed the analyst; once the key was in a register it bought nothing.

## Fix / defense

- Never hard-code or locally-derive the file-encryption key. Generate a random per-file (or per-victim) key and wrap it under an asymmetric public key you control.
- Treat anti-debug (TLS callbacks, `NtQueryInformationProcess`) as friction, not a confidentiality control — it does not protect the key material.
- When triaging any recovered artifact, identify it by magic bytes, not by its extension.
