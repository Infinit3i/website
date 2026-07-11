---
layout: post
title: "Mr. Abilgate"
date: 2028-02-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, ransomware, aes, cbc, malware, ooxml]
---

## Overview

Mr. Abilgate is a Medium reversing challenge themed around a ransomware incident.
You are handed the ransomware binary (`KeyStorage.exe`) and a single encrypted file
(`ImportantAssets.xls.bhtbr`). The whole challenge is a lesson in why symmetric-only
ransomware that ships its own key is not ransomware at all — it is a reversible cipher.
Recover the AES key baked into the sample, decrypt the file with AES-256-CBC and a zero
IV, and read the flag out of the recovered spreadsheet.

## The technique

Real ransomware generates a per-victim AES key and then *wraps that key under the
attacker's RSA public key*, so only the attacker's private key can ever recover it. This
sample skips that step: the AES-256 file key is simply the SHA-256 of a constant compiled
into the executable. Because the key never leaves the binary, a defender who has the sample
has the key. This is the [use of a hard-coded cryptographic key](https://cwe.mitre.org/data/definitions/321.html)
weakness class ([CWE-321](https://cwe.mitre.org/data/definitions/321.html)).

`KeyStorage.exe` is deliberately annoying to analyse statically:

- **Self-decrypting stub** — the entry point jumps into a byte-copy loop that rewrites its
  own code before the real logic runs.
- **API hashing** — the import table only exposes `LoadLibraryA`, `GetProcAddress`, and
  `VirtualProtect`; every real API (including the crypto calls) is resolved at runtime by
  hash, so the imports tell you nothing.
- **Anti-debug** — it trips when a debugger is attached.

You could fully unpack it and single-step the crypto, but the strings give away the plan:
`"Microsoft Enhanced RSA and AES Cryptographic Provider"` tells us it uses the Windows AES
provider. Windows block ciphers default to **CBC with a zero IV** when you do not set one —
that plus the recovered 32-byte key is everything needed.

## Solution

The recovered AES-256 key material (SHA-256 of the constant baked into the binary):

```
49 3B 94 2E F1 6B F5 9D 72 54 BB 9A 64 6A C3 39
57 8C 8E DE 50 AC C9 D2 0A 13 C6 F1 4F 68 D5 93
```

`solve.py`:

```python
import io, zipfile, re
from Crypto.Cipher import AES

KEY = bytes.fromhex("493B942EF16BF59D7254BB9A646AC339578C8EDE50ACC9D20A13C6F14F68D593")
IV  = b"\x00" * 16                                   # Windows crypto default: zero IV

ct = open("ImportantAssets.xls.bhtbr", "rb").read()
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)      # AES-256-CBC, not ECB
assert pt[:4] == b"PK\x03\x04"                       # OOXML/zip magic -> it's really .xlsx

zf = zipfile.ZipFile(io.BytesIO(pt))                 # the .xlsx is a zip
blob = zf.read("xl/sharedStrings.xml").decode()      # cell strings live here
print(re.search(r"HTB\{[^}]*\}", blob).group(0))
```

```bash
python3 solve.py   # -> HTB{...}
```

Two gotchas trip people up here:

1. **ECB vs CBC.** With a zero IV, block 0 is byte-for-byte identical under ECB and CBC, so
   decrypting the header *looks* right in both modes. Only from block 1 do they diverge — ECB
   produced junk, CBC produced a valid Excel file. Always validate the whole file
   (`file dec.bin` → "Microsoft Excel 2007+"), not just the magic bytes.
2. **`.xls` is a lie.** The recovered bytes start with `50 4B 03 04`, a ZIP header — i.e.
   modern OOXML `.xlsx`, not the old OLE2 `.xls`. Unzip it and the flag is a cell string in
   `xl/sharedStrings.xml`.

## Why it worked

The ransomware's encryption key is recoverable from the sample itself and is never protected
by an asymmetric key. Possession of the binary is therefore equivalent to possession of the
key, so every "encrypted" file can be restored offline with a five-line script. The Windows
CryptoAPI default of CBC-with-zero-IV makes the ciphertext fully deterministic and removes
even the small friction of hunting for an IV.

## Fix / defense

Never derive an encryption key from a constant that ships alongside the ciphertext. A correct
file-encryption envelope generates a random per-file data key and a random IV, then wraps the
data key under an asymmetric public key (RSA-OAEP) or a KMS-held key — so possession of the
client binary does not equal possession of the decryption key.
