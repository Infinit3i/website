---
title: "SecretRezipe"
date: 2027-05-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, crypto, zipcrypto, bkcrack, known-plaintext]
description: "An Easy Misc challenge where the flag is sealed in a ZIP encrypted with `zip -P` — traditional ZipCrypto, not AES. Because the server appends our own input next to the secret, we get a long known-plaintext segment for free and bkcrack recovers the keys in seconds, no password needed."
---

## Overview

`SecretRezipe` is an Easy HackTheBox **Misc** challenge. A small Node service writes our requested "ingredients" into a file alongside a secret recipe, encrypts the file into a password-protected ZIP, and hands it back. The password is a fresh random UUID per request, so it looks safe — but the encryption is **traditional PKWARE ZipCrypto**, which is broken under a known-plaintext attack. And the server gives us the known plaintext itself.

## The technique

`zip -P <password>` uses ZipCrypto by default — a 32-bit stream cipher whose entire keystream is fixed by three internal keys. With roughly 12 contiguous bytes of **known plaintext** at a known offset, [bkcrack](https://github.com/kimci86/bkcrack) recovers those keys and can then decrypt **every** entry in the archive. The password never enters the attack — only the plaintext does. Using a strong, random password is therefore irrelevant; the cipher itself is the [use of a broken or risky cryptographic algorithm](https://cwe.mitre.org/data/definitions/327.html).

The server's own code is what makes this trivial:

```js
// routes.js
let data = `Secret: ${FLAG}`
if (req.body.ingredients) {
  data += `\n${req.body.ingredients}`        // attacker-controlled, appended AFTER the flag
}
fs.writeFileSync(tempPath + '/ingredients.txt', data)
child_process.execSync(`zip -P ${PASSWORD} ${tempPath}/ingredients.zip ${tempPath}/ingredients.txt`)
```

The plaintext is `Secret: HTB{...}\n<our ingredients>`. We control everything after the flag, so we can plant as much known plaintext as we like.

Two practical details decide whether the crack takes an hour or a few seconds:

1. **bkcrack works on the *compressed* stream.** For a deflated entry you'd need the compressed form of the known bytes (deflate is stateful — hard). So we make the entry **STORED** (uncompressed) by sending **high-entropy** ingredients, so our bytes appear verbatim in the encrypted stream.
2. **More known bytes = much faster.** A 12-byte guess at offset 0 (`Secret: HTB{`) can take ~1 hour; a 120-byte controlled segment cracks in ~16 seconds.

## Solution

Create `solve.py`:

```python
import json, urllib.request, zipfile, io, random, subprocess, re

TARGET = "http://<host>:<port>"
BK = "/path/to/bkcrack"                              # built from github.com/kimci86/bkcrack
charset = ''.join(chr(c) for c in range(33, 127))    # high-entropy printable

def post(ingr):
    body = json.dumps({"ingredients": ingr}).encode()
    req = urllib.request.Request(TARGET + "/ingredients", data=body,
                                 headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=20).read()

# 1) regenerate the payload until the entry comes back STORED (method 0)
for seed in range(1, 200):
    random.seed(seed)
    cand = ''.join(random.choice(charset) for _ in range(120))
    zb = post(cand)
    info = zipfile.ZipFile(io.BytesIO(zb)).infolist()[0]
    if info.compress_type == 0:                      # STORED -> raw plaintext maps 1:1
        known, zbytes = cand.encode(), zb
        break
open("known.bin", "wb").write(known)
open("ingredients.zip", "wb").write(zbytes)

name  = info.filename
usize = info.file_size
off   = usize - len(known)        # "Secret: "(8) + FLAG + "\n"(1) + known

# 2) recover the 3 internal keys from the known-plaintext segment
out = subprocess.run([BK, "-C", "ingredients.zip", "-c", name, "-p", "known.bin", "-o", str(off)],
                     capture_output=True, text=True).stdout
keys = re.search(r'([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})', out).groups()

# 3) decrypt the whole entry with the keys, read the flag (no password needed)
subprocess.run([BK, "-C", "ingredients.zip", "-c", name, "-k", *keys, "-d", "plain.bin"])
data = open("plain.bin", "rb").read()
print(re.search(rb'HTB\{[^}]*\}', data).group().decode())
```

Run it against the live instance:

```bash
python3 solve.py
# [*] STORED entry usize=164 known@off=44 flag_len=35
# bkcrack ... Keys: ac70829e e26cac0b d976a2f1   (~16s)
# [*] decrypted head: b'Secret: HTB{...}\n'
# HTB{...}
```

The decrypted file starts with `Secret: ` followed by the flag — recovered live, no password required.

## Why it worked

ZipCrypto's confidentiality depends entirely on three internal keys, which known plaintext over-determines. The server volunteered the rest of the problem: it placed **attacker-controlled data in the same encrypted stream as the secret**, and high-entropy input kept the entry stored so that data became a long, raw known-plaintext segment at a predictable offset. With that, the random per-request password protected nothing.

## Fix / defense

- Use **AES-256** ZIP encryption (e.g. `7z a -tzip -mem=AES256 ...`) or encrypt with a modern AEAD before zipping — ZipCrypto (`zip -P`) is broken regardless of password strength.
- **Never place a secret in the same archive or stream as attacker-controlled or otherwise-known content.**
- Treat ZipCrypto as obfuscation only; its confidentiality is checksum-grade. As the flag puts it: compression — and ZipCrypto — is not encryption.
