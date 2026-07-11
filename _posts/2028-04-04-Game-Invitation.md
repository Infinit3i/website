---
layout: post
title: "Game Invitation"
date: 2028-04-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, maldoc, vba, docm, rc4, xor, olevba, cwe-506]
description: "A macro-enabled Word document hides its payload as raw bytes appended after a marker, carved by the VBA with an evolving XOR keystream, then peeled through an eval(RC4(base64)) JavaScript dropper. Reverse the whole chain offline and the flag falls out of a hardcoded Cookie header."
---

## Overview

Game Invitation is a Hard HackTheBox Forensics challenge. You get a single file — `invitation.docm`, a macro-enabled Word document — and nothing else. It is a malicious-document (maldoc) reversing task, and the trick that earns the "Hard" rating is that the real payload is **not in the VBA macro at all**: it is a blob of bytes appended to the end of the document, and the macro carves it out of its own file, decrypts it with an evolving XOR keystream, and hands off to a JavaScript dropper that hides its logic behind base64 + RC4. The whole thing is solved statically — you never let the document run. This is [CWE-506](https://cwe.mitre.org/data/definitions/506.html) — embedded malicious code.

## The technique

Multi-stage droppers layer their obfuscation so that each stage only reveals the next when decoded:

1. **VBA `AutoOpen`** reads the document's own bytes, regex-locates a long random **80-character marker** string, reads the bytes right after it, and decrypts them with a **single-byte XOR whose key changes every byte** (a keystream, not a constant).
2. The decrypted **JavaScript dropper** runs `eval(RC4(argument, base64_decode(embedded)))`, where the RC4 key is the command-line argument the macro passed it.
3. The final stage is a **C2 recon downloader** — and it stashes the flag as a hardcoded HTTP request header.

## Solution

Dump the VBA without executing anything, using `olevba` from oletools:

```bash
olevba invitation.docm
```

Two functions matter. `JFqcfEGnc` is the decryptor with an **evolving** key:

```vb
xor_key = 45
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
```

And `AutoOpen` reads the document's own bytes, finds an 80-char marker with a regex, reads 13083 bytes after it (`Get #f, FirstIndex + 81`), decrypts them, writes the result to `%APPDATA%\Microsoft\Windows\mailform.js`, and runs it with an argument that turns out to be the RC4 key.

The one offset subtlety: VBA's `FirstIndex` is a 0-based index, and `Get FirstIndex+81` (1-based) lands exactly at `data.find(marker) + len(marker)` because the marker is 80 bytes long. The stage-2 JS ends with `eval(xR68(WScript.Arguments(0), JrvS(lyEK())))` — `xR68` is standard RC4, `JrvS` is base64 decode, `lyEK` returns the embedded ciphertext. Reproduce both stages in Python:

Create `solve.py`:

```python
import re, base64

DOCM = "files/invitation.docm"
MARKER = b"<80-char-marker-from-the-macro>"
KDX = 13082

def stage1_xor(buf):
    out = bytearray(len(buf)); k = 45
    for i in range(len(buf)):
        out[i] = buf[i] ^ k
        k = ((k ^ 99) ^ (i % 254)) & 0xff
    return bytes(out)

def rc4(key, data):
    S = list(range(256)); j = 0; key = [ord(c) for c in key]
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256; S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) % 256; j = (j + S[i]) % 256; S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

data = open(DOCM, "rb").read()
i = data.find(MARKER) + len(MARKER)
mailform = stage1_xor(data[i:i + KDX + 1])

b64 = re.search(rb'function lyEK\(\)\{var r="([^"]+)"', mailform).group(1).decode()
stage3 = rc4("<rc4-key-from-macro-argument>", base64.b64decode(b64))

cookie = re.search(rb'Cookie:","flag=([^"]+)"', stage3).group(1)
print("FLAG:", base64.b64decode(cookie).decode().strip())
```

Run it:

```bash
python3 solve.py
```

Stage 3 is a full C2 recon downloader (`systeminfo`, `net view`, `tasklist`, exfil over HTTP), and buried in its request builder is a hardcoded header:

```js
S47T.SETREQUESTHEADER("Cookie:","flag=<base64>");
```

Base64-decode that value and the flag appears:

```
HTB{...}
```

## Why it worked

Appending the payload to the file — instead of embedding it in the macro stream — defeats analysts (and simple tooling) that only read the VBA: the macro itself is short and looks almost benign, and the malicious code is just data sitting past a marker. The evolving XOR keystream carries state across bytes, so a naive single-byte-key guess fails; you have to replicate the exact recurrence. And the `eval(RC4(base64))` JavaScript shape, with the launch argument doubling as the RC4 key, is a classic way to keep the final stage unreadable until runtime.

## Fix / defense

- Disable Office macros by Group Policy; open untrusted documents in Protected View.
- Triage every `.docm` with `olevba` before opening — alert on `AutoOpen` combined with reading `ActiveDocument.FullName` as Binary and `CreateObject("WScript.Shell")`.
- Block `wscript.exe` / `cscript.exe` from executing files under `%APPDATA%` via WDAC or AppLocker, which breaks this dropper's persistence and execution step.
