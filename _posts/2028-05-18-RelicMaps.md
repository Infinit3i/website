---
layout: post
title: "Relic Maps"
date: 2028-05-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, malware-analysis, onenote, batch-obfuscation, powershell, aes-cbc, dotnet, reflective-loading]
description: "A OneNote lure, an obfuscated batch dropper, a base64 blob hidden in a comment, and a reflectively-loaded .NET assembly — unpacked statically, no Windows required."
---

## Overview

Relic Maps is a **Medium** HackTheBox **Forensics** challenge (Cyber Apocalypse 2023). The
target is a Flask/Werkzeug web app, but nothing on it is "hacked" — it merely **hosts** a staged
malware lure. The work is pure static analysis: deobfuscate a Windows batch dropper, follow its
PowerShell to a hidden base64 blob, decrypt and decompress it into a .NET assembly, and read the
flag out of the assembly.

## The technique

The app serves a chain of files:

- `/relicmaps.one` — the initial OneNote lure
- `/uploads/soft/topsecret-maps.one` — a second-stage OneNote
- `/get/DdAbds/window.bat` — the obfuscated dropper (the load-bearing artifact)

`window.bat` is obfuscated with cmd.exe **variable substitution**: `set "eFlP=set "` makes
`%eFlP%` expand to `set `, so every following `%eFlP%"NAME=VAL"` line defines a one-token
variable, and the **last line** is a huge `%VAR%%VAR%...` concatenation that expands into the real
PowerShell command.

That PowerShell reads its **own file**, extracts the base64 blob on the line starting with `":: "`
(a batch comment used as a ciphertext store), then runs a fixed unpack chain:

```
FromBase64String(blob)
 → AES-256-CBC decrypt (PKCS7)     # Key + IV are base64 literals in the script
 → GZipStream decompress
 → [Reflection.Assembly]::Load(bytes) ; EntryPoint.Invoke()   # fileless .NET
```

API names are hidden by string reversal — e.g. `'gnirtS46esaBmorF'[-1..-16] -join ''` spells
`FromBase64String`, `'daoL'[-1..-4]` spells `Load`. The AES **Key and IV are regenerated on every
deploy**, so they must be parsed out of the script each run, never hardcoded.

## Solution

Deobfuscate the batch by emulating cmd variable expansion in Python:

```python
import re
vars = {}
def expand(s):
    for _ in range(50):
        ns = re.sub(r'%([A-Za-z0-9_]+)%', lambda m: vars.get(m.group(1), m.group(0)), s)
        if ns == s: break
        s = ns
    return s
setre = re.compile(r'^\s*set\s+"([^=]+)=(.*)"\s*$')
lines = open('window.bat', errors='replace').read().split('\n')
for ln in lines:
    m = setre.match(expand(ln))
    if m: vars[m.group(1)] = m.group(2)
open('deob_ps.txt', 'w').write(expand(lines[-1]))   # reconstructed PowerShell
```

Then run the unpack chain:

```python
import base64, gzip, re
from Crypto.Cipher import AES

bat  = open('window.bat', errors='replace').read().split('\n')
blob = next(l[3:].strip() for l in bat if l.startswith(':: '))
ps   = open('deob_ps.txt').read()
key  = base64.b64decode(re.search(r"\.Key = .*?\('([^']+)'\)", ps).group(1))
iv   = base64.b64decode(re.search(r"\.IV = .*?\('([^']+)'\)", ps).group(1))

pt  = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(blob))
pt  = pt[:-pt[-1]]                          # strip PKCS7
asm = gzip.decompress(pt)                   # .NET PE (MZ / 4d5a)
print(re.search(r'HTB\{[^}]+\}', asm.decode('utf-16-le', 'ignore')).group())
# -> HTB{...}
```

The payload is a small .NET assembly; the flag is a UTF-16LE string baked into it (`strings -e l`
or `ilspycmd` recover it just as well).

## Why it worked

Every layer here is reversible with material the sample carries itself: the batch variables define
their own expansion, the ciphertext lives in a comment, and the AES key/IV are literals in the
script. Malware has to be self-contained to run on the victim, so a patient analyst always has
everything needed to unpack it statically — no Windows execution required.

## Fix / defense

- Treat `.one` (OneNote) attachments as executable lures — they embed scripts and are a known
  phishing vector; block or sandbox them at the mail gateway.
- Alert on `cmd.exe` spawning `powershell.exe -ep bypass -windowstyle hidden`, and on PowerShell
  using `[Reflection.Assembly]::Load` (fileless .NET execution).
- String-reversal / char-array reconstruction of API names in scripts is a strong obfuscation
  signal for AMSI/EDR heuristics.
