---
title: "Reminiscent"
date: 2027-02-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, memory, volatility, powershell, malware]
description: "An Easy Forensics challenge: a recruiter opens a malicious resume and a memory dump is captured. The infection is a fileless PowerShell stager whose -enc command line sits in RAM as plaintext — carve it, decode the UTF-16LE base64, and the flag is embedded in the Empire stager."
---

## Overview

**Reminiscent** is an Easy HackTheBox **Forensics** challenge. You get a memory
dump of an infected Windows 7 VM (`flounder-pc-memdump.elf`, a VirtualBox ELF core
dump) plus the phishing email (`Resume.eml`) that started it. The path to the flag
is a single idea: the malware is a fileless PowerShell stager, and PowerShell's
`-enc` command line lives in RAM as plaintext — so you can carve it with `strings`,
decode the base64 as UTF-16LE, and read the flag straight out of the decoded stager.

## The technique

When PowerShell runs with `-enc <base64>`, the entire command line is stored in
memory as readable text. Two facts make this trivial to recover from a raw dump:

1. The launcher (`powershell.exe -noP -w 1 -enc <blob>`) is plaintext — no Volatility
   profile or symbol resolution required.
2. PowerShell's `-enc` argument is **always** Base64 of a **UTF-16LE** string.

So a `strings | grep` for the launcher plus a one-line decode reconstructs the
attacker's script. This box nests two stages, but each is just base64 you peel.

## Solution

Read the email — it lures the victim into downloading `resume.zip` from an attacker
host. That zip drops `resume.pdf.lnk`, which launches PowerShell. Carve the launcher
lines out of the dump:

```bash
strings -n 8 flounder-pc-memdump.elf \
  | grep -iE 'FromBase64String|powershell.*-(e|enc|encodedcommand)|-nop.*-w.*hidden'
```

This reveals the chain:

- **Stage 1 (ASCII base64):** `powershell -win hidden -Ep ByPass` runs a loader that
  opens `resume.pdf.lnk`, seeks to a fixed offset/length inside it, `FromBase64CharArray`
  → Unicode → `iex` — the `.lnk` is a polyglot carrying the next stage in its body.
- **Stage 2 (UTF-16LE base64):** `powershell -noP -sta -w 1 -enc <BIG_BLOB>` — a
  PowerShell Empire HTTP stager (RC4 key, WebClient beacon) that embeds the flag
  literally as `$flag='HTB{...}'`.

Carve the `-enc` blob and decode it as UTF-16LE to drop out the flag:

Create `solve.py`:

```python
import base64, re, sys

DUMP = sys.argv[1] if len(sys.argv) > 1 else "flounder-pc-memdump.elf"
data = open(DUMP, "rb").read()

m = re.search(rb"-e(?:nc|ncodedCommand)?\s+([A-Za-z0-9+/=]{200,})", data)
b64 = m.group(1)
b64 = b64[: len(b64) - (len(b64) % 4)]
script = base64.b64decode(b64).decode("utf-16-le", "replace")

flag = re.search(r"HTB\{[^}']+\}", script)
print("FLAG:", flag.group(0) if flag else "NOT FOUND")
```

```bash
python3 solve.py flounder-pc-memdump.elf
# FLAG: HTB{...}
```

## Why it worked

The attacker's obfuscation — base64, UTF-16 encoding, a `.lnk` polyglot, nested
stages — is meant to defeat casual inspection of files on disk. But execution leaves
the launcher command line in memory verbatim, and every encoding choice is
deterministic. Recovering the payload is just peeling known encodings, not breaking
anything.

## Fix / defense

- Enable **PowerShell Script Block Logging** and Module Logging (Event ID 4104) — it
  records the *decoded* script at execution time regardless of `-enc`, so the stager
  is captured even when the command line is obfuscated.
- Alert on `powershell -enc` / `-w hidden` / `FromBase64String` spawned as a child of
  Office or Explorer — the classic phishing macro/`.lnk` execution chain.
- Treat zip-of-`.lnk` and double-extension names like `resume.pdf.lnk` as high-risk at
  the mail gateway.
