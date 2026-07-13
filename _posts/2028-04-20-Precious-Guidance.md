---
layout: post
title: "Precious Guidance"
date: 2028-04-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, vbscript, malware, deobfuscation, dropper, dotnet, cwe-506]
description: "A 2.2 MB obfuscated VBScript hides every stage as an integer array run through one decoder. Reimplement that decoder in Python, dodge a prefix-matching decoy array, and the dropped .NET assembly hands you the flag as a hex string in its Backdoor constructor."
---

## Overview

Precious Guidance is a Medium HackTheBox Forensics challenge. You are handed a single file, `SatelliteGuidance.vbs` — a 2.2 MB heavily-obfuscated VBScript malware dropper. Every real instruction is stored as an array of integers that one decoder function turns back into code, buried under noise bytes and decoy arrays. The path to the flag is to reimplement that decoder offline, recover the dropped .NET assembly, and read the flag out of its constructor. You never run the malware.

## The technique

All of the real code is hidden the same way: it is stored as an integer array and passed through a single decoder function (named `polymerase`). For each element `v` the decoder appends `ChrW(v - 9)`. The offset `9` is itself hidden behind dead arithmetic — `(6842-6781.0)-(89+(-(37+0.0)))` evaluates to `9`. Elements equal to the sentinel `999999` decode to a *random* character (via `Rnd`), pure noise whose only purpose is to break a naive byte-for-byte decoder.

```vbs
Function polymerase(a)
  For i = LBound(a) To UBound(a)
    If a(i) = 999999 Then s = s & ChrW(Int((hi-lo+1)*Rnd+lo))   ' random noise
    Else s = s & ChrW(a(i) - 9) : End If                        ' real byte, offset 9
  Next
  polymerase = s
End Function
execute(polymerase(realArray))
```

Only the arrays wrapped in `execute(polymerase(...))` are live code. The file is padded with hundreds of decoy arrays — and, crucially, several of them share a *prefix* with the real payload to mislead anyone who extracts the first array they see. This is a classic embedded-malicious-code obfuscation ([CWE-506](https://cwe.mitre.org/data/definitions/506.html)) whose entire defense is volume.

## Solution

The whole solve is one Python script that reimplements `polymerase`, decodes the executed stages, and re-extracts the dropped DLL. Do **not** execute the VBScript to deobfuscate it.

Create `solve.py`:

```python
#!/usr/bin/env python3
import re, sys

txt = open("files/SatelliteGuidance.vbs", "r", errors="replace").read()
lines = txt.split("\n")

# scalar table: const NAME = NUM  /  NAME = NUM
scalars = {}
for l in lines:
    m = re.match(r'^\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*(-?\d+)\s*$', l)
    if m:
        scalars[m.group(1)] = int(m.group(2))

# array table: NAME = Array( ... )
arrays = {}
for m in re.finditer(r'([A-Za-z_]\w*)\s*=\s*Array\(([^)]*)\)', txt):
    arrays[m.group(1)] = [t.strip() for t in m.group(2).split(",")]

def tok_val(t):
    if re.fullmatch(r'-?\d+', t):
        return int(t)
    return scalars.get(t)

def polymerase(varname):
    out = []
    for t in arrays.get(varname, []):
        v = tok_val(t)
        if v is None or v == 999999:
            continue
        out.append(chr(v - 9))
    return "".join(out)

exec_vars = [m.group(1) for l in lines
             for m in re.finditer(r'execute\(polymerase\(([A-Za-z_]\w*)\)\)', l)]

if "--dll" in sys.argv:
    stage = polymerase("FaHw")   # the dropper stage
    m = re.search(r'For Each HCZ in Array\((.*?)\)\s*\n\.WriteText polymerase', stage, re.S)
    out = bytearray()
    for t in (x.strip() for x in m.group(1).split(",")):
        v = tok_val(t)
        if v is None or v == 999999:
            continue
        out.append((v - 9) & 0xFF)
    open("files/textual.m3u", "wb").write(out)
    print(f"DLL {len(out)} bytes header={bytes(out[:2])}")
    sys.exit(0)

for i, v in enumerate(exec_vars):
    print(f"\n===== stage {i} : {v} =====")
    print(polymerase(v))
```

Run it to recover the ~19 decoded stages:

```bash
python3 solve.py > stages.txt
```

The stages implement sandbox checks (core count, disk size, script name) and a dropper. The dropper writes a .NET DLL to `%TEMP%\textual.m3u` via an `ADODB.Stream` (`Type = 2`, `Charset = "ISO-8859-1"`, one `.WriteText` per byte) and launches it with:

```text
rundll32 textual.m3u,DllRegisterServer
```

Here is the trap. The DLL bytes are an **inline 8192-element `Array()` that appears only inside the decoded dropper stage** — not the same-named top-level array (2259 elements) that begins identically. Extracting the top-level decoy yields a truncated, broken PE whose on-disk size disagrees with its own section table. Pull the array from the *decoded* code and check it:

```bash
python3 solve.py --dll
file files/textual.m3u
# PE32 executable ... Intel i386 Mono/.Net assembly, 3 sections
rabin2 -S files/textual.m3u   # sanity-check the section table vs file size
```

The dropped `textual.m3u` is a small Mono/.NET assembly. Decompile it and read the `Backdoor` class constructor, which assembles the flag as a `StringBuilder` of hex chunks:

```bash
cp files/textual.m3u textual.dll
ilspycmd textual.dll
```

```csharp
h = new StringBuilder("4854427b54724176456c5f4775");
h.Append("4964416e63455f41667445725f");
h.Append("4c6966457d");
```

Concatenate the chunks and hex-decode to recover the flag:

```python
bytes.fromhex("4854427b54724176456c5f4775"
              "4964416e63455f41667445725f"
              "4c6966457d").decode()
# HTB{...}
```

## Why it worked

The obfuscation is entirely about volume, not strength. A trivial `chr(v - 9)` transform is buried under random-noise sentinel elements, hundreds of decoy arrays, and dead sandbox logic — enough to stop casual static review and any decoder that trusts byte counts. Reimplementing the single decoder collapses every layer at once. The one genuine snag is the decoy array that shares a prefix with the real DLL payload; the fix is to extract the payload from the decoded code (8192 bytes) rather than the source-level array (2259 bytes) and to verify the resulting PE against its own section table.

## Fix / defense

This is malware analysis, so the "fix" is detection rather than a code change:

- Alert on a script host (`wscript.exe` / `cscript.exe`) assembling an `MZ`/PE header byte-by-byte from numeric arrays, and on `rundll32.exe` running a non-`.dll` extension out of `%TEMP%`.
- Enable AMSI and PowerShell/script-block logging so the decoded stages are captured even when the on-disk VBScript is obfuscated.
- Constrain `rundll32` to signed DLLs with expected extensions via WDAC/AppLocker, and egress-filter the dropper's stager.
