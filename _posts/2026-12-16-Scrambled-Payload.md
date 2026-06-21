---
title: "Scrambled Payload"
date: 2026-12-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, vbscript, malware, deobfuscation, regex]
description: "A Very Easy reversing challenge built around a layered-obfuscated VBScript dropper that only fires on one specific machine. Unwrap the Chr/Array/base64 layers statically, then recover the target ComputerName as the per-position intersection of three anchored regex character classes — which turns out to be base64 of the flag."
---

## Overview

`Scrambled Payload` is a Very Easy HackTheBox **Reversing** challenge. You are handed a single `payload.vbs` — the "final payload" of a malware campaign that, per the brief, "seems to do nothing, maybe it is targeting a specific device?" It is a multi-layer obfuscated VBScript dropper: peel the layers statically (never run it) and you find it checks the machine's `ComputerName` against a set of anchored regexes. The only name that satisfies every pattern is base64 of the flag.

## The technique

Two reusable ideas stack here:

1. **Layered VBScript deobfuscation.** The script hides COM ProgIDs (`Microsoft.XMLDOM`, `Msxml2.DOMDocument`, `bin.base64`, `WScript.Network`) as `Chr((a*b) mod 256)` products, and carries its next stage as a base64 literal decoded through MSXML's `bin.base64` node. That second stage is a sequence of self-decoding blocks of the form `d="":for i=0to K:d=d+Chr((Array(...)(i) <op>)mod 256):Next:Execute d`, each `Array` scrambled by a per-block operation (`+196`, `*117`, `Xor 183`, `*33`, `*65`, `*103`, `*119`, `*23`) before being `Execute`d. None of it ever has to run — you decode each `Array` in Python to reveal the real logic.

2. **Regex character-class intersection.** The decoded logic reads `WScript.Network.ComputerName` and tests it against **three** anchored 36-character regexes built only of single-char classes, e.g. `^[MSy][FfK][ERT]...$`. Match all three and the script pops `MsgBox("Correct!")`; otherwise `WScript.Quit`. Because every position is constrained independently by each pattern, the accepted string is just the **per-position intersection** of the three classes — each index collapses to exactly one character. No brute force.

## Solution

Decode the layers and intersect the patterns. The full solver:

Create `solve.py`:

```python
#!/usr/bin/env python3
# Scrambled Payload (HTB Reversing) — recover the ComputerName the VBS malware targets.
# Layered obfuscation: Chr((a*b)mod256) string-build -> base64 (MSXML bin.base64) stage2
# -> stage2 has self-decoding `for i=0to N:d=d+Chr((Array(...)(i) <op>)mod256):Next:Execute d` blocks.
# The Execute blocks set RegExp patterns of [charclass] sets tested against ComputerName;
# the only name matching ALL three 36-char patterns = base64(flag). MsgBox "Correct!" on match.
import re, base64
src = open('payload.vbs').read()
stage2 = base64.b64decode(re.findall(r'"([A-Za-z0-9+/=]{40,})"', src)[0]).decode('latin1')

def apply(v, op):
    o, k = re.match(r'(?i)\s*(\+|\*|Xor|And|Or|Mod|-)\s*(\d+)', op).groups()
    o = o.lower(); k = int(k)
    return {'+': v+k, '-': v-k, '*': v*k, 'xor': v^k, 'and': v&k, 'or': v|k, 'mod': v%k}[o] % 256

blocks = re.findall(r'd="":for i=0to (\d+):d=d\+Chr\(\(Array\(([\d,]+)\)\(i\)([^)]*)\)mod 256\):Next:Execute d', stage2)
decoded = [''.join(chr(apply(int(x), op)) for x in arr.split(',')) for _, arr, op in blocks]

def resolve(expr):  # collapse a VBScript &-joined Chr(...)/"..." concat to its literal string
    s = ''; i = 0
    while i < len(expr):
        c = expr[i]
        if c in '& ': i += 1; continue
        if c == '"':
            j = expr.index('"', i+1); s += expr[i+1:j]; i = j+1; continue
        if expr.startswith('Chr(', i):
            depth = 0; j = i+3; start = j
            while j < len(expr):
                if expr[j] == '(': depth += 1
                elif expr[j] == ')':
                    depth -= 1
                    if depth == 0: break
                j += 1
            s += chr(eval(expr[start+1:j].replace('mod 256', '%256').replace('mod', '%')) % 256)
            i = j+1; continue
        i += 1
    return s

pats = [resolve(m.group(1)) for b in decoded for m in re.finditer(r'r\.Pattern=(.*?)(?::If|$)', b)]
classes = [re.findall(r'\[([^\]]+)\]', p) for p in pats if '[' in p]
name = ''.join((set.intersection(*[set(c[i]) for c in classes])).pop() for i in range(len(classes[0])))
print("ComputerName:", name)
print(base64.b64decode(name).decode())
```

Run it against the challenge file:

```bash
python3 solve.py
```

The recovered ComputerName is `SFRCe1NjUjRNQkwzRF9WQl9TY3IxUFQxTkd9`, which base64-decodes to the flag `HTB{...}`.

## Why it worked

The obfuscation is all reversible bijections — character arithmetic, base64, per-block linear/XOR transforms — so it slows a reader down without ever requiring execution. The actual gate is even weaker: expressing the target check as a conjunction of independent single-character-class constraints means each character position is fully pinned by the intersection of the classes. The "scrambled", multi-pattern presentation is camouflage over what is really a closed-form answer.

## Fix / defense

For malware analysts this is the intended workflow — static deobfuscation beats detonation every time, and a check built from independent per-position constraints is trivially invertible. As a defensive note for the *technique being demonstrated*: an environment-keyed payload that derives its target from a recoverable check (here the answer was literally embedded in the regex classes) offers no real protection. Real targeting/anti-analysis uses the environment value as a **key-derivation input** (e.g. decrypt the next stage with a hash of the hostname) so that without the correct machine you never recover the payload at all — there is nothing to intersect. Defensively, treat any script that string-builds `Microsoft.XMLDOM`/`bin.base64`/`WScript.Network` from `Chr()` arithmetic as a high-confidence malicious-dropper signal and analyze it in an isolated, non-executing harness.
