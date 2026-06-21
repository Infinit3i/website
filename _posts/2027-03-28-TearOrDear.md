---
title: "Tear Or Dear"
date: 2027-03-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, dotnet, winforms, crackme, mono, cwe-656]
description: "An Easy Reversing challenge: a .NET WinForms login crackme buries its credential check under junk pointer math and decoy helpers. Decompiling with ilspycmd collapses it to a tiny gate, and the prompt's 'false positives' warning turns out to be three fixed points of a string-mapping function — the real flag being the deepest fallback branch."
---

## Overview

Tear Or Dear is an Easy Reversing challenge: a single 32-bit .NET (Mono/WinForms) login window. The goal is to recover the accepted username and password and submit them as `HTB{username:password}`. The whole challenge hangs on its own hint — *"It can produce false positives"* — because the validation accepts several credential pairs, and only one is the real flag.

## The technique

.NET compiles to IL, which decompiles cleanly back to readable C#. The validation logic is heavily obfuscated, so the work is separating signal from deliberate noise. The obfuscation here is twofold:

- **Dead pointer math** — helpers like `kapa()`/`expo()`/`via()` do a flurry of `unsafe int*` writes to build a string, but it gets overwritten before it's ever used. Pure misdirection.
- **Decoy helper chains** — `check1 → check2 → check3 → check4 → check` and `encrypted1/10/11` look load-bearing but mostly return constants.

Trace it by hand, ignore the dead writes, and `LoginForm.button1_Click` collapses to:

```
accepted  ⇔  textBox_user == aa  AND  textBox_pass == encrypted10(pass)
```

`aa` resolves to a constant: `encrypted1` ignores its argument and hardcodes `"1hpip"`, which `Multiply(s, -1)` reverses to `"piph1"`, then the code drops the last char → **`aa = "piph"`**. The password check needs `pass == encrypted10(pass)` — a **fixed point** of a string-mapping function. There are three: `dire`, `roiw`, and `roiw!@#`. Those three are the "false positives." This is textbook [reliance on security through obscurity](https://cwe.mitre.org/data/definitions/656.html): the secret is just string identities baked into the client.

## Solution

Decompile and read the handler:

```bash
ilspycmd TearORDear.exe > src.cs   # monodis / ikdasm also work on Kali
```

Confirm findings headlessly without a display (WinForms hangs under bare mono). Two approaches: copy the validation methods verbatim into a console program and run them, or drive the real binary with a reflection harness under `xvfb-run` — correct creds block on a `MessageBox.Show("Correct!")`, which is itself an accept oracle (the process hangs instead of returning).

The durable artifact is a Python reimplementation of the reduced gate:

Create `solve.py`:

```python
import math
pepper = 10; state = {}

def encrypted11(s1, P):
    a = list("qwertyuiopasdfghjklzxcvbnm")
    t = a[3]+a[8]+a[7]+a[int(math.sqrt(2))]          # "roiw"
    return t if s1 == t else t + "!@#"

def encrypted10(s1, P):
    a = list("abcdefghijklmnopqrstuvwxyz")
    t = a[3]+a[8]+a[17]+a[int(math.sqrt(18))]        # "dire"
    return t if s1 == t else encrypted11(P, P)

def encrypted1(s1, U, P):
    a = ["1","2","4","g","h","l","o","3","g","p","p","k","d","f",
         "s","e","w","r","t","z","u","i","i","&","$","_"]
    if state['pep'] == 0: s1 = a[0]+a[4]+a[10]+a[22]+a[9]   # "1hpip"
    state['pep'] += 1
    if state['pep'] == pepper: state['o'] = encrypted10(P, P); return s1
    s1 += encrypted1(P, U, P); return s1

def login(u, p):
    state['pep'] = 0; state['o'] = ""
    aa = encrypted1(u, u, p)[:5][::-1][:-1]          # "piph"
    return p == state['o'] and u == aa, aa

_, aa = login("x", "x")
print(f"username = {aa}")
for p in ("dire", "roiw", "roiw!@#"):
    print(f"  accepts {p!r}: {login(aa, p)[0]}")
print(f"HTB{{{aa}:roiw!@#}}")     # deepest fallback branch = the real flag
```

```bash
python3 solve.py
```

All three pairs log in, so each goes to the submission API. `HTB{piph:dire}` and `HTB{piph:roiw}` are rejected; the deepest fallback branch is the real one:

```
HTB{...}
```

## Why it worked

The application performed credential validation entirely client-side, with the "secret" reduced to obfuscated string comparisons compiled into the binary. Obfuscation slows a reader but never removes the answer — decompilation recovers the exact gate. The multiple accepted passwords are an artifact of checking against the fixed points of a chained string-mapping function; when such a gate has several fixed points, the intended flag is usually the deepest fallback branch.

## Fix / defense

Never gate authentication on client-side, obfuscated string identities ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)). Validate credentials server-side against a salted, slow password hash, so the client never carries the check and reverse-engineering the binary reveals nothing usable.
