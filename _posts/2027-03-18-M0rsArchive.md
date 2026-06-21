---
title: "M0rsArchive"
date: 2027-03-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, stego, morse, nested-zip, python, cwe-656]
description: "An Easy Misc challenge: a thousand-deep matryoshka of password-protected zips where each layer's password is hidden as a Morse-code strip painted into a tiny PNG. Decode the pixels, unzip, recurse — with one lowercase gotcha that only bites once the passwords stop being digits."
---

## Overview

`M0rsArchive` is an Easy HackTheBox **Misc** challenge. The download is a single
zip that, when opened, contains *another* password-protected zip plus a tiny
`pwd.png`. The PNG is a [Morse-code](https://cwe.mitre.org/data/definitions/656.html)
strip that spells the password for that layer — decode it, unzip, and you find yet
another zip and another `pwd.png`. The archive is **1000 layers deep**, so the whole
challenge is recognising the encoding and automating the descent.

## The technique

Each `pwd.png` is a thin RGB image with exactly two colours: a background and an
"on" colour. The password is Morse code rendered as pixels:

- The **corner pixel `(0,0)`** is always the background — use it as the reference.
- **Blank pixel-rows separate** the data rows. **Each non-blank row = exactly one Morse character**, read top-to-bottom.
- Within a row, an "on" run of **3 px = dash**, **1 px = dot**; a single "off" px separates symbols.

The one real trap is **case**. Morse maps to uppercase letters, but the zip passwords
are lowercase. You don't notice immediately because the first ~12 layers are pure
**digits** (`9`, `08`, …) where case is irrelevant — the bug only surfaces at layer 13,
where letters first appear: the strip decodes to `JSZONJREP0FVVP`, the zip rejects it,
and `jszonjrep0fvvp` works. A related trap: an early naive decoder reads only the
*middle* pixel-row, which is fine for a 3-row image but blank in a taller
multi-character PNG — always iterate **all** non-blank rows.

## Solution

The whole solve is one decode-and-recurse loop. Seed `cur.zip` + `pwd.png` in a work
directory from the top layer, then run:

Create `solve.py`:

```python
import os, shutil, subprocess
import numpy as np
from PIL import Image

MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
    '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
    '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5',
    '-....':'6','--...':'7','---..':'8','----.':'9',
}

def decode_row(row, bg):
    seq = [tuple(p) != bg for p in row]
    runs, i = [], 0
    while i < len(seq):
        j = i
        while j < len(seq) and seq[j] == seq[i]:
            j += 1
        runs.append((seq[i], j - i)); i = j
    return ''.join('-' if ln >= 3 else '.' for on, ln in runs if on)

def decode_png(path):
    a = np.array(Image.open(path).convert('RGB'))
    bg = tuple(a[0, 0])
    out = ''
    for row in a:
        if all(tuple(p) == bg for p in row):
            continue
        out += MORSE.get(decode_row(row, bg), '?')
    return out.lower()

c = 'cur.zip'
while True:
    pwd = decode_png('pwd.png')
    subprocess.run(['unzip', '-o', '-P', pwd, c, '-d', 'x'], capture_output=True)
    files = [os.path.join(d, f) for d, _, g in os.walk('x') for f in g]
    zips = [f for f in files if f.endswith('.zip')]
    if not zips:
        print(open([f for f in files if not f.endswith(('.zip', '.png'))][0]).read())
        break
    shutil.copy(zips[0], c)
    shutil.copy([f for f in files if f.endswith('.png')][0], 'pwd.png')
    shutil.rmtree('x')
```

Running it descends all 1000 layers and prints the flag:

```bash
python3 solve.py        # HTB{...}
```

## Why it worked

Stego is not encryption. The password was never protected — it was sitting in plain
sight, just rendered as pixels instead of text. Once you recognise the image as a
*data carrier* (Morse here, but it could equally be a QR grid or a bitmap-as-bytes),
the rest is a mechanical decode → unzip → recurse loop. The depth (1000 layers) exists
only to force automation; the lowercase quirk exists only to punish a pipeline that
was validated on the easy digit-only inputs and never tested against the letter case.

## Fix / defense

For a CTF puzzle there's nothing to "patch," but the lesson generalises:
[**reliance on security through obscurity**](https://cwe.mitre.org/data/definitions/656.html)
is not a control. Embedding a secret in an image strip — or any reversible encoding —
provides zero protection: anyone who can read the bytes can read the secret. Real
archives should use authenticated encryption with a proper key-derivation function,
not a password hidden in a picture.
