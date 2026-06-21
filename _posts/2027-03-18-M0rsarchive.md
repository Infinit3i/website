---
title: "M0rsarchive"
date: 2027-03-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, stego, morse, zip, recursion, python]
description: "An Easy Misc challenge: a single zip opens onto 1000 recursively nested password-protected archives, and each layer hands you its own key as a Morse-code strip painted into a tiny PNG. Decode the image, unzip, repeat — with one lowercase gotcha that only bites twelve layers deep."
---

## Overview

`M0rsarchive` is an Easy HackTheBox **Misc** challenge. The download contains
`flag_999.zip` and a tiny `pwd.png`. Opening the zip reveals *another*
password-protected zip plus *another* `pwd.png` — and this nests **1000 times**.
Each layer's password is hidden in its `pwd.png` as a Morse-code strip, so the whole
challenge is one decode-and-recurse loop with a single case-sensitivity trap.

## The technique

Each `pwd.png` is a thin RGB image with two colours — a background and an "on" colour.
The encoding falls straight out of looking at the pixels:

```
.###.###.###.###.###.....   <- row 1  -> ----- -> 0
.###.###.###.#.#.........   <- row 3  -> ---.. -> 8
```

- The **corner pixel `(0,0)` is always the background**; any other colour is "on".
- **Blank pixel-rows are separators. Each non-blank row is exactly one Morse character.**
- Within a row: an "on" run of **3 px = dash (`-`)**, **1 px = dot (`.`)**; a single "off"
  px just separates symbols.
- Concatenate the characters top-to-bottom → the password for that layer's sibling zip.

The password grows by one character per layer (`9`, `08`, `376`, …), so the PNGs get
taller as you descend. This is a [steganography](https://cwe.mitre.org/data/definitions/549.html)
puzzle, not a vulnerability — the point is to script the loop instead of unzipping 1000
archives by hand.

### The one gotcha: case

Morse decodes naturally to **uppercase**, but the zip passwords are **lowercase**. You
don't notice immediately because the **first ~12 layers are pure digits** (where case is
irrelevant). The trap springs at layer 13, where letters first appear: the strip decodes
to `JSZONJREP0FVVP`, the zip rejects it, and `jszonjrep0fvvp` works. Lowercase the decode
from the start. (A related trap: reading only the *middle* pixel-row works for a 3-row
image but the middle row of a taller multi-character PNG is blank — always iterate **all**
non-blank rows.)

## Solution

The full solver decodes each `pwd.png`, unzips with that password, grabs the inner zip +
PNG, and recurses. Filenames are arbitrary (they do **not** count down by 1), so the loop
condition is "is there still an inner `.zip`?" — not the number in the name. After 1000
iterations the final archive drops a plain text file holding the flag.

Create `solve.py`:

```python
#!/usr/bin/env python3
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
    for y in range(a.shape[0]):
        row = a[y]
        if all(tuple(p) == bg for p in row):
            continue
        out += MORSE.get(decode_row(row, bg), '?')
    return out.lower()

def main():
    work = 'run'
    shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    shutil.copy('files/flag_999.zip', f'{work}/cur.zip')
    shutil.copy('files/pwd.png', f'{work}/pwd.png')
    level = 0
    while True:
        pwd = decode_png(f'{work}/pwd.png')
        ext = f'{work}/ext'
        shutil.rmtree(ext, ignore_errors=True); os.makedirs(ext)
        r = subprocess.run(['unzip', '-o', '-P', pwd, f'{work}/cur.zip', '-d', ext],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[level {level}] pwd={pwd!r} FAILED"); return
        names = [os.path.join(d, f) for d, _, fs in os.walk(ext) for f in fs]
        zips = [n for n in names if n.endswith('.zip')]
        pngs = [n for n in names if n.endswith('.png')]
        other = [n for n in names if not n.endswith(('.zip', '.png'))]
        if other or not zips:
            for n in (other or names):
                print(">>>", open(n).read().strip())
            return
        shutil.copy(zips[0], f'{work}/cur.zip')
        if pngs:
            shutil.copy(pngs[0], f'{work}/pwd.png')
        level += 1

if __name__ == '__main__':
    main()
```

Run it from the unzipped challenge directory:

```bash
python3 solve.py
```

```
[level 0]   pwd=9
[level 1]   pwd=08
[level 13]  pwd=jszonjrep0fvvp
[level 999] pwd=7920
>>> HTB{...}
```

## Why it worked

The author encodes each layer's password as a per-row Morse strip so it can't be brute-forced
or read from the filename — but the encoding is fully deterministic, so a 40-line decoder
plus a recursion loop solves all 1000 layers in seconds. The only friction is the
lowercase/uppercase mismatch, which is masked by the digit-only opening layers.

## Fix / defense

There's nothing to "fix" — this is a CTF stego puzzle. The transferable lesson is the
reflex: when a challenge feeds you *an artifact that unlocks the next artifact*, script the
decode-and-extract loop rather than doing it by hand, loop on the **structure**
("still a zip?") instead of a filename counter, and lowercase/normalize early so an
encoding quirk doesn't surface a dozen iterations deep. The same pattern shows up in
nested-zip challenges where the inner **filename** is the next password.
