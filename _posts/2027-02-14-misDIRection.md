---
title: "misDIRection"
date: 2027-02-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, forensics, steganography, filesystem]
description: "An Easy Misc challenge that hides its flag in the shape of a directory tree instead of inside any file — subdirectories named by characters, empty files named by their positions, reassembled and base64-decoded."
---

## Overview

**misDIRection** is an Easy HackTheBox **Misc** challenge. You download an archive
of a "suspicious directory" the prompt says contains no malicious *files* — and it
is right, because every file in it is empty. The flag is encoded in the **structure**
of the directory tree itself: directory names and file names, not file contents. The
title is the hint — mis**DIR**ection — the data was *directly in plain sight*, in the
**DIR**ectory layout.

## The technique

Standard steganography reflexes (`strings`, `binwalk`, `steghide`, `exiftool`) all
inspect file *contents* and metadata. A filesystem carries information in three
channels those tools ignore: **directory names, file names, and nesting**. When a
challenge ships a pile of empty files, that emptiness is the signal — read the tree,
not the bytes.

Unzipping the archive (password `hackthebox`) reveals:

```bash
find files/.secret -printf '%y %p\n' | sort   # %y = node type (d/f), %p = path
```

- `files/.secret/` holds **64 single-character subdirectories**, named by characters
  from the base64 alphabet (`A–Z a–z 0–9`).
- Each subdirectory contains **empty files named by numbers** — the 1-based
  **positions** that character occupies in the final hidden string.
  - `.secret/u/20` and `.secret/u/28` ⇒ the character `u` belongs at positions 20 and 28.

## Solution

Build a `position → character` map by walking the tree, concatenate the characters
in position order, and base64-decode the result.

Create `solve.py`:

```python
#!/usr/bin/env python3
import os, base64, sys
root = sys.argv[1]
pos = {}
for ch in os.listdir(root):                 # subdir name = one output character
    d = os.path.join(root, ch)
    if not os.path.isdir(d):
        continue
    for f in os.listdir(d):                  # filename = a 1-based position
        pos[int(f)] = ch
b64 = "".join(pos[i] for i in sorted(pos))   # positions 1..N in order
print(b64)
print(base64.b64decode(b64).decode())
```

Run it against the secret directory:

```bash
python3 solve.py files/.secret
```

```
SFRCe0RJUjNjdEx5XzFuX1BsNDFuX1NpN2V9
HTB{...}
```

The reassembled string beginning `SFRC` is the giveaway — that is base64 for `HTB`,
confirming the layer is base64 before you even decode it.

## Why it worked

The challenge author moved the payload out of file contents and into filesystem
*metadata*. Empty files defeat content-based stego tooling entirely, and the
position-indexed naming scheme is a tidy way to scatter an ordered string across an
unordered set of directories. Sorting by the numeric filenames re-imposes the order.

## Fix / defense

There is nothing to "patch" — it is a puzzle. The transferable lesson for
forensics and detection: never treat a zero-byte file as harmless. Filenames and
directory layout are a viable covert channel and data-exfiltration vector, so when
triaging a suspicious directory, hash and log the **full path inventory** (names and
tree shape), not just file bodies.
