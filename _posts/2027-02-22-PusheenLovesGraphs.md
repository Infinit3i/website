---
title: "Pusheen Loves Graphs"
date: 2027-02-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, stego, reversing, elf, ida, control-flow-graph]
description: "An Easy Misc/stego challenge: a 32-bit ELF hides its flag as the picture IDA's control-flow-graph layout draws. Thousands of trivial basic blocks form a grid, and the hidden bitmap is encoded in each block's SIZE — read it straight from the symbol table, no IDA required."
image:
    path: /assets/Images/pusheen-loves-graphs-bitmap.png
---

## Overview

**Pusheen Loves Graphs** is an Easy HackTheBox **Misc** (stego) challenge. You get a
download-only 32-bit ELF and the hint *"Pusheen loves graphs, Graphs and IDA."* The
flag is not in any string, data section, or program output — it is the **picture that
IDA's control-flow-graph layout draws** when you view the binary's graph. The
intended solve is to open it in IDA, raise the graph node limit, and read the flag off
the spatial arrangement of basic blocks. Below I reconstruct the exact same bitmap
**headlessly from the symbol table** — no IDA needed.

## The technique

Running `file` shows a 32-bit ELF, *not stripped*. The symbol table is the giveaway:

```bash
nm Pusheen | grep ' t e_' | wc -l        # 6767
```

There are **6767 tiny functions** named `e_<a>_<b>`, with `a` in `0..66` (67 columns)
and `b` in `0..100` (101 rows) — a full **67×101 grid**. Every `(a,b)` exists, so the
*names* carry no information. Disassembling any block shows the same thing: a run of
junk arithmetic that ends in `jmp <next>` (`e9 00 00 00 00`, a fall-through). So the
whole program is **one long linear chain** with no conditional edges — the
control-flow *topology* carries no information either.

The information is hidden in one place left: the **size** of each block.

```text
size bucket   count   meaning
16 bytes      6213    11-byte header + 5-byte jmp  -> OFF pixel
~86-113 bytes  rest   block padded with dead code  -> ON  pixel
```

Each grid cell is a pixel; a block is "on" if it was bulked up with filler
instructions. IDA's grid graph-layout makes this visible; computing the size of each
function from the symbol table reproduces the identical bitmap in seconds.

## Solution

The block size is simply the distance to the next symbol. Build the grid, threshold,
transpose, and render — the pixel-font text reads `fUn_` / `w17h_` / `CFGz`.

Create `solve.py`:

```python
from elftools.elf.elffile import ELFFile

elf  = ELFFile(open("Pusheen", "rb"))
syms = sorted(set(
    (s['st_value'], s.name)
    for s in elf.get_section_by_name(".symtab").iter_symbols()
    if s['st_value'] and s.name.startswith('e_')
))
nxt  = {syms[i][1]: syms[i+1][0] for i in range(len(syms)-1)}
size = {n: nxt.get(n, a+16) - a for a, n in syms if n.startswith('e_')}   # size = next_addr - addr

on = lambda a, b: size.get(f'e_{a}_{b}', 0) > 20      # 16 = minimal (OFF), larger = filled (ON)
for b in range(101):                                   # transpose: rows = b, cols = a
    row = ''.join('#' if on(a, b) else ' ' for a in range(67))
    if row.strip():
        print(row)
```

```bash
python3 solve.py
```

Piped through a small PIL renderer (scale ~10×, try both orientations and 90°
rotations) the grid resolves to three lines of pixel-font text:

![Rendered block-size bitmap](/assets/Images/pusheen-loves-graphs-bitmap.png)

Reading it: `fUn_` `w17h_` `CFGz` — "fun with CFGz" (CFG = Control Flow Graphs).
Wrapped in the flag format:

```text
HTB{...}
```

(flag value redacted).

## Why it worked

The author encoded a 2-D bitmap where **each pixel is one basic block** and the
pixel's color is whether that block was padded with dead instructions. The grid of
identical `jmp`-chained blocks exists only to give IDA's layout engine a regular
canvas to draw on. Because the blocks are laid out by name on a fixed grid, thresholding
their sizes recovers the picture without ever rendering the graph.

## Fix / defense

This is a CTF stego trick, not a real-world vulnerability — there is nothing to
"patch." The transferable lesson for reverse engineers: when a binary contains a
**huge, regular grid of trivial near-identical functions or blocks**, stop
disassembling and start **measuring**. The payload is usually in the per-block
*metadata* — size, address spacing, alignment, count — not in the instructions
themselves.
