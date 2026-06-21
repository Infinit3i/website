---
title: "The secret of a Queen"
date: 2027-03-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, cipher, cryptography, nomenclator, mary-stuart, osint]
description: "An Easy Misc challenge that looks like image stego but isn't — the PNG is a message written in the cipher Mary, Queen of Scots used in the Babington Plot. Recognise the historical nomenclator, decode it, done."
---

## Overview

**The secret of a Queen** is an Easy Misc challenge that hands you a single PNG of strange hand-drawn glyphs. It *looks* like steganography, but there's nothing embedded — the picture itself is a message written in a **named historical cipher**: the nomenclator Mary, Queen of Scots used during the Babington Plot. The whole challenge is recognising the cipher from the title and decoding it.

## The technique

Before reaching for stego tools, confirm there's actually a hidden payload. Here every byte-level check comes up empty:

```bash
file "The secret of a Queen.png"          # PNG 1616x413, 8-bit RGBA
exiftool "The secret of a Queen.png"      # only Screenshot / XMP — nothing useful
binwalk "The secret of a Queen.png"       # just the PNG/TIFF header, no trailing archive
strings -n 6 "The secret of a Queen.png" | grep -i flag   # empty
```

Clean across the board means **there is no embedded data** — the glyphs *are* the message. Rows of odd symbols (∞, θ, α, arrows, triangles, doubled-f) are a **substitution / nomenclator cipher**, and the title is the pointer: "the secret of a **Queen**" → **Mary, Queen of Scots**, whose encrypted letters in the **Babington Plot** used a nomenclator (per-letter symbol plus a few NULL/decoy blanks). It's hosted on dcode.fr as the *Mary Stuart code*.

## Solution

Match each drawn glyph to the published Babington alphabet. Calibrate with the `HTB` crib — the first three symbols decode to H, T, B — then read out the rest. The raw decode is `HTB <null> THEBABINGTONPLOT <null>`, where the cipher's NULL/blank symbols land exactly where the flag braces belong.

`solve.py`:

```python
#!/usr/bin/env python3
# The PNG is NOT digital stego (exiftool/binwalk/strings all clean). The drawn glyphs
# are the Mary, Queen of Scots / Babington Plot nomenclator (dcode.fr "Mary Stuart code"):
# each letter is a unique symbol, plus a few NULL/decoy blanks used as separators.
# Reading the two lines and mapping them through the Babington alphabet gives:
#   H T B <null> T H E B A B I N G T O N P L O T <null>
plain_tokens = ["H", "T", "B", "NULL",
                "T", "H", "E", "B", "A", "B", "I", "N", "G", "T", "O", "N", "P", "L", "O", "T",
                "NULL"]
letters = [t for t in plain_tokens if t != "NULL"]
flag = "HTB{" + "".join(letters[3:]) + "}"   # drop the HTB crib, wrap the secret word
print(flag)
```

Running it prints the flag (`HTB{...}` — value redacted), which the HTB API accepts.

## Why it worked

A nomenclator is just a fancy monoalphabetic substitution. Because the alphabet is *published history*, there's no cryptanalysis to do once you identify it — the title is effectively an OSINT hint that points straight at dcode's decoder. The decoded plaintext even names the conspiracy the cipher was historically used in, which is a tidy confirmation the read is correct.

## Fix / defense

There's no software vulnerability here — the takeaway is recognition discipline: **a clean-stego image of unusual glyphs plus a person/era hint is a named historical cipher, not LSB stego.** Search "&lt;hint&gt; cipher / ancient cryptography", decode on dcode, and wrap the NULL-delimited output as the flag. Don't sink the clock into `steghide`/`zsteg` on a payload-free PNG.
