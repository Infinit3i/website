---
title: "No Place To Hide"
date: 2027-05-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, rdp, bitmap-cache, bmc-tools, dfir]
description: "An Easy Forensics challenge: a Windows RDP bitmap cache silently records every 64x64 screen tile drawn during a session — reconstruct the tiles and you read the attacker's cmd.exe right off the pixels."
---

## Overview

**No Place To Hide** is an Easy HackTheBox **Forensics** challenge. The SOC caught a
password-spray against a Domain Controller followed by a suspicious RDP session, and
hands you the artifacts pulled from the host. There's no server and no obvious flag in
the files — the flag was *displayed on screen* during the RDP session, and the Windows
RDP client quietly cached it. Recover the [cleartext-stored](https://cwe.mitre.org/data/definitions/312.html)
bitmap cache and you can read the attacker's terminal.

## The technique

You're given two files:

| File | What it is |
|------|------------|
| `Cache0000.bin` (18 MB) | Windows **RDP bitmap cache** (newer "v2" format) written by `mstsc.exe` |
| `bcache24.bmc` (0 bytes) | legacy bitmap cache — empty |

When you RDP into a host, the client doesn't redraw the whole screen every frame — it
caches **64×64-pixel tiles** of what's been shown and re-references them. Those tiles get
persisted to disk, unencrypted, under
`%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`. So even with no screenshot and
no video, everything the operator saw on screen — including a typed command — is sitting
in that cache one tile at a time. This is the whole lesson: **RDP leaves a visual trail
on the client.**

## Solution

### 1. Extract the tiles

Use ANSSI-FR's [`bmc-tools`](https://github.com/ANSSI-FR/bmc-tools):

```bash
git clone https://github.com/ANSSI-FR/bmc-tools
python3 bmc-tools.py -s Cache0000.bin -d tiles/ -b
# [===] 1162 tiles successfully extracted in the end.
# also writes tiles/Cache0000.bin_collage.bmp
```

### 2. Understand why the collage looks like noise

The tiles are stored in **cache order, not screen order**. The collage is just every tile
laid out 64-wide in the order they happened to be cached, so a single line of on-screen
text is shredded into scattered chunks. There is no reliable tool to auto-reassemble the
screen (RdpCacheStitcher only helps you do it by hand).

### 3. Find the text, ignore the wallpaper

Most tiles are desktop gradient or window chrome. Filter to tiles that look like console
text (mostly light background with some dark ink), then group the survivors into **runs of
consecutive cache indices** — when the client drew the cmd window line it cached those
tiles as adjacent indices, so each run is roughly one window region drawn at one moment.

Create `solve.py`:

```python
import glob, os, re, subprocess
from PIL import Image

def content_tiles():
    keep = []
    for t in sorted(glob.glob("tiles/Cache0000.bin_*.bmp")):
        if "collage" in t:
            continue
        px = list(Image.open(t).convert("L").getdata()); n = len(px)
        if n and sum(p > 180 for p in px)/n > 0.15 and sum(p < 70 for p in px)/n > 0.05:
            keep.append(int(re.search(r'_(\d+)\.bmp', t).group(1)))
    return sorted(keep)

def runs(idxs, gap=2):
    out, cur = [], [idxs[0]]
    for a in idxs[1:]:
        cur.append(a) if a - cur[-1] <= gap else (out.append(cur), cur := [a])
    out.append(cur)
    return [r for r in out if len(r) >= 3]

subprocess.run(["python3", "bmc-tools.py", "-s", "Cache0000.bin", "-d", "tiles/", "-b"])
for r in runs(content_tiles()):
    files = [f"tiles/Cache0000.bin_{i:04d}.bmp" for i in r]
    subprocess.run(["montage", *files, "-tile", f"{len(files)}x1",
                    "-geometry", "64x64+0+0", f"strip_{r[0]:04d}.png"])
    print(f"run {r[0]:04d}-{r[-1]:04d} ({len(r)} tiles)")
```

```bash
python3 solve.py
```

### 4. Read the flag off the pixels

The run at tiles **1031–1046** is an `Administrator: cmd.exe` window. Montage it horizontally,
then zoom in (the line is legible at ~6× with a point filter):

```bash
convert strip_1031.png -crop 312x64+520+0 -filter point -resize 600% flagbody.png
```

The cmd line reads back clean:

```text
C:\Users\Administrator>echo HTB{...}
HTB{...}
```

**Flag:** `HTB{...}` — l33t for *"watch your connection"*.

## Why it worked

RDP bitmap caching is on by default, the cache is **unencrypted**, and it **persists across
reboots**. Anyone who later obtains the file can reconstruct exactly what was on screen — a
textbook [cleartext storage of sensitive information](https://cwe.mitre.org/data/definitions/312.html)
(CWE-312). The attacker typed the secret into a terminal believing the session was
ephemeral; the client wrote it to disk as a mosaic of tiny bitmaps.

## Fix / defense

- **Client:** disable bitmap caching — `disable bitmap caching:i:1` in the `.rdp` file, or
  uncheck *Persistent bitmap caching* in the mstsc Experience tab.
- **Hygiene:** wipe `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` between
  sessions, and treat the cache as sensitive data at rest (full-disk encryption).
- **DFIR:** flip it around — the bitmap cache is often the *only* visual record of what an
  attacker did over RDP, so collect and reconstruct it during incident response.
