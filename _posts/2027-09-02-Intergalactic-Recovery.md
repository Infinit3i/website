---
layout: post
title: "Intergalactic Recovery"
date: 2027-09-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, raid5, mdadm, disk-recovery, xor-parity, ext4, debugfs]
---

## Overview

A disk-forensics challenge. Miyuki's team stores case evidence on a shared **RAID 5** array,
and an "EMP cannon" partially destroyed it. You're handed three disk images — two intact 5 MB
members and one 3790-byte stub (a red herring) — and asked to recover the contents. The path is
a textbook single-disk RAID 5 reconstruction: parse the `mdadm` superblock for the geometry,
XOR the surviving members to rebuild the dead disk, re-stripe the array, then carve the ext4
filesystem for the evidence file.

## The technique

RAID 5 stripes data across N disks in fixed-size **chunks**, and for every "stripe row" one
chunk holds **parity** equal to the XOR of the other chunks in that row. The parity slot rotates
from row to row. Because `parity = D0 ^ D1 ^ ...`, the XOR of **all** chunks in a row is `0`.
So when exactly one disk is missing, each missing chunk is simply the XOR of the surviving
chunks — `missing = survivor_a ^ survivor_b`. RAID 5 tolerates one disk loss, and recovery is a
byte-wise XOR. The only thing you must not guess is the array geometry — and you don't have to,
because the Linux `md` driver writes it all into an on-disk superblock.

## Solution

**Step 1 — read the mdadm superblock.** Both 5 MB images carry an **mdadm v1.2 superblock at
file offset `0x1000`**. The challenge zeroed the 4-byte magic, but the rest is intact — `strings`
reveals the array name. Parse `struct mdp_superblock_1` (offsets relative to `0x1000`):

```python
import struct
sb = open("fef0d1cd.img", "rb").read()[0x1000:0x1200]
print("name", sb[0x20:0x40].split(b"\x00")[0])           # longnte:md0
print("level", struct.unpack("<i", sb[0x48:0x4c])[0])    # 5
print("layout", struct.unpack("<I", sb[0x4c:0x50])[0])   # 2 = left-symmetric
print("chunk", struct.unpack("<I", sb[0x58:0x5c])[0]*512)# 524288 = 512 KB
print("raid_disks", struct.unpack("<I", sb[0x5c:0x60])[0])
print("data_offset", struct.unpack("<Q", sb[0x80:0x88])[0]*512)  # 2 MB
print("data_size", struct.unpack("<Q", sb[0x88:0x90])[0]*512)    # 3 MB
print("dev_number", struct.unpack("<I", sb[0xa0:0xa4])[0])
print("dev_roles", struct.unpack("<4H", sb[0x100:0x108]))        # (0,1,65535,2)
```

`dev_roles[dev_number]` maps each physical disk to its array role: `fef0d1cd` → **role 0**,
`06f98d35` → **role 2**. The missing role is **1** — the EMP-destroyed disk.

**Step 2 — reconstruct and re-stripe.** Recover the dead member as the XOR of the survivors,
then reassemble the linear array in **left-symmetric** order (`pd_idx = (N-1) - stripe % N`;
the i-th data chunk lives on slot `(pd_idx + 1 + i) % N`):

Create `solve.py`:

```python
#!/usr/bin/env python3
import os
F = "files/forensics_intergalactic_recovery"
DATA_OFF, DATA_SZ, CHUNK, N = 4096*512, 6144*512, 1024*512, 3

def datapart(fn):
    return open(os.path.join(F, fn), "rb").read()[DATA_OFF:DATA_OFF+DATA_SZ]

role0 = datapart("fef0d1cd.img")
role2 = datapart("06f98d35.img")
role1 = bytes(a ^ b for a, b in zip(role0, role2))     # RAID5 single-disk recover
disks = [role0, role1, role2]

out = bytearray()
for s in range(DATA_SZ // CHUNK):                       # 6 stripe rows
    pd = (N - 1) - (s % N)                              # left-symmetric parity
    for i in range(N - 1):
        slot = (pd + 1 + i) % N
        out += disks[slot][s*CHUNK:(s+1)*CHUNK]

open("array.img", "wb").write(out)
print("assembled", len(out), "bytes")
```

```bash
python3 solve.py
file array.img        # Linux rev 1.0 ext4 filesystem data
```

**Step 3 — carve the evidence and read the flag.** No mount or root needed — `debugfs` reads
the raw image directly:

```bash
debugfs -R "ls -l /" array.img                          # imw_1337.pdf
debugfs -R "dump /imw_1337.pdf imw_1337.pdf" array.img
pdfimages -png imw_1337.pdf page                         # one 2480x1884 image
```

The PDF has no text layer and no metadata — the flag is **printed visually** on the rendered
"CASE: IMW-1337 Mind Map" image.

```
HTB{...}
```

## Why it worked

RAID 5's parity is plain XOR, and the `md` superblock stores the exact geometry (level, layout,
chunk size, data offset, and the per-disk role map). Together those mean a single failed member
is fully and deterministically recoverable from the surviving disks — no controller, no key, no
guessing.

## Fix / defense

RAID is **redundancy, not backup**. It survives a single disk failure, but a forensic analyst
(or an attacker) holding any N-1 of the N members can reconstruct the entire array offline via
XOR. Sensitive data on a RAID set must still be **encrypted at rest** — put LUKS/dm-crypt under
the array — or losing or seizing the disks leaks everything on them.
