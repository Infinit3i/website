---
title: "Uplink Artifact"
date: 2026-12-24 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, qr-code, data-visualization, opencv, steganography]
description: "A Very Easy AI/ML challenge that hands you a 'spatial' point-cloud CSV. The secret isn't in the coordinates — it's in the label/class. One class quietly snaps to an integer 25x25 grid that, when rasterised, is a QR code. Isolate that class, render it, and OpenCV reads the flag."
---

## Overview

`Uplink Artifact` is a Very Easy HackTheBox **AI/ML** challenge. It ships a single
`uplink_spatial_auth.csv` with columns `x,y,z,label` (1822 rows, four classes) and a brief
about "physical access credentials hidden within the spatial structure" of a recovered dataset.
The trick: the payload is encoded in *which class a point belongs to*, not in the geometry. One
class is a rasterised QR code; the others are decoy clusters. Isolate the signal class, render it
to pixels, and decode.

## The technique

Naive clustering, PCA, or MDS gets you nowhere here because every class looks like a plausible
blob of points — the geometry is deliberately uninformative. The tell is in the **coordinate
quantisation**, not the shape:

- `label == 1` (322 points): `x` and `y` are **integers** in `[0, 24]`, and `z` is tightly
  banded around `0.5`. That is a clean **25x25 binary grid**.
- `label` 0/2/3: continuous float coordinates spread over the plane — pure decoys.

A 25x25 grid with three 7x7 squares in the corners is a **QR code** (version 2). So the whole
challenge reduces to: split rows by label, find the one class whose coordinates are integers on a
small grid, draw those points as black modules, and decode the QR.

## Solution

First, confirm the structure — only one class has integer coordinates:

```python
import csv
rows = list(csv.DictReader(open('uplink_spatial_auth.csv')))
for L in {r['label'] for r in rows}:
    sub = [r for r in rows if r['label'] == L]
    xs = [float(r['x']) for r in sub]
    intx = sum(1 for v in xs if v == int(v))
    print(L, len(sub), "integer-x:", intx, "/", len(sub))
# label 1 -> 322/322 integer; the rest -> 0/N
```

Then isolate label 1, raster it to a PNG, and let OpenCV decode it. `cv2.QRCodeDetector`
decodes QR codes with no `zbar`/`pyzbar` system library — handy on Kali, which ships no
`zbar-tools` (`pip3 install --user opencv-python-headless pillow`).

Create `solve.py`:

```python
import csv, sys
import cv2
from PIL import Image

CSV = sys.argv[1] if len(sys.argv) > 1 else 'uplink_spatial_auth.csv'
N = 25

rows = list(csv.DictReader(open(CSV)))
pts = {(int(float(r['x'])), int(float(r['y']))) for r in rows if r['label'] == '1'}

scale, border = 10, 4
sz = (N + 2 * border) * scale
img = Image.new('L', (sz, sz), 255)
px = img.load()
for x, y in pts:
    row, col = (N - 1 - y), x
    for dx in range(scale):
        for dy in range(scale):
            px[(col + border) * scale + dx, (row + border) * scale + dy] = 0
img.save('qr.png')

data, _, _ = cv2.QRCodeDetector().detectAndDecode(cv2.imread('qr.png'))
print(data)
```

Run it:

```bash
python3 solve.py uplink_spatial_auth.csv   # HTB{...}
```

Two implementation details matter or detection fails: render the QR with a **quiet-zone border**
of ~4 modules and **scale each module up** to ~10px. The top QR row is the maximum `y` here, so
the row index is `N - 1 - y`; if the finder-pattern corners come out wrong, flip that.

## Why it worked

The dataset author hid the secret in the **label assignment** of an otherwise plausible
clustering dataset, betting that an analyst reaches for dimensionality reduction or clustering and
never thinks to split by class and inspect coordinate precision. The discriminator is trivial once
you see it — one class is quantised onto a grid while the rest are continuous noise — but it is
invisible to any aggregate statistic over all points at once.

## Fix / defense

This is a data-handling lesson rather than a software vulnerability: don't encode secrets in the
metadata or labels of a dataset you ship. From the defender's side, the generalisable detection
habit is to **plot each class separately** and look for the one with quantised/grid-aligned
coordinates whenever a challenge talks about "spatial structure" — the same move recovers glyphs
and QR codes hidden across distance-matrix, embedding, and coordinate-path challenges.
