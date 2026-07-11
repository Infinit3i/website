---
layout: post
title: "Triangles"
date: 2028-01-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, geometry, trilateration, obfuscation, python]
---

## Overview

Triangles is a Medium **Misc** challenge whose whole prompt is *"Three vertices.
Two CSV files. One solution."* You are given a 100×100 grid of random characters
(`grid.csv`), a `triangulate.py` encoder, and an `out.csv` of `(value, distance)`
pairs. Each flag character is hidden at some grid cell, and the only evidence you
get is a handful of distances from that cell to random nearby points. Because the
grid ships with the challenge, the whole thing is reversible geometry — a classic
[trilateration](https://cwe.mitre.org/data/definitions/327.html) problem with no key.

## The technique

For every flag character sitting at grid cell `(cx, cy)`, the encoder picks three
random points `p1, p2, p3` within ±7 of the center and writes **six** rows to
`out.csv`:

| row | value                | distance          |
|-----|----------------------|-------------------|
| 1   | `grid[p1]`           | `dist(center, p1)`|
| 2   | `grid[p2]`           | `dist(center, p2)`|
| 3   | `grid[p3]`           | `dist(center, p3)`|
| 4   | `grid[p1] + grid[p2]`| `dist(p1, p2)`    |
| 5   | `grid[p2] + grid[p3]`| `dist(p2, p3)`    |
| 6   | `grid[p1] + grid[p3]`| `dist(p1, p3)`    |

The center character `grid[cx][cy]` — the actual secret — is never written. With
`132 / 6 = 22` groups, the flag is 22 characters long.

The key realization: you don't have to reconstruct the random points at all. Just
**brute-force the center** over all 10,000 grid cells. A cell is the true location
iff grid cells carrying the three named characters exist at exactly the three named
distances from it, *and* those points also satisfy the three pairwise distances in
rows 4–6. Squaring every distance turns them into integers (Euclidean distances
between integer grid points have integer squares), so matching is exact — no
floating-point tolerance anywhere.

## Solution

The full, runnable solver:

```python
#!/usr/bin/env python3
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))
arr = [r for r in csv.reader(open(os.path.join(HERE, "files", "grid.csv")))]
out = [r for r in csv.reader(open(os.path.join(HERE, "files", "out.csv")))]
N = len(arr)

pos = {}
for r in range(N):
    for c in range(len(arr[r])):
        pos.setdefault(arr[r][c], []).append((r, c))

def sq(d):
    return round(float(d) ** 2)

flag = []
for g in range(0, len(out), 6):
    v1, d1 = out[g][0],   sq(out[g][1])
    v2, d2 = out[g+1][0], sq(out[g+1][1])
    v3, d3 = out[g+2][0], sq(out[g+2][1])
    d12, d23, d13 = sq(out[g+3][1]), sq(out[g+4][1]), sq(out[g+5][1])

    for cx in range(N):
        for cy in range(N):
            c1 = [p for p in pos.get(v1, []) if (p[0]-cx)**2+(p[1]-cy)**2 == d1]
            if not c1: continue
            c2 = [p for p in pos.get(v2, []) if (p[0]-cx)**2+(p[1]-cy)**2 == d2]
            if not c2: continue
            c3 = [p for p in pos.get(v3, []) if (p[0]-cx)**2+(p[1]-cy)**2 == d3]
            if not c3: continue
            hit = any(
                (p1[0]-p2[0])**2+(p1[1]-p2[1])**2 == d12 and
                (p2[0]-p3[0])**2+(p2[1]-p3[1])**2 == d23 and
                (p1[0]-p3[0])**2+(p1[1]-p3[1])**2 == d13
                for p1 in c1 for p2 in c2 for p3 in c3)
            if hit:
                flag.append(arr[cx][cy]); break
        else:
            continue
        break

print("FLAG:", "".join(flag))
```

Running it recovers every one of the 22 characters uniquely:

```console
$ python3 solve.py
FLAG: HTB{...}
```

## Why it worked

There is no secret. The reference grid is shipped with the challenge, so the
transform — "encode a character as its distances to known points" — is fully
invertible. Squaring the distances removes all ambiguity, collapsing what looks
like a fuzzy geometric search into exact integer matching. Every group resolves to
a single grid cell, and that cell's character is the flag byte.

## Fix / defense

Distance-from-known-reference encodings are **obfuscation, not encryption**. If you
must hide data this way, the reference grid itself has to be secret and
high-entropy — shipping it alongside the ciphertext reduces the scheme to a puzzle
anyone can brute-force in seconds.
