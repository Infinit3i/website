---
title: "Computational Recruiting"
date: 2026-12-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, coding, text-parsing, formula, bankers-rounding]
description: "A Very Easy Misc/Coding challenge: a raw TCP service hands you a 200-row candidate table and two math formulas, and wants the top-14 by a computed score. The whole puzzle is reading the spec correctly — the intermediate per-skill score feeds the final value, and the worked example's number magnitude is what tells you so."
---

## Overview

`Computational Recruiting` is a Very Easy HackTheBox **Misc** challenge of the
"Coding" flavour — there is no vulnerability and nothing to exploit. The download
is a single `data.txt`: a pretty-printed ASCII table of 200 candidates, each with
six integer skills (Health, Agility, Charisma, Knowledge, Energy, Resourcefulness),
scored 1–10. A raw-TCP service prints two formulas and asks for the **14 candidates
with the highest `overall_value`**, formatted `First Last - value, ...`. The entire
challenge is parsing the table and reading the formula precisely.

## The technique

The service hands you two formulas that **reuse the same field names**:

```text
<skill>_score = round(6 * (s * <skill>_weight)) + 10
overall_value = round(5 * (health*0.18 + agility*0.20 + charisma*0.21
                          + knowledge*0.08 + energy*0.17 + resourcefulness*0.16))

weights: health 0.2, agility 0.3, charisma 0.1, knowledge 0.05, energy 0.05, resourcefulness 0.3
```

The trap is the names `health`, `agility`, … inside `overall_value`: do they mean the
raw 1–10 skill, or the computed `<skill>_score`? Plug in the **raw** skills and your
top candidates land in the 30s–40s. But the prompt's own worked example shows scores
like **94, 92, 92** — in the 90s. Because the `overall_value` coefficients
(0.18 + 0.20 + 0.21 + 0.08 + 0.17 + 0.16) sum to **1.0**, we have
`overall_value ≈ 5 × mean(_score)`, and each `_score = round(6·s·w) + 10` ≈ 12–28, so
the mean is ~18 and `overall_value` ≈ 90. **That magnitude is the disambiguator: the
intermediate `_score` feeds the final `overall_value`.** The raw-skill reading can
never reach the 90s the example demonstrates.

Two more details, both stated in the prompt:

- **Banker's rounding.** `round()` is Python 3's, which rounds half-to-even
  (`round(2.5) == 2`, `round(3.5) == 4`). Use Python's built-in `round` and it is
  correct for free; reimplementing it as `int(x + 0.5)` gives wrong answers on `.5`
  boundaries.
- **Stable tie-break.** Many candidates tie on `overall_value`; a stable sort keeps
  the original file order among ties, which is what the server expects.

## Solution

The candidate data is the static `data.txt` — the service banner sends only the
formulas, no table, so the answer is computed locally and submitted over the socket.

Create `solve.py`:

```python
import socket

HOST, PORT = "TARGET_IP", TARGET_PORT
DATA = "data.txt"

SW = dict(health=0.2, agility=0.3, charisma=0.1, knowledge=0.05, energy=0.05, resourcefulness=0.3)

def score(s, w):
    return round(6 * (s * w)) + 10            # per-skill _score

def overall(h, a, c, k, e, r):
    hs, ags, cs = score(h, SW["health"]), score(a, SW["agility"]), score(c, SW["charisma"])
    ks, es, rs  = score(k, SW["knowledge"]), score(e, SW["energy"]), score(r, SW["resourcefulness"])
    return round(5 * (hs*0.18 + ags*0.20 + cs*0.21 + ks*0.08 + es*0.17 + rs*0.16))

cands = []
for line in open(DATA):
    t = line.split()
    if len(t) >= 8 and all(x.isdigit() for x in t[-6:]):
        first, last = t[0], t[1]
        cands.append((first, last, overall(*map(int, t[-6:]))))

top = sorted(cands, key=lambda x: -x[2])[:14]   # stable sort -> file order on ties
answer = ", ".join(f"{f} {l} - {v}" for f, l, v in top)

s = socket.create_connection((HOST, PORT), timeout=10)
s.recv(65535)
s.sendall(answer.encode() + b"\n")
print(s.recv(65535).decode())
```

Running it sends the correctly ordered top-14 and the service replies with the flag:

```text
You have recruited the best possible companions. Before you leave, take this: HTB{...}
```

## Why it worked

The server compares your ordered top-14 (names and values) against its own
computation. Matching the formula interpretation exactly — the intermediate
`_score` feeding `overall_value`, Python 3 banker's rounding, and a stable
tie-break — reproduces its list identically, and it releases the flag.

## Fix / defense

There is no security bug to fix. The transferable lesson is for solving: when a spec
defines an intermediate quantity and a final quantity using the **same field names**,
the intermediate almost always feeds the final — and any worked example's **output
magnitude** is the cheapest way to confirm which interpretation is intended before you
write a line of code.
