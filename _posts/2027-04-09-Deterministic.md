---
title: "Deterministic"
date: 2027-04-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, automata, state-machine, xor, single-byte-xor]
description: "An Easy Misc challenge that hands you a 130 KB text file encoding a deterministic finite automaton. Strip a decoy legend, walk the machine from the start state to the halt state collecting each emitted value, then peel off a single-byte XOR whose key falls out of plain space-frequency — and the locked door's passphrase is the flag."
---

## Overview

Deterministic is an Easy HackTheBox **Misc** challenge — download only, no instance. You get a single 130 KB `deterministic.txt` and a riddle scrawled on the wall: *"State 0: 69420, State N: 999, flag ends at state N, key length: one."* The file is a **deterministic finite automaton** listed one transition per line; walk it from the start state to the halt state, collect every emitted value, and undo a one-byte XOR to read the passphrase.

## The technique

The file has two parts.

A **decoy legend** sits at the very top — rows like `100 H 110`, `110 T 111`, `111 B 112` … whose middle column is a *letter*. Followed end to end they spell the troll string `HTB{l0l_n0pe}`. Ignore it; its middle field is non-numeric.

The **real machine** is ~15 000 rows of `current_state  value  next_state` (e.g. `9 18 69`), and the blocks repeat many times. This is a [state machine](https://cwe.mitre.org/data/definitions/656.html) where, from each state, one transition emits a `value` and moves to `next_state`. The "writing on the wall" is the run recipe: **start at state `69420`, follow transitions until you reach state `999`, and each emitted `value` is one character of the passphrase XORed with a single secret byte.**

Two observations crack it:

- **Walk is unambiguous.** Build `trans[cur] = (value, next)` from the numeric rows only and follow `next` from `69420` to `999`. (There is exactly one self-conflicting state with two outgoing edges; the path never traverses it, so last-definition-wins is harmless.) The walk emits 394 values.
- **Single-byte XOR leaks its own key.** Natural-language text is mostly spaces, so the **most common emitted value is the space** (`0x20`). The commonest value here is `73`, so `key = 73 ^ 0x20 = 105` (`'i'`). Equivalently, brute all 256 keys and keep the one whose decode contains the `HTB{` crib — note the flag is embedded *mid-sentence* ("…passphrase is: `HTB{...}`"), so the crib must be matched as a **substring**, not a prefix.

## Solution

Create `solve.py`:

```python
#!/usr/bin/env python3
"""Deterministic (HTB Misc, Easy): walk a `cur value next` DFA 69420->999,
each value = one char XORed with a single secret byte; recover key by crib."""
import sys
from collections import defaultdict

def load(path):
    trans, conflicts = {}, defaultdict(set)
    for ln in open(path):
        p = ln.split()
        if len(p) != 3:
            continue
        a, b, c = p
        if not (a.lstrip('-').isdigit() and b.lstrip('-').isdigit() and c.isdigit()):
            continue
        a, b, c = int(a), int(b), int(c)
        if a in trans and trans[a] != (b, c):
            conflicts[a].add((b, c)); conflicts[a].add(trans[a])
        trans[a] = (b, c)
    return trans, conflicts

def walk(trans, start):
    out, cur, seen = [], start, set()
    while cur in trans and cur not in seen:
        seen.add(cur)
        v, nxt = trans[cur]
        out.append(v)
        cur = nxt
    return out, cur

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "deterministic.txt"
    trans, _ = load(path)
    nexts = {n for _, n in trans.values()}
    starts = [s for s in trans if s not in nexts]
    for start in starts:
        vals, halt = walk(trans, start)
        for key in range(256):
            dec = bytes(((v ^ key) & 0xFF) for v in vals if 0 <= v <= 0x10FFFF)
            i = dec.find(b"HTB{")
            if i != -1 and b"}" in dec[i:]:
                print(f"[+] start={start} XOR key={key} ({chr(key)!r})")
                print("[+] FLAG:", dec[i:dec.index(b'}', i) + 1].decode())
                return

if __name__ == "__main__":
    main()
```

Run it against the file:

```bash
python3 solve.py deterministic.txt
```

```
[+] start=69420 XOR key=105 ('i')
[+] FLAG: HTB{...}
```

The full decoded message is a congratulatory note ending with *"The passphrase to unlock the door is: `HTB{...}`."*

## Why it worked

The "encryption" is theater. Stripping the decoy legend leaves a plain **linked list of bytes** indexed by state number, and a single-byte XOR has only 256 possible keys. With a known-plaintext crib — the space character's frequency, or the `HTB{` flag prefix — the key is pinned in one guess. Determinism guarantees exactly one path from `69420` to `999`, so the reconstruction is never ambiguous.

## Fix / defense

Obfuscation is not encryption. A reversible state-machine encoding combined with a single-byte XOR adds zero meaningful secrecy: the keyspace is 256 and the plaintext statistics (space frequency, a known header) give the key away immediately. Anything guarding a real secret needs a proper cipher with a full-entropy key — not a bespoke encoding that merely *looks* complicated.
