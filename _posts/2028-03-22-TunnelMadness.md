---
layout: post
title: "TunnelMadness"
date: 2028-03-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, maze, bfs, static-analysis, jump-table, pwntools]
description: "A networked reversing crackme whose puzzle — a 20x20x20 3D maze — is baked into the binary as static data. Lift the maze, BFS to the vault offline, verify against the binary's fake flag, then replay the moves to the live instance for the real flag."
---

## Overview

TunnelMadness is a Medium reversing challenge. You get a binary, `tunnel`, and a docker
instance. The binary hides a 3D maze; reaching the vault triggers a flag read that only
works on the server. Because the entire maze is static data inside the binary, the whole
solution is computed offline — the network is only needed to print the real flag.

## The binary

`tunnel` is a non-stripped PIE with four functions: `main`, `prompt_and_update_pos`,
`get_cell`, `get_flag`. Its strings are a roadmap: `/flag.txt`,
`HTB{fake_flag_for_testing}`, `You break into the vault and read the secrets within...`,
and the prompt `Direction (L/R/F/B/U/D/Q)?`. The distributed binary carries a fake flag;
the real `/flag.txt` exists only on the instance, read by `get_flag()`
(`fopen("/flag.txt")` → `fgets` → `puts`).

## The maze

`get_cell(pos)` computes a cell address as:

```
index = pos[0]*400 + pos[1]*20 + pos[2]      # 20x20x20 grid
addr  = maze + index*16                        # 16-byte cells
```

So `maze` is a `const` 20×20×20 array of 16-byte cells at a fixed VA (`0x20e0`). The `int`
at cell offset **+12** is the cell **type**:

- `main` wins when the current cell's type `== 3` (the vault → `get_flag()`).
- a move into a cell of type `== 2` is rejected (`"Cannot move that way"`).
- other types are open floor.

Start is `(0,0,0)`; the vault sits at `(19,19,19)`.

## The controls

Each move reads a char, `toupper`s it, then dispatches through a jump table:
`sub al, 0x42; cmp al, 0x13; ja default; jmp [table + idx*4]`. Decoding the table (each
entry is a signed offset from the table base; match each target to its coordinate-update
branch) yields the key → move map:

| key | axis | Δ |
|-----|------|---|
| L / R | 0 | −1 / +1 |
| B / F | 1 | −1 / +1 |
| D / U | 2 | −1 / +1 |

## Solution

Lift the maze statically with pwntools, BFS to the vault, translate to keys, verify
locally, then replay to the instance.

Create `solve.py`:

```python
#!/usr/bin/python3
import sys, re
from collections import deque
from pwn import ELF, remote, context
context.log_level = "error"

raw = ELF("tunnel").read(0x20e0, 20*20*20*16)
def typ(a,b,c): return int.from_bytes(raw[(a*400+b*20+c)*16+12:][:4], "little")
goal = next((a,b,c) for a in range(20) for b in range(20) for c in range(20) if typ(a,b,c)==3)

MOVES = [('L',0,-1),('R',0,1),('B',1,-1),('F',1,1),('D',2,-1),('U',2,1)]
prev = {(0,0,0): None}; dq = deque([(0,0,0)])
while dq:
    p = dq.popleft()
    if p == goal: break
    for ch,ax,d in MOVES:
        q = list(p); q[ax] += d; q = tuple(q)
        if 0 <= q[ax] < 20 and typ(*q) != 2 and q not in prev:
            prev[q] = (p, ch); dq.append(q)
path = []; cur = goal
while prev[cur]:
    p, ch = prev[cur]; path.append(ch); cur = p
path.reverse()

io = remote(sys.argv[1], int(sys.argv[2]))
for ch in path:
    io.recvuntil(b"? "); io.sendline(ch.encode())
out = io.recvall(timeout=6).decode(errors="replace")
print(out)
print(re.search(r"HTB\{[^}]*\}", out).group())
```

Before touching the (short-lived) docker instance, prove the path against the local
binary — it prints the fake flag on success:

```bash
python3 -c "print('\n'.join('UUURFUR...RFRR'))" | ./tunnel
# ... You break into the vault and read the secrets within...
# HTB{fake_flag_for_testing}
```

Then run it against the instance for the real flag:

```bash
python3 solve.py <host> <port>
# HTB{...}
```

## Why it worked

The entire puzzle is static data shipped in the client binary — security through
obscurity. Arriving at the vault isn't cryptographically gated, so the level can be lifted
and solved offline with a plain graph search; the network only matters for the final flag
read.

## Fix / defense

- Don't treat embedded level/puzzle data as secret
  ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)).
- If a win-state must gate a secret, verify a cryptographic proof of the solution
  server-side, not mere arrival at a state.
- Keep the flag-read logic and its trigger entirely off the client-distributed binary.
