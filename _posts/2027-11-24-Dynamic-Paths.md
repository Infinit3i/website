---
title: "Dynamic Paths"
date: 2027-11-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, dynamic-programming, min-path-sum, pwntools, tcp]
description: "A raw-TCP coding gauntlet that wants the minimum path sum across 100 grids, moving only down or right. The whole solve is the classic min-path-sum DP plus one parsing trap: the example text's arrows collide with the input prompt."
---

## Overview

Dynamic Paths is a Misc (Easy) challenge that is really an algorithmic gauntlet over a raw TCP socket. You connect with `nc`, the server runs **100 rounds**, and each round hands you a grid and asks for the cheapest path from the top-left corner to the bottom-right corner while moving **only down or right**. Answer all 100 correctly and it prints the flag. The name is the hint — the intended tool is dynamic programming.

## The technique

Each round prints the grid dimensions `i j` (`2 <= i,j <= 100`) followed by `i*j` integers in row-major order (`1 <= n <= 50`). You start at cell `(0,0)`, may step only **right** or **down**, and must report the minimum sum of the cells you pass through.

This is the textbook **minimum path sum** problem. Because a cell can only be reached from its left neighbour or its upper neighbour, the cheapest cost to reach `(r,c)` is its own value plus the cheaper of the two ways in:

```
dp[r][c] = grid[r][c] + min(dp[r-1][c], dp[r][c-1])
```

with the first row and first column degenerating to a running sum. The answer is `dp[i-1][j-1]`. A 1D rolling row makes it `O(i*j)` time and `O(j)` space — trivial even at the 100×100 worst case. Greedy (always step toward the smaller neighbour) is *wrong*; the optimal path can pass through a locally-worse cell to reach a much cheaper region later.

The only real trap is **parsing**. The intro the server prints includes the example's optimal route:

```
(Optimal route is 2 -> 5 -> 2 -> 1 -> 3 -> 4)
```

So a naive `recvuntil(b"> ")` matches the `-> ` arrows inside that sentence rather than the real input prompt, and the parser desyncs on the very first round. The fix is to synchronise on a token that only appears once per round and never in flavour text — `recvuntil(b"Test ")` — then read the `n/100` line, the dimensions, and the numbers explicitly.

## Solution

`solve.py` — runnable verbatim against a fresh instance:

```python
#!/usr/bin/env python3
import sys
from pwn import remote, context
context.log_level = 'error'

HOST, PORT = sys.argv[1], int(sys.argv[2])

def min_path_sum(rows, cols, nums):
    g = [nums[r*cols:(r+1)*cols] for r in range(rows)]
    dp = [0]*cols
    for r in range(rows):
        for c in range(cols):
            if r == 0 and c == 0:
                dp[c] = g[0][0]
            elif r == 0:                       # top row: only from the left
                dp[c] = dp[c-1] + g[r][c]
            elif c == 0:                       # left col: only from above
                dp[c] = dp[c] + g[r][c]
            else:
                dp[c] = min(dp[c], dp[c-1]) + g[r][c]
    return dp[cols-1]

io = remote(HOST, PORT)
for t in range(100):
    io.recvuntil(b"Test ")                     # sync on the round marker, NOT "> "
    io.recvline()                              # "n/100"
    i, j = map(int, io.recvline().split())
    nums = list(map(int, io.recvline().split()))
    while len(nums) < i*j:                      # in case the numbers wrap lines
        nums += list(map(int, io.recvline().split()))
    io.sendline(str(min_path_sum(i, j, nums)).encode())

print(io.recvall(timeout=5).decode(errors='replace'))   # prints the flag
io.close()
```

Run it:

```bash
python3 solve.py <host> <port>
```

After the 100th correct answer the server prints the reward line containing `HTB{...}`.

## Why it worked

Grid traversal has optimal substructure: any optimal path ending at `(r,c)` is an optimal path to one of its in-neighbours plus the final step. That lets DP compute every cell's best cost in a single sweep, and the 100 rounds are just a throughput check that you automated the answer instead of solving by hand. The parsing gotcha is the only thing that turns an "easy" into a frustrating debug — choosing a round-sync token that doesn't collide with the prompt (`-> ` vs `> `) is the durable lesson.

## Fix / defense

There is nothing to "patch" here — it is a coding gauntlet, not a vulnerable service. The reusable takeaway is the **TCP coding-challenge harness pattern**: a problem server that prints one structured problem per round and expects an answer line. Sync on a stable per-round marker, parse the input, compute, `sendline`, repeat — and always read the prompt text for delimiter collisions before picking your `recvuntil` token.
