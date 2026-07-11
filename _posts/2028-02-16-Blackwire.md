---
layout: post
title: "Blackwire"
date: 2028-02-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Coding]
tags: [hackthebox, challenge, coding, dynamic-programming, subsequence-counting, state-machine, bit-parsing]
description: "A story about a firmware logic bomb that boils down to a classic competitive-programming problem: counting the number of distinct subsequences of an opcode stream that equal a fixed pattern. The whole solve is recognizing the reduction and getting the DP iteration order right."
---

## Overview

Blackwire is a Medium coding challenge presented through the browser-based harness (a Monaco editor that POSTs your code to a `/run` endpoint, which executes it against hidden tests and returns the flag when they all pass). The narrative — a firmware logic bomb modeled as a finite state machine — dresses up a well-known dynamic-programming problem: counting how many distinct subsequences of a stream equal a fixed target pattern.

## The technique

The firmware is one long binary string. The first input line gives two integers `T` and `L`:

- The next `T * 20` bits are transition-table entries, 20 bits each: the first 12 bits are a current state `S`, the next 8 bits are the opcode required to move from state `S` to state `S+1`. So each entry defines `req[S] = opcode`.
- The following `L` bits are the actual execution stream: `L / 8` eight-bit opcodes, in order.

The machine starts in state 0 and must reach the final state `T`, advancing exactly one state at a time. As it walks the opcode stream in order, whenever the current opcode equals `req[S]` it *may* advance to `S+1` — but it doesn't have to. That optionality is what creates multiple paths. The task is to count how many distinct ways (distinct choices of opcode positions) drive the machine from state 0 to state `T`.

Strip away the story and this is precisely: **how many subsequences of the opcode stream equal the pattern `[req[0], req[1], …, req[T-1]]`?**

## Solution

The standard count-distinct-subsequences DP. `cnt[k]` holds the number of distinct subsequences that have matched the first `k` pattern tokens; each incoming opcode that matches pattern token `k-1` adds `cnt[k-1]` new ways to reach `cnt[k]`. The iteration over pattern indices must go **high to low**, so a single stream element advances at most one level per step — going low-to-high would let one opcode cascade through repeated pattern tokens and overcount.

Create `solve_prog.py` (this is what the `/run` harness executes against the hidden tests):

```python
import sys
data = sys.stdin.read().split()
T = int(data[0]); L = int(data[1])
bits = ''.join(data[2:])
table = bits[:T*20]
ops_bits = bits[T*20:T*20+L]

req = {}
for i in range(T):
    e = table[i*20:(i+1)*20]
    req[int(e[:12], 2)] = e[12:20]           # 12-bit state -> 8-bit opcode

pattern = [req[k] for k in range(T)]
ops = [ops_bits[i:i+8] for i in range(0, len(ops_bits), 8)]

cnt = [0] * (T + 1); cnt[0] = 1
for o in ops:
    for k in range(T, 0, -1):                # high -> low is essential
        if o == pattern[k-1]:
            cnt[k] += cnt[k-1]
print(cnt[T])
```

On the worked example (`T=3, L=240`) this prints `4`, matching the spec. Submitting it to the harness runs it against every hidden case and returns the flag live:

```
HTB{...}
```

## Why it worked

The counts can grow enormous, so Python's arbitrary-precision integers are the pragmatic language choice — no modulus juggling. The only real trap is the DP direction: iterate pattern positions from `T` down to `1`. The rest is careful bit-slicing of a single concatenated binary string into fixed-width fields.

## Fix / defense

There's nothing to defend here — it's an algorithmic puzzle, not a vulnerability. The transferable lesson is recognition: any "count the ways to complete an ordered chain of required events, where each matching event is an optional advance" problem is subsequence counting, solvable in `O(n·T)` with a one-dimensional DP.
