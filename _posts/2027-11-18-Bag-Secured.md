---
title: "Bag Secured"
date: 2027-11-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, dynamic-programming, knapsack, pwntools, tcp-interaction, algorithm]
description: "An easy Misc challenge: a TCP service presents 100 rounds of the classic 0/1 Knapsack optimisation problem. Solve each with 1D dynamic programming, but watch for the round-header interleaving that trips up naive line readers."
---

## Overview

`Bag Secured` is an easy HackTheBox **Misc** challenge. You connect to a raw TCP service that
runs 100 back-to-back instances of the
[0/1 Knapsack problem](https://en.wikipedia.org/wiki/Knapsack_problem): given N items each with
a weight and a value, and a bag of capacity C, find the maximum total value that fits. Answer all
100 rounds correctly and the server prints the flag.

The challenge tests two things: (1) knowing the standard 1D dynamic-programming solution
to knapsack, and (2) correctly parsing the server's interleaved round headers over a live
pwntools connection.

## The technique

**0/1 Knapsack via 1D bottom-up DP.** Build an array `dp` of length `C+1` where `dp[j]` is
the maximum value achievable with a bag capacity of exactly `j`. For each item `(w, v)` iterate
capacity values right-to-left — this ensures every item is counted at most once (the "0/1"
constraint):

```python
def knapsack(n, c, items):
    dp = [0] * (c + 1)
    for w, v in items:
        for j in range(c, w - 1, -1):   # right-to-left = each item used at most once
            if dp[j - w] + v > dp[j]:
                dp[j] = dp[j - w] + v
    return dp[c]
```

Runtime is O(N × C) per round. With N ≤ 100 and C ≤ 10^5, each test takes at most 10^7
comparisons — easily fast enough before the connection times out. Python native integers handle
values up to 10^10 without overflow.

## Solution

```python
#!/usr/bin/env python3
from pwn import *

HOST = "<host>"
PORT = <port>

def knapsack(n, c, items):
    dp = [0] * (c + 1)
    for w, v in items:
        for j in range(c, w - 1, -1):
            if dp[j - w] + v > dp[j]:
                dp[j] = dp[j - w] + v
    return dp[c]

conn = remote(HOST, PORT)
conn.recvuntil(b"Test 1/100\n")   # skip the intro banner

for test in range(1, 101):
    line = conn.recvline().decode().strip().split()
    n, c = int(line[0]), int(line[1])

    items = []
    for _ in range(n):
        w, v = map(int, conn.recvline().decode().strip().split())
        items.append((w, v))

    conn.sendline(str(knapsack(n, c, items)).encode())

    if test < 100:
        # Server echoes "Test (t+1)/100\n" before the next N C line — consume it
        conn.recvuntil(f"Test {test + 1}/100".encode())
        conn.recvline()
    else:
        print(conn.recvall(timeout=5).decode())
```

Run it against the spawned instance:

```bash
python3 solve.py
# … 100 rounds …
# You filled your bag with amazing weapons, your adventure will be a piece of cake now.
# Here is your reward: HTB{...}
```

## Why it worked

The DP is the textbook approach to 0/1 Knapsack. The tricky part here is the TCP framing:
after accepting each answer the server immediately sends `Test (t+1)/100\n` on the wire **before**
sending the next problem's `N C` line. A bare `recvline()` call expecting `N C` would instead
return `"Test 2/100"`, fail the `int()` parse, and crash.

The fix is `recvuntil` on the exact header string — this resynchronises the reader to a known
boundary regardless of how the server buffers its output — then a `recvline()` to consume the
trailing newline before reading the first data line of the next round.

## Fix / defense

This is an algorithmic puzzle rather than a security vulnerability — there is no attack surface
to harden. The lesson for CTF automation is to use `recvuntil(known_marker)` as a sync point
whenever a server interleaves protocol headers between data lines, rather than assuming a fixed
line order.
