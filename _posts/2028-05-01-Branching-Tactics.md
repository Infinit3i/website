---
layout: post
title: "Branching Tactics"
date: 2028-05-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, algorithms, trees, lca, binary-lifting, numpy, socket]
description: "A 100-round networked coding gauntlet over raw TCP: each round is a tree and a set of troops that walk toward a destination with limited energy. The maths is a k-th-node-on-path query solved with binary-lifting LCA — but the real fight is a newline-vs-space answer format and making Python fast enough for 300k-node trees before the server resets."
---

## Overview

Branching Tactics is a Medium HackTheBox **Misc** (algorithmic) challenge from Business CTF 2024. You connect to a raw TCP service that runs **100 rounds**; each round hands you a tree and a batch of "troops," and you must answer where each troop ends up. Clear all 100 and it prints the flag. The underlying maths is clean; the difficulty is in reading the protocol carefully and making the solution fast enough.

## The technique

Each round gives `n` nodes (up to 3·10^5) and `n-1` edges — an undirected **tree** — then `m` troops, each a triple `(s, d, e)`. A troop walks the *unique* tree path from `s` toward `d`, spending one energy per edge, and stops after `k = min(e, dist(s,d))` steps. Report the node it stops at, in order.

The node `k` steps along the path `s→d` is found with a **lowest-common-ancestor** query. Root the tree at node 1, compute each node's depth and `2^i`-th ancestors (binary lifting), then:

```
l       = lca(s, d)
up_len  = depth[s] - depth[l]          # length of the ascending part s..lca
dist    = up_len + depth[d] - depth[l]
k       = min(e, dist)
answer  = kth_ancestor(s, k)           if k <= up_len     # still climbing toward the lca
        = kth_ancestor(d, dist - k)    otherwise          # descending toward d
```

Preprocessing is `O(n log n)`; each troop is `O(log n)`.

## Solution

Two things decide whether it actually works against the live server:

**1. Answers are newline-separated, not space-separated.** The worked example in the intro prints its two answers on separate lines. If you space-join, every round with a single troop passes (there's no separator to get wrong) and then the server silently closes the socket on the first multi-troop round — which reads exactly like a wrong answer with no error message.

**2. It has to be fast.** With `n` up to 300k, up to `n` queries per round, and 100 rounds, a pure-Python binary lifting is too slow on the big late rounds and the server times out and sends a TCP reset. The fix is to vectorise everything with numpy — the up-table level build is a single gather, `up[k] = up[k-1][up[k-1]]`, and the LCA / k-th-ancestor steps run over *all* queries at once with masked `numpy.where` lifts.

Core of the solver:

```python
import numpy as np
from collections import deque

def solve(n, edges, queries):     # queries: numpy arrays s, d, e
    LOG = max(1, n.bit_length())
    depth = np.zeros(n + 1, dtype=np.int64)
    up = np.zeros((LOG, n + 1), dtype=np.int64)
    adj = [[] for _ in range(n + 1)]
    for a, b in edges:
        adj[a].append(b); adj[b].append(a)
    vis = bytearray(n + 1); vis[1] = 1; up[0][1] = 1
    dq = deque([1])
    while dq:
        u = dq.popleft()
        for v in adj[u]:
            if not vis[v]:
                vis[v] = 1; depth[v] = depth[u] + 1; up[0][v] = u; dq.append(v)
    for k in range(1, LOG):
        up[k] = up[k - 1][up[k - 1]]            # vectorised level build

    def kth(nodes, kk):
        nodes = nodes.copy(); kk = kk.copy()
        for i in range(LOG):
            sel = ((kk >> i) & 1).astype(bool)
            nodes[sel] = up[i][nodes[sel]]
        return nodes

    def lca(a, b):
        a = a.copy(); b = b.copy()
        sw = depth[a] < depth[b]
        a, b = np.where(sw, b, a), np.where(sw, a, b)
        a = kth(a, depth[a] - depth[b])
        res = np.where(a == b, a, 0)
        for k in range(LOG - 1, -1, -1):
            ua, ub = up[k][a], up[k][b]
            lift = (a != b) & (ua != ub)
            a = np.where(lift, ua, a); b = np.where(lift, ub, b)
        return np.where(res != 0, res, up[0][a])

    s, d, e = queries
    l = lca(s, d)
    ul = depth[s] - depth[l]
    dist = ul + depth[d] - depth[l]
    k = np.minimum(e, dist)
    return np.where(k <= ul, kth(s, k), kth(d, dist - k))
```

The I/O harness: skip the intro up to the `Example Response:` label (its prose contains numbers that would pollute a naive integer parser), anchor each round on the `Test k/100` header, and drain each scenario by reading until a short recv-timeout with enough integers (the server sends the whole round then blocks for the answer). The HTB API needs a browser `User-Agent` or it returns 403, instances expire in minutes, and the game closes the socket on any wrong answer — so respawn and retry the whole 100-round game, guarding the final read (where the flag arrives) against a connection reset.

## Why it worked

The problem reduces to a standard k-th-node-on-path query, and binary-lifting LCA answers it in logarithmic time. Everything else is engineering: matching the exact answer format and moving the hot loops into numpy so the largest rounds finish before the server's patience runs out.

## Fix / defense

Not a security bug — a competitive-programming task. The takeaways are general: read the wire format from the worked example (a wrong separator fails silently), and profile against the stated input bounds before assuming a naive implementation is fast enough.
