---
layout: post
title: "Insane Bolt"
date: 2028-02-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, automation, bfs, pathfinding, socket, scripting]
---

## Overview

Insane Bolt is a Medium Misc challenge — an automated coding gauntlet. A `nc` service streams an emoji maze each round and asks for a route; you must solve **500 mazes in a row**, guiding a robot 🤖 to a diamond 💎 by the shortest route while collecting bolts 🔩, to hit 500 💎 and ≥5000 🔩 and win the flag. It's a scripting problem: parse the grid, BFS, emit the moves, loop the socket.

## Reading the grid

Each cell is one emoji (with a stray `U+FE0F` variation selector to strip):

| Emoji | Codepoint | Meaning |
|-------|-----------|---------|
| 🔥 | U+1F525 | border wall |
| ☠️ | U+2620 | obstacle (not steppable) |
| 🔩 | U+1F529 | bolt — walkable path cell |
| 🤖 | U+1F916 | robot (start) |
| 💎 | U+1F48E | diamond (goal) |

Steppable = `{🔩, 🤖, 💎}`; everything else is a wall.

## The catch — moves are D/L/R only

The route format is "DLR (Down, Left, Right)" — there is **no Up**. So it's a breadth-first search using exactly three neighbor moves: `down (r+1,c)`, `left (r,c-1)`, `right (r,c+1)`. Reconstruct the move string from the BFS parent map and send it. The shortest path walks over enough bolts that the ≥5000 total is met across 500 mazes.

## Solution

Connect once, then loop: read to the `>` prompt, parse the grid, BFS, send the `D/L/R` string, repeat until `HTB{...}` appears.

```python
import socket, sys, re, time
from collections import deque
IP, P = sys.argv[1], int(sys.argv[2]); WALK = {'🔩','🤖','💎'}
s = socket.socket(); s.connect((IP,P)); buf=b""
def recv_until(tok, t=8):
    global buf; tok=tok.encode(); end=time.time()+t; s.settimeout(t)
    while tok not in buf and time.time()<end:
        try: d=s.recv(65536)
        except: break
        if not d: break
        buf+=d
    data=buf; buf=b""; return data.decode('utf-8','replace')
def parse(g):
    return [[c for c in l if ord(c)>0x2000 and ord(c)!=0xFE0F]
            for l in g.splitlines()
            if any(ord(c)>0x2600 for c in l)]
def solve(grid):
    R=len(grid); C=max(len(r) for r in grid)
    for r in grid: r += ['🔥']*(C-len(r))
    start=goal=None
    for i in range(R):
        for j in range(C):
            if grid[i][j]=='🤖': start=(i,j)
            if grid[i][j]=='💎': goal=(i,j)
    prev={start:None}; q=deque([start])
    while q:
        cur=q.popleft()
        if cur==goal: break
        for mv,dr,dc in [('D',1,0),('L',0,-1),('R',0,1)]:
            ni,nj=cur[0]+dr,cur[1]+dc
            if 0<=ni<R and 0<=nj<C and (ni,nj) not in prev and grid[ni][nj] in WALK:
                prev[(ni,nj)]=(cur,mv); q.append((ni,nj))
    path=[]; node=goal
    while prev[node] is not None:
        p,mv=prev[node]; path.append(mv); node=p
    return ''.join(reversed(path))
recv_until('>'); s.sendall(b'2\n')
while True:
    data=recv_until('>')
    m=re.search(r'HTB\{[^}]+\}', data)
    if m: print("FLAG:", m.group(0)); break
    grid=parse(data)
    if not any('💎' in r for r in grid): break
    s.sendall(solve(grid).encode()+b'\n')
```

`python3 solve.py <ip> <port>` clears all 500 rounds in seconds and prints the flag.

## Why it worked

There's no vulnerability — it's an automation gate. The two things to get right are decoding the emoji grid into a matrix (strip `U+FE0F`, map each emoji to a cell type) and running BFS with the correct, constrained move set (Down/Left/Right, no Up). Everything else is looping the socket.

## Takeaway

For any "solve N rounds over `nc`" challenge: keep one connection, buffer input until the round's prompt token, identify the underlying algorithm (here, BFS shortest path on a grid), and let the script run. Mind constraints like a restricted move set — they change the neighbor function, not the approach.
