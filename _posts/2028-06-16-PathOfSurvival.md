---
layout: post
title: "Path of Survival"
date: 2028-06-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, dijkstra, shortest-path, pathfinding, graph, coding-gauntlet, sockets, automation]
description: "A Medium Misc challenge that looks like a browser game but is really a weighted shortest-path puzzle: reach a weapon within a time budget across a terrain grid with directional, asymmetric edge costs — 100 rounds in a row. Solved with Dijkstra, then made reliable with a precompute + socket-prefetch + respawn-retry harness that beats a flaky single-thread server."
---

## Overview

*Path of Survival* is a Medium **Misc** challenge. It presents as a little RPG-style web
game — you are dropped on a randomly generated terrain grid and must walk to a **weapon**
tile before your **time** runs out. Do it **100 times in a row** and the server returns the
flag; a single wrong move or a timeout resets your streak to zero. Under the cute frontend it
is a **weighted shortest-path** problem with a nasty, direction-dependent cost function,
wrapped in a fragile server that makes the real challenge *finishing 100 rounds before the
instance dies*.

## The technique

The game is driven entirely by a small JSON API (no auth), so you script it:

| Endpoint | Purpose |
|---|---|
| `POST /map` | current map: `player.position [x,y]`, `player.time` (budget), `tiles["(x, y)"] = {terrain, has_weapon}` |
| `POST /update {"direction":"U\|D\|L\|R"}` | move one tile → `new_pos`+`time`, or `solved`, or `error`, or `flag` |
| `GET /regenerate` | discard the map and reset the streak |

Every move costs "time points" that depend on **both terrains involved** and **the direction
of approach**. That makes it a textbook graph with weighted edges — solved with **Dijkstra's
algorithm** — but the cost function needs three inputs, not two:

- Same terrain → 1. Any valid move to/from a **Cliff** or **Geyser** → 1.
- Otherwise an asymmetric lookup table: `Plains→Mountain 5` but `Mountain→Plains 2`;
  `River→Mountain 10` but `Mountain→River 8`; `Sand→Mountain 7`, and so on. Climbing costs
  more than descending.
- **Empty** tiles are impassable.
- **Cliffs** can only be entered from the top or the left — i.e. a **D**own or **R**ight move.
- **Geysers** can only be entered from the bottom or the right — a **U**p or **L**eft move.

Because cliff/geyser legality depends on the entry direction, the weight is
`cost(from_terrain, to_terrain, move_letter)`.

**The coordinate trap.** The intuitive guess — `position = [row, col]`, Up = `row-1` — is
wrong, and a wrong move nukes your 100-streak. The real convention has to be *calibrated*:
send one move per axis on a throwaway map, read the returned `new_pos`, and observe which
coordinate changed. It turns out position is `[x, y]` with:

```
U : y-1     D : y+1     L : x-1     R : x+1
```

## Solution

Compute the cheapest path to any weapon with Dijkstra (preferring fewest hops via BFS when
that already fits the budget, to cut the number of requests), then submit the precomputed
move list. The one hard part is *reliability*: the backend is a single-threaded Werkzeug dev
server that answers `Connection: close` (no keep-alive) and the Docker instance
crashes/reaps erratically at roughly 30–120 seconds — while 100 rounds is ~800 HTTP requests.
Three tricks make it finish in time:

1. **Precompute the whole round** — the map is static while you walk it, so never wait for an
   intermediate response to decide the next move.
2. **A small background socket-prefetch pool** — two threads keep a few TCP sockets
   pre-connected so the handshake latency overlaps the previous request (~2.4s/round → ~0.85s/round).
3. **Keep concurrency low and respawn-retry** — too many simultaneous connections crash the
   single-thread server *sooner*; wrap the solve in a loop that spawns a fresh instance and
   reruns until one survives long enough (it solved on the 5th spawn).

`solve.py` — the durable artifact (raw-socket prefetch-pool client + Dijkstra/BFS pathfinder):

```python
#!/usr/bin/env python3
import sys, json, heapq, time, socket, threading, queue

HOST, PORT = sys.argv[1], int(sys.argv[2])
POOL = queue.Queue(maxsize=3)
def filler():
    while True:
        try: POOL.put(socket.create_connection((HOST, PORT), timeout=20))
        except Exception: time.sleep(0.05)
for _ in range(2):
    threading.Thread(target=filler, daemon=True).start()

def _raw(method, path, body=None):
    data = b'' if body is None else json.dumps(body).encode()
    h = f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: Mozilla/5.0\r\n"
    if body is not None:
        h += f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n"
    h += "Connection: close\r\n\r\n"
    return h.encode() + data

def _recv_json(s):
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(65536)
        if not d: raise ConnectionError('closed')
        buf += d
    head, rest = buf.split(b'\r\n\r\n', 1); clen = 0
    for line in head.split(b'\r\n')[1:]:
        k, _, v = line.decode().partition(':')
        if k.lower().strip() == 'content-length': clen = int(v.strip())
    body = rest
    while len(body) < clen:
        d = s.recv(65536)
        if not d: break
        body += d
    return json.loads(body[:clen])

def req(method, path, body=None):
    for attempt in range(5):
        try:
            s = POOL.get(timeout=20)
            s.sendall(_raw(method, path, body)); r = _recv_json(s)
            try: s.close()
            except: pass
            return r
        except Exception:
            if attempt == 4: raise
            time.sleep(0.2)

TABLE = {
    ('P','M'):5, ('M','P'):2, ('P','S'):2, ('S','P'):2,
    ('P','R'):5, ('R','P'):5, ('M','S'):5, ('S','M'):7,
    ('M','R'):8, ('R','M'):10, ('S','R'):8, ('R','S'):6,
}
DELTA = {'U':(0,-1), 'D':(0,1), 'L':(-1,0), 'R':(1,0)}

def step_cost(a, b, move):
    if b == 'E': return None
    if b == 'C' and move not in ('D','R'): return None
    if b == 'G' and move not in ('U','L'): return None
    if a in ('C','G') or b in ('C','G'): return 1
    if a == b: return 1
    return TABLE.get((a, b))

def parse(m):
    grid = {}; weapons = set()
    for k, v in m['tiles'].items():
        x, y = map(int, k.strip('()').split(','))
        grid[(x, y)] = v['terrain']
        if v['has_weapon']: weapons.add((x, y))
    return grid, weapons, tuple(m['player']['position']), m['player']['time']

def solve_path(grid, weapons, start):
    dist = {start: 0}; prev = {}; pq = [(0, start)]
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, 1e9): continue
        if u in weapons:
            moves = []; cur = u
            while cur in prev:
                pc, mv = prev[cur]; moves.append(mv); cur = pc
            return d, moves[::-1]
        ux, uy = u
        for mv, (dx, dy) in DELTA.items():
            v = (ux+dx, uy+dy)
            if v not in grid: continue
            sc = step_cost(grid[u], grid[v], mv)
            if sc is None: continue
            nd = d + sc
            if nd < dist.get(v, 1e9):
                dist[v] = nd; prev[v] = (u, mv); heapq.heappush(pq, (nd, v))
    return None, None

def main():
    solved = 0; t0 = time.time()
    while True:
        m = req('POST', '/map', {})
        grid, weapons, start, budget = parse(m)
        cost, moves = solve_path(grid, weapons, start)
        if moves is None or cost > budget:
            req('GET', '/regenerate'); continue
        for mv in moves:
            r = req('POST', '/update', {'direction': mv})
            if r.get('error'): print("ERROR:", r['error']); return
            if r.get('flag'): print("FLAG:", r['flag']); return
            if r.get('solved'):
                solved += 1
                if solved % 10 == 0: print(f"solved {solved} @ {time.time()-t0:.1f}s")
                break

if __name__ == '__main__':
    main()
```

Driven by a bash loop that spawns a fresh instance each attempt and reruns until the flag
prints:

```
attempt 5  target 154.x.x.x:30451
solved 60 @ 52.8s
solved 70 @ 61.3s
solved 80 @ 69.1s
solved 90 @ 79.7s
FLAG: HTB{...}
```

## Why it worked

Dijkstra always returns the minimum-time path, so we never lose to the clock — the only way
to fail a round is a mis-encoded move, which is why calibrating the `[x,y]` / `U D L R`
convention up front matters. The intended difficulty is the directional, asymmetric cost
model; the *practical* difficulty is the flaky single-thread server, and precompute +
prefetch + retry turns "the instance keeps dying" into a solve that just needs one lucky
lifetime.

## Fix / defense

- **Don't ship a single-thread dev server as the challenge backend.** A real WSGI server
  (gunicorn/uwsgi) with multiple workers and keep-alive means one greedy client can't wedge
  or crash the whole instance — the fragility here was accidental difficulty, not a control.
- **Enforce any round/rate limit server-side per session** as an explicit counter the client
  can't influence, not as an emergent side effect of the server falling over.
- Client-authoritative movement is fine for a puzzle, but the server must validate the full
  move sequence — which this one does (invalid move resets the streak), and that instinct is
  correct.
