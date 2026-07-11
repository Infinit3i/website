---
layout: post
title: "MazeOfPower"
date: 2028-04-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, golang, prng, seed-recovery, crc32, maze, redpwn-pow, cwe-330]
description: "A Go maze TUI hides its walls by rendering them as spaces, but seeds its RNG from crc32 of the proof-of-work string you send — so you control the seed, regenerate the maze offline with the same library, BFS it, and replay the moves."
---

## Overview

MazeOfPower is a Hard HackTheBox Reversing challenge. A Go binary gates on a [redpwn](https://github.com/redpwn/pow) proof-of-work, then shows an interactive maze ("Controls: q/k/j/h/l") and prints the flag if you navigate start-to-goal within 20 seconds. The catch is that the walls are never shown to you — but the maze's randomness is seeded from a value you control, which is [CWE-330](https://cwe.mitre.org/data/definitions/330.html): [use of insufficiently random values](https://cwe.mitre.org/data/definitions/330.html), here a PRNG seeded from attacker-supplied input.

## The problem: you can't see the maze

The binary renders the maze with `github.com/itchyny/maze`, but with a custom `Format` whose `Wall` glyph is two spaces. Over a socket, a pipe, or even a PTY, the frame shows only `S` (top-left) and `E` (bottom-right) on a blank grid — the wall layout is never transmitted. You cannot solve what you cannot see.

## The key: you control the seed

Disassembling `main.main` reveals how the maze RNG is seeded:

```
main.go:57   CALL hash/crc32.ChecksumIEEE(SB)
main.go:57   CALL math/rand.Seed(SB)
```

The value fed to `crc32.ChecksumIEEE` is the line read by `bufio.ReadString('\n')` — the **proof-of-work solution string you type**, including its trailing newline:

```
seed = crc32.ChecksumIEEE(pow_solution + "\n")
```

You send the PoW solution, so you know the seed, so the maze is fully deterministic and reproducible offline.

## Solution

Read the exact library version (`go version -m ./main` → `github.com/itchyny/maze v0.0.9`) and `go get` it. Same version + same seed + same call order reproduces the maze bit-for-bit. Grab the dimensions from the inline `NewMaze` constants (`$0x19` = 25 rows, `$0x32` = 50 cols; Start `(0,0)`, Goal `(24,49)`), then regenerate, BFS, and emit keys:

```go
rand.Seed(int64(crc32.ChecksumIEEE([]byte(powLine)))) // powLine includes trailing "\n"
m := maze.NewMaze(25, 50)
m.Generate()

// BFS on m.Directions: a set bit (Up=1, Down=2, Left=4, Right=8) means an open edge.
// itchyny/maze dx/dy: Up=row-1, Down=row+1, Left=col-1, Right=col+1  ->  vim keys k/j/h/l.
start, goal := pt{0, 0}, pt{24, 49}
// ... standard BFS, reconstruct path goal->start, map each step to its key ...
fmt.Print(string(path)) // e.g. "llljjjlllljlkkljlllkljjljljjlk..."
```

Top-level `math/rand` output for a given `rand.Seed(n)` is stable across Go releases — building the solver with go1.26 against the go1.22 binary produced identical mazes. Send the resulting key string as the maze answer.

For the PoW, don't reimplement the sloth VDF (modular square-roots plus a bit-flip, not plain squaring) — the `https://pwn.red/pow` installer caches a solver binary at `~/.cache/redpwnpow/redpwnpow-v0.1.2-linux-amd64`; call it directly per challenge (~1.5 s).

Develop entirely offline first: the binary reads the answer from stdin and the flag from `/flag.txt`, so a correct path prints `Here is your flag: HTB{f4k3_fl4g}` locally. Then spawn a fresh instance and run PoW → generate → solve → send back-to-back inside the 20-second window. Result: `Here is your flag: HTB{...}`. The flag is derived live from the on-chain instance, never copied.

## Why it worked

A PRNG seeded from attacker-controlled input (the `crc32` of the string you send) is not random from the attacker's point of view — it is a pure function you can evaluate offline. Hiding the walls in the rendering is irrelevant once the seed is in your hands; you regenerate the identical maze with the identical library and solve it with a plain BFS.

## Fix / defense

Seed puzzle/game RNG from a server-side secret the client never sees, or from `crypto/rand` — never from client-supplied data. If the maze must be solved live, transmit it (or a commitment to it) rather than relying on the client's inability to see the walls; security by obscured rendering collapses the moment the generator is reproducible.
