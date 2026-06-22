---
layout: post
title: "HackTheBox Challenge: Fentastic Moves"
date: 2027-09-10 09:00:00 -0500
categories: [HackTheBox, Challenges]
tags: [hackthebox, challenge, misc, chess, stockfish, automation, scripting, fen]
---

## Overview

**Fentastic Moves** is an Easy HackTheBox **Misc** challenge. Connecting with `nc` drops you into a
chess trainer that renders a position as an ANSI-coloured Unicode board and asks for White's best move
in coordinate notation (`e2e4`). Answer **25 positions back-to-back** under a time limit and you get the
flag. No human reads and solves 25 tactical puzzles that fast — the whole challenge is a scripting task:
parse each board into a position string, ask a chess engine for the best move, and feed it back.

## The technique

```
Let's see if you can find the best moves for 25 puzzles! (Don't take too long tho :P)
White to Move (always)
Example: e2e4
<ANSI-coloured unicode board>
What's the best move?
```

The flavour text *is* the hint:

> *"Garry told me to catch some fish 20 meters deep"*

- **Garry** → Garry **Kasparov** (chess world champion).
- **fish** → **Stockfish**, the chess engine.
- **20 meters deep** → run Stockfish at search **`go depth 20`**.

So the solve is three small pieces: parse the rendered board to a [FEN](https://en.wikipedia.org/wiki/Forsyth%E2%80%93Edwards_Notation)
string, drive Stockfish at depth 20 for the best move, and loop the 25-round protocol.

The one real subtlety is **determinism**. The server stored a single expected move per puzzle,
precomputed with one specific engine version at one specific depth. Many of these positions are forced
mates, where several different moves all deliver mate — so a time-based, non-deterministic search (such
as `python-chess`'s `engine.play()`) can return a *different* mating move and get rejected. The fix is to
reproduce the reference exactly: raw UCI `go depth 20` against the **same engine version** (Stockfish 16,
not 16.1).

## Solution

Parsing the board: strip the ANSI escapes, anchor on the `a b c d e f g h` footer line, and read the
piece glyph at the fixed character index `3 + 2*file` of each of the eight rank lines above it. Unicode
`U+2654..2659` are the white pieces `K Q R B N P`; `U+265A..265F` are the black pieces `k q r b n p`.
Emit ranks 8→1 and append `" w - - 0 1"` (White always moves).

Create `solve.py`:

```python
import re, sys, subprocess
from pwn import remote

HOST, PORT = sys.argv[1], int(sys.argv[2])
SF = "./stockfish16/stockfish-ubuntu-x86-64-avx2"   # Stockfish 16, run directly (no apt/root)
DEPTH = 20

GLYPH = {"♔": "K", "♕": "Q", "♖": "R", "♗": "B", "♘": "N", "♙": "P",
         "♚": "k", "♛": "q", "♜": "r", "♝": "b", "♞": "n", "♟": "p"}
ANSI = re.compile(r"\x1b\[[0-9;]*m")

class Fish:
    def __init__(self, path):
        self.p = subprocess.Popen(path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  bufsize=1, universal_newlines=True)
        self._cmd("uci"); self._wait("uciok")
    def _cmd(self, c): self.p.stdin.write(c + "\n"); self.p.stdin.flush()
    def _wait(self, tok):
        for line in self.p.stdout:
            if line.startswith(tok): return line
    def bestmove(self, fen):
        self._cmd("ucinewgame"); self._cmd("isready"); self._wait("readyok")
        self._cmd(f"position fen {fen}"); self._cmd(f"go depth {DEPTH}")
        return self._wait("bestmove").split()[1]

def parse_board(blob):
    lines = ANSI.sub("", blob).splitlines()
    idx = next(i for i, l in enumerate(lines) if "a b c d e f g h" in l)
    rows = []
    for ln in lines[idx - 8: idx]:          # rank 8 (top) .. rank 1 (bottom)
        row, empty = "", 0
        for f in range(8):
            ch = ln[3 + 2 * f] if 3 + 2 * f < len(ln) else " "
            if ch in GLYPH:
                if empty: row += str(empty); empty = 0
                row += GLYPH[ch]
            else:
                empty += 1
        if empty: row += str(empty)
        rows.append(row)
    return "/".join(rows) + " w - - 0 1"

def main():
    fish = Fish(SF)
    io = remote(HOST, PORT)
    io.recvuntil(b"Example: e2e4")
    for n in range(1, 26):
        blob = io.recvuntil(b"What's the best move?").decode("utf-8", "replace")
        fen = parse_board(blob)
        move = fish.bestmove(fen)
        print(f"[{n}] {fen}  ->  {move}")
        io.sendline(move.encode())
    print(io.recvall(timeout=15).decode("utf-8", "replace"))

if __name__ == "__main__":
    main()
```

Grab the engine without root — download the official Stockfish 16 release tarball from GitHub, extract,
and run the binary directly:

```bash
python3 solve.py <host> <port>
```

The script walks all 25 boards in a few seconds — each depth-20 search is sub-second on an AVX2 build —
and the server prints the flag after the 25th correct move:

```
Correct!, next one!
You did it! Here's your flag: HTB{...}
```

Promotions come out of the engine already encoded as UCI (`c7c8q`), so they need no special handling.

## Why it worked

The position is fully observable and White is always to move, so a strong engine simply *is* the answer
key. The author precomputed the expected move for each puzzle with Stockfish at depth 20; reproducing the
exact engine version and search depth regenerates the identical move, including in the forced-mate
positions where multiple moves would otherwise be "equally best."

## Fix / defense

This is an automation puzzle rather than a security flaw, so the takeaway is methodological: read CTF
flavour text **literally** as a parameter hint, and when a service grades structured output against a
stored deterministic answer, match the reference *tool and its exact version and parameters* — not merely
"a correct answer." Reproducing the grader beats out-computing it.
