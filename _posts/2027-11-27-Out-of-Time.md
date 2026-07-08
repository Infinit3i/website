---
title: "Out of Time"
date: 2027-11-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, side-channel, power-analysis, timing, prefix-oracle]
description: "A Hardware challenge that returns a power trace for every password guess. The check compares the secret character-by-character with an early exit on the first mismatch, so the trace leaks the matched-prefix length — recover the flag one character at a time against a NUL reference, no CPA and no key required."
---

## Overview

Out of Time is a Hardware (Easy) challenge. You get `socket_interface.py` and a live instance.
Option `1` ("Try password") takes a guess and returns a base64-encoded NumPy **power trace** (1000
`float64` samples) of the device verifying that guess. There is no option that hands you the flag —
the flag *is* the secret password, and it has to be read out of the side-channel. The trap is that
the trace leaks **how far the comparison got**, not which bytes were processed, so the clean solve is
a [matched-prefix-length oracle](https://cwe.mitre.org/data/definitions/208.html), recovered one
character at a time.

## The technique

The verifier compares the guess to the secret character by character and **early-exits on the first
mismatch** (think `strcmp`). Every character that matches is one more loop iteration before the
bail-out, and each iteration leaves a distinct signature in the power trace. So a guess whose prefix
matches the secret one character *further* than another guess produces a measurably different trace —
the extra comparison shows up as a large deviation.

Crucially, the byte *values* do **not** leak. Correlation Power Analysis (the reflex move for a
power-trace challenge) modelling the leakage as `HW(guess[i] ⊕ secret[i])` — or `HW(guess[i])`, or
the identity of the byte — all sit at the noise floor (~0.26 correlation with 250 traces). That null
result is itself the diagnostic: when no byte-value model correlates, the trace is leaking **control
flow** (how many compares ran), not data. Autocorrelation confirms it — a clean period-12 operation
structure (~83 ops per trace) consistent with a per-character compare loop.

So the move is to stop modelling values and treat the trace as a prefix-length oracle.

## Solution

Greedy recovery, one character at a time, starting from the known flag prefix `HTB{`:

1. Build a **reference** trace with a guaranteed-wrong next character: `trace(prefix + "\x00")`.
   NUL is never the real character, so the matched prefix length is pinned at `len(prefix)`.
2. For each printable candidate `c` (ASCII 33–126), take `trace(prefix + c)` and score it
   `d = sum(|trace − ref|)`.
3. The **correct** character extends the matched prefix by one, so its trace diverges strongly from
   the reference. In practice the correct character scored ~150 while every wrong character sat at
   ~60 — a threshold of 100 separates them cleanly.
4. Append the winner and repeat until the character is `}`. No averaging is needed; a single trace
   per candidate decides it.

Create `solve.py`:

```python
import socket, sys, base64, numpy as np

HOST, PORT = sys.argv[1], int(sys.argv[2])
CHARSET = [chr(x) for x in range(33, 127)]

def get_trace(guess):
    s = socket.socket(); s.connect((HOST, PORT)); s.settimeout(5)
    s.recv(1024); s.sendall(b'1'); s.recv(1024); s.sendall(guess.encode())
    buf = b''
    try:
        while True:
            t = s.recv(8096)
            if not t: break
            buf += t
    except socket.timeout: pass
    s.close()
    return np.frombuffer(base64.b64decode(buf))

flag = "HTB{"
while not flag.endswith("}"):
    ref = get_trace(flag + "\x00")
    best_c, best_d = None, -1.0
    for c in CHARSET:
        tr = get_trace(flag + c); n = min(len(tr), len(ref))
        d = float(np.sum(np.abs(tr[:n] - ref[:n])))
        if d > best_d: best_d, best_c = d, c
        if d > 120: best_c = c; break
    flag += best_c
    print("[+]", flag, round(best_d, 1))
print("FLAG:", flag)
```

Run it against the live instance:

```bash
python3 solve.py <host> <port>
```

Each position prints with a diff around 150, and the script walks the flag out to the closing brace:

```
[+] HTB{c    (diff=166.7)
[+] HTB{c4   (diff=165.0)
...
[+] HTB{c4n7_h1d3_f20m_71m3}   (diff=132.1)
FLAG: HTB{...}
```

## Why it worked

The password check is not constant-time: it short-circuits on the first wrong character, which makes
the work done — and therefore the returned power trace — a direct function of the matched-prefix
length. That is a textbook
[observable timing discrepancy](https://cwe.mitre.org/data/definitions/208.html). Because the leak is
about *control flow* rather than *data values*, a value-recovery attack like CPA gets nothing, but a
single comparison of "does adding this character make the device do more work?" recovers the secret
in roughly 94 queries per character.

## Fix / defense

- Compare a **fixed-length hash** of the input with a constant-time primitive (`hmac.compare_digest`)
  so the amount of work is independent of how many leading characters match.
- Never early-exit a secret comparison — accumulate all differences, then test once.
- Don't return raw side-channel traces of a secret-dependent operation to untrusted clients; if a
  hardware side-channel surface is unavoidable, add masking, random delays, or dummy operations.

```python
import hmac, hashlib
def check(guess, secret):
    g = hashlib.sha256(guess.encode()).digest()
    s = hashlib.sha256(secret.encode()).digest()
    return hmac.compare_digest(g, s)   # constant-time; work independent of match
```
