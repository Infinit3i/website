---
title: "Evaluative"
date: 2026-09-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Coding]
tags: [hackthebox, challenge, coding, polynomial, stdin-parsing, flask, monaco]
description: "A Monaco-editor coding challenge that asks you to evaluate a degree-8 polynomial from nine coefficients and a point x. The whole solve is recognizing the Flask + /run harness and writing a stdin parser that doesn't trust the example's line layout."
---

## Overview

`Evaluative` is a Very Easy HackTheBox **Coding** challenge. Instead of a downloadable binary or an `nc` oracle, it serves a small Flask web app with a **Monaco** code editor. You write a program, the server pipes a generated test case into its stdin, compares the stdout to its expected answer, and hands back the flag when they match. The task itself is a one-liner: evaluate the polynomial `a0 + a1*x + ... + a8*x^8`.

## The technique

HTB Coding challenges all share the same shape. The page's "Run" button does:

```
POST /run   { "code": <your source>, "language": "python" }
```

and the JSON reply is `{ "input", "result", "stderr", "flag" }`. The `flag` field is populated the instant your program's output matches the server's expected answer for the input it fed in. There is no browser step required — you POST your solver yourself and read `.flag`.

The task page describes the input as nine coefficients `a0`-`a8` (each in `[-100, 100]`) and an integer `x`, with the worked example:

```
Input:  1 -2 3 -4 5 -6 7 -8 9 5
Output: 2983941
```

## Solution

The one real trap is the input layout. The example shows all ten numbers on a single line, so an obvious `input().split()` looks correct — but the server actually feeds the **nine coefficients on line 1 and `x` on line 2**. A single `input()` would silently grab only the coefficients. The robust fix is to read the entire stdin and split on all whitespace, making the solver line-agnostic.

Create `solve_code.py` (this is the program submitted to `/run`):

```python
import sys
v = list(map(int, sys.stdin.read().split()))
a = v[:9]
x = v[9]
print(sum(c * x**i for i, c in enumerate(a)))
```

Verify it locally against the worked example before sending:

```bash
echo "1 -2 3 -4 5 -6 7 -8 9 5" | python3 solve_code.py
2983941
```

Then submit it to the live `/run` endpoint and read the flag straight out of the JSON:

```python
import json, urllib.request
code = open('solve_code.py').read()
body = json.dumps({"code": code, "language": "python"}).encode()
req  = urllib.request.Request("http://<target>:<port>/run", data=body,
                              headers={"Content-Type": "application/json"})
print(json.loads(urllib.request.urlopen(req, timeout=30).read())["flag"])
```

The live test fed `coeffs = -15 -82 15 45 -82 -80 -5 -32 -78` with `x = -91`, the solver printed `-365145682055345206`, and the response returned the flag `HTB{...}`.

## Why it worked

There is no vulnerability here — it is a programming exercise. The entire "trick" is recognizing the Flask + Monaco + `/run` harness so you can automate the submission, plus parsing the input defensively. Reading all of stdin and tokenizing on whitespace survives the line-layout mismatch that a positional `input()` quietly gets wrong.

## Fix / defense

The transferable lesson is for real-world I/O code, not security: **never hard-code an input's line structure when the spec shows only one example**. Parse the data, not the layout — tokenizing on whitespace (or using a proper parser) survives format drift that a positional read silently mishandles.
