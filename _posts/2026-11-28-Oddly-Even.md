---
title: "Oddly Even"
date: 2026-11-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Coding]
tags: [hackthebox, challenge, coding, modulo, parity, flask, monaco]
description: "A Very Easy Coding challenge served through the Flask + Monaco /run harness. Read a number, print odd or even — the whole solve is recognizing the editor-backed judge and POSTing a one-line parity check instead of touching the browser."
---

## Overview

`Oddly Even` is a Very Easy HackTheBox **Coding** challenge. It is not an exploit at
all — it is a programming-judge task wrapped in a small Flask web app with a
[Monaco](https://microsoft.github.io/monaco-editor/) code editor. The brief is one line:
*"Take in a number, print 'odd' if odd and 'even' if even."* Submit source that passes
the hidden test case and the judge prints the flag.

## The technique

HTB Coding challenges all share the same shape: a Flask app serves a Monaco editor, and
the **Run** button does a single `POST /run` with a JSON body `{"code": <source>,
"language": "python"}`. The server pipes a hidden test value to your program's stdin,
compares your stdout to the expected answer, and — on a match — emits the flag. There is
no need to drive the browser; the entire interaction is one HTTP request you can script.

The page's own handler tells you where the flag lands. For this instance the Run button
reads `data.stdout`, so the grader prints the flag **straight into stdout** when your
solution is accepted (other Coding instances expose a dedicated `flag` field instead —
always check the page's `fetch('/run')…then(data => …)` to know which).

## Solution

The task is a trivial parity check. Read an integer from stdin and print `even` or `odd`:

`solve.py`:

```python
import json, urllib.request

# Solution submitted to the /run sandbox: read an int, print odd/even.
code = 'n = int(input())\nprint("even" if n % 2 == 0 else "odd")'

req = urllib.request.Request("http://<rhost>:<rport>/run",
    data=json.dumps({"code": code, "language": "python"}).encode(),
    headers={"Content-Type": "application/json"})
resp = json.load(urllib.request.urlopen(req, timeout=30))
print(resp["stdout"])   # -> HTB{...} on a passing solution
```

Running it returns the flag in `stdout`:

```bash
python3 solve.py
# STDOUT: HTB{...}
```

## Why it worked

The flag is simply the judge's success output. The submitted program reads the hidden
stdin case (`n = int(input())`) and prints the correct parity token; the grader accepts
it and writes the flag to stdout. The only real skill is recognizing the Flask + Monaco +
`/run` harness and automating the single POST rather than typing into the editor.

## Fix / defense

For a CTF judge this behaviour is by design. The general lesson for real applications: any
endpoint that executes user-submitted code must run it in a strongly sandboxed,
network-isolated, resource-limited environment, and must never grant the submitted runtime
access to the host, its filesystem, or internal services. Treat "run arbitrary code from
the request body" as the maximum-trust operation it is.
