---
layout: post
title: "Snakecode"
date: 2027-07-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, python, bytecode, obfuscation, cwe-656, marshal, decompile, xdis, uncompyle6]
---

## Overview

Snakecode is an HTB Reversing challenge (Easy) consisting of a single Python 2.7 `.pyc` file. Every inner function is hidden behind a three-layer encoding — base64 → zlib → marshal — loaded at runtime via a `loadLambda` helper. The flag characters are stored as individual single-character constants inside the inner function `a3`'s `co_consts`, assembled into a list at call time. The solve is entirely static: decompile the outer `.pyc` with `uncompyle6`, decode each inner blob with `xdis` (cross-version Python 2.7 marshal parsing from Python 3), and read `co_consts` to reconstruct the flag.

**[CWE-656](https://cwe.mitre.org/data/definitions/656.html) — Reliance on Security Through Obscurity**

---

## The Technique

### Multi-layer Python .pyc obfuscation — flag in `co_consts`

The outer `.pyc` defines a single function `loadLambda` (`ll`):

```python
ll = types.FunctionType(
    marshal.loads(zlib.decompress(base64.b64decode(blob))),
    globals()
)
```

Every inner function (`i0`, `i1`, `f0`–`f8`, `a1`–`a9`, `m0`–`m2`) is reconstituted from a base64 blob at module load time. Static analysis of the outer `.pyc` reveals only opaque byte strings — no logic is visible.

The actual program is a curses Snake game. The key function is `a3`: it takes the snake length (`pl`) and returns `flag_list[pl // 5 % len(flag_list)]` — one character of the flag per score milestone. The full flag list is baked into `a3`'s `co_consts` as 26 individual single-character string literals.

---

## Solution

### Step 1 — Decompile the outer `.pyc`

```bash
python3 -m venv /tmp/uncompyle_env
/tmp/uncompyle_env/bin/pip install -q uncompyle6
/tmp/uncompyle_env/bin/uncompyle6 chall.pyc
```

This reveals the `loadLambda` pattern and all inner base64 blobs, including the blob for function `a3`.

### Step 2 — Decode the inner blob (cross-version marshal)

Python 3's `marshal.loads` rejects Python 2.7 code objects with "bad marshal data" because the type codes differ. `xdis.unmarshal.load_code` handles cross-version parsing — magic int `62211` (`0xF303` LE) identifies Python 2.7.

Create `solve.py`:

```python
#!/usr/bin/env python3
import base64
import zlib
import io
import sys

try:
    import xdis.unmarshal as um
    import xdis.opcodes.opcode_27 as op27
except ImportError:
    sys.exit("Install xdis: pip install xdis")

# Inner base64-zlib-marshal blob for function a3 (flag assembly)
BLOB_A3 = (
    'eJw10EtLw0AUBeAzTWLqo74bML8gSyFdiotm40rEZF+kRyVtCGKmqzar/nHvHBDmfty5c+fBrB2A'
    'iUVuUVkMG4MOnIARGIMJeAKm4BQ8Bc9UsfwcvABn/5VL8Aq81tINeAveKb/Hd47R4WDDTp5j7hEm'
    'R4fsoS4yu+7Vh1e8yEYu5V7WciffZCl/5UpW8l162cuF3Mq1fJSUY5uYhTZFRvfZF+EvfOCnU89X'
    'gdATGFLjafBs+2e1fJShY4jDomvcH1q4K9U='
)

def decode_blob(b64_str):
    return zlib.decompress(base64.b64decode(b64_str))

def disasm_a3(code):
    HAVE_ARGUMENT = op27.HAVE_ARGUMENT
    opname = op27.opname
    bytecode = code.co_code
    chars = []
    i = 0
    while i < len(bytecode):
        opcode = bytecode[i]
        op_name = opname[opcode] if opcode < len(opname) else f"OP_{opcode}"
        if opcode >= HAVE_ARGUMENT:
            arg = bytecode[i+1] | (bytecode[i+2] << 8)
            if op_name == 'LOAD_CONST' and arg != 0:
                c = code.co_consts[arg]
                if isinstance(c, str) and len(c) == 1:
                    chars.append(c)
            i += 3
        else:
            i += 1
    return ''.join(chars)

def main():
    raw = decode_blob(BLOB_A3)
    code = um.load_code(io.BytesIO(raw), 62211, None)
    flag = disasm_a3(code)
    print(f"Flag: {flag}")

if __name__ == '__main__':
    main()
```

### Step 3 — Run

```bash
pip install xdis
python3 solve.py
```

```
Flag: HTB{...}
```

---

## Why It Worked

The `a3` function's bytecode contains 26 consecutive `LOAD_CONST` instructions, each pushing one character of the flag onto the stack, followed by `BUILD_LIST 26` to collect them. Because the constants are stored verbatim in `co_consts`, any tool that can parse the code object — including a cross-version marshal parser like `xdis` — recovers the full flag list without ever running the program.

The three-layer encoding (base64 → zlib → marshal) raises the bar slightly by preventing `strings` from finding printable text, but it is fully [reversible obfuscation](https://cwe.mitre.org/data/definitions/656.html), not encryption. An attacker who identifies the `loadLambda` pattern faces only the minor obstacle of cross-version marshal parsing.

---

## Fix / Defense

Never store a flag, secret, or authentication credential as a sequence of character constants in client-side code — any decompiler or `co_consts` dump recovers it instantly. If secret delivery is required, derive the value server-side and transmit it over an authenticated channel. Multi-layer encoding (base64, zlib, marshal) is [security through obscurity](https://cwe.mitre.org/data/definitions/656.html) and provides no cryptographic protection once an attacker holds the file.
