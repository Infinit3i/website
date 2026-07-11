---
layout: post
title: "MultiDigilingual"
date: 2028-03-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, polyglot, python, perl, ruby, php, c]
description: "One source file that is simultaneously valid Python, Perl, Ruby, PHP, C, and C++ — and each one reads the flag. A tour of the four tricks that make a six-language polyglot possible."
---

## Overview

MultiDigilingual is a HackTheBox Misc challenge (Medium). The instance asks for **one base64-encoded program** that must be valid **Python3, Perl, Ruby, PHP8, C, and C++** at the same time, and every one of the six, when run or compiled, has to read `flag.txt`. That single file is a **polyglot** — one sequence of bytes with six correct interpretations. The whole challenge is building it.

## The technique

The server writes your source to `poly.py`, `poly.pl`, `poly.rb`, `poly.php`, `poly.c`, and `poly.cpp`, runs each (compiling the C/C++ with `gcc`/`g++`), and only rewards you if **all six** outputs contain the flag.

You can't just stack six per-language blocks, because **Python parses the whole file before executing a line** — one token it dislikes (a stray `<?php`, a C `main`, a `&&`) is an instant `SyntaxError`. Every character has to be correct or inert in all six languages simultaneously. Four primitives make that work:

1. **Shared characters only.** `"` and `#` are understood by all six. C's `&& || !` are banned (Python would choke on them); the interpreted trio use the word operators `and / or / not`. And C compiles as C++, so that's one target, not two.

2. **Hide the C code with the preprocessor.** Everything between `#if 0` and `#endif` is stripped before `gcc`/`g++` compile — so the scripting block lives there, invisible to the compiler. Because those lines each start with `#`, Python/Ruby/Perl also treat them as comments.

3. **Hide the PHP inside a comment.** `#//<?php system('cat flag.txt;'); __halt_compiler();?>` — the leading `#` makes the scripting languages skip it, PHP runs only what's inside `<?php ... ?>`, and `__halt_compiler()` stops PHP parsing the rest of the file.

4. **One line, three interpreted behaviours.** The same expression evaluates differently in Python, Ruby, and Perl. In **Perl**'s numeric context `"b" + "0" == 0` is *true* (undefined strings coerce to `0`); in Python/Ruby it's *false*. **Ruby**'s `and`/`or` have lower precedence than Python's, so `0 and 1 or 2` groups differently. Compose `(("b"+"0"==0 and PERL) or (0 and RUBY or PYTHON))` and each language falls into its own branch.

For the C side, a literal `int main()` token would break the scripting languages, so `main` is written in **inline assembly** (`__asm__(".globl main\nmain: ...")`) using raw `open`/`read`/`write`/`exit` syscalls — with the filename pushed onto the stack little-endian (`flag.txt` = `0x7478742e67616c66`) after a NULL qword.

## Solution

The complete polyglot:

```c
#if 0
#<?php system('cat flag.txt;'); __halt_compiler();?>
print((("b" + "0" == 0 and exec("cat flag.txt")) or (0 and exec("cat flag.txt") or eval('__import__("sys").stdout.write(open("flag.txt").read())'))));
#endif
__asm__(".section .text\n.globl main\nmain:\nmov $0x0,%rax\npush %rax\nmov $0x7478742e67616c66,%rax\npush %rax\nmov %rsp,%rdi\nxor %rsi,%rsi\nmov $2,%rax\nsyscall\nmov %rax,%rdi\nmov %rsp,%rsi\nmov $0x100,%rdx\nxor %rax,%rax\nsyscall\nmov $1,%rdi\nmov %rsp,%rsi\nmov %rax,%rdx\nmov $1,%rax\nsyscall\nxor %rdi,%rdi\nmov $60,%rax\nsyscall\n");
```

Base64-encode it and send it to the instance. A small driver handles the connection (and the instance's slow startup — connect only once it's actually listening, and do the whole flow in one process):

```python
import socket, base64
src = open("poly.c", "rb").read()
payload = base64.b64encode(src)
s = socket.socket(); s.connect((HOST, PORT))
s.recv(4096)                    # banner
s.sendall(payload + b"\n")      # server reads the program as base64
print(s.recv(65536).decode())   # -> ... HTB{...}
```

All six interpretations print the flag, the server's check passes, and it returns `HTB{...}`.

## Why it worked

The server trusts that a file "is" whatever its extension says and that each toolchain will parse it in isolation. But a file's type is not a property of its bytes — it's a property of *which parser reads them*. The four primitives (shared charset, preprocessor gating, comment-nested PHP, and logical-eval divergence) exploit exactly that: the same bytes present a different, valid program to each of the six parsers.

## Fix / defense

There's nothing to "patch" in the challenge itself — it's a construction puzzle. The real-world lesson is the inverse of it: **never decide a file's type from a single interpretation**. Upload filters, antivirus, and content sniffers that reason "this parses as a valid PNG, so it can't be a script" are defeated by polyglots that are *also* something else. Validate by canonicalizing or re-encoding the file (decode and re-emit it through a trusted library), not by confirming that one parser accepts it — because a second parser may accept something entirely different from the same bytes.
