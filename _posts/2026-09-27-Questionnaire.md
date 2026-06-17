---
title: "Questionnaire"
date: 2026-09-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, binary-analysis, checksec, ret2win, pwntools]
description: "A Pwn challenge with no exploit at all — the remote is a 10-question quiz about a provided binary. Answer them from file, checksec, nm, and the source, and it hands you the flag. The real takeaway is binary triage plus a read-until-prompt pwntools bot."
---

## Overview

`Questionnaire` is a Very Easy HackTheBox **Pwn** challenge, and it is deliberately
not an exploit. You get a tiny C program (`test.c`) with its compiled binary
(`test`) and a remote `nc host port`. The remote's own banner says *"There is no
bug in the questionnaire"* — it is a 10-question quiz that teaches you to read a
binary's properties with `file`, `checksec`, `nm`, and the source. Answer all ten
correctly and the server prints the flag.

## The technique

Two things make this trivial once you see them: knowing the standard
binary-analysis facts a quiz like this asks for, and scripting a
**read-until-prompt** bot so you do not hand-type ten answers against an
ANSI-coloured socket that re-prompts on a wrong answer.

The provided source is a textbook [ret2win](https://cwe.mitre.org/data/definitions/121.html)
setup, even though the quiz never asks you to fire it:

```c
void gg(){ system("cat flag.txt"); }          // win function, never called

void vuln(){
    char buffer[0x20] = {0};                   // 32-byte buffer
    fprintf(stdout, "\nEnter payload here: ");
    fgets(buffer, 0x100, stdin);               // reads 256 bytes -> classic overflow
}

void main(){ vuln(); }
```

`fgets` reads `0x100` (256) bytes into a 32-byte stack buffer — a classic
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html). With no
stack canary and no PIE, you could fill 32 bytes of buffer plus 8 bytes of saved
`RBP` (40 bytes) and then overwrite the saved return address with the fixed address
of `gg()`. The quiz stops at "find the offset and the win address"; it never asks
for the payload itself.

## Solution

Three commands gather every fact the quiz wants:

```bash
file test                 # ELF 64-bit, dynamically linked, not stripped
pwn checksec test         # Canary: No | NX: yes | PIE: No (0x400000) | RelRO: Partial
nm test | grep -E ' gg| vuln| main'   # gg=0x401176 vuln=0x401190 main=0x4011fa
```

That maps directly to the ten answers:

| # | Question | Answer | Source |
|---|----------|--------|--------|
| 1 | 32 or 64-bit? | `64-bit` | `file` |
| 2 | linking? | `dynamic` | `file` |
| 3 | stripped? | `not stripped` | `file` |
| 4 | protections enabled? | `NX` | `checksec` (only NX is on) |
| 5 | function called in `main()`? | `vuln()` | source |
| 6 | size of buffer? | `32` | `buffer[0x20]` |
| 7 | custom function never called? | `gg()` | source (the win func) |
| 8 | std func that triggers the BOF? | `fgets()` | `fgets(buf,0x100,...)` |
| 9 | bytes until SegFault? | `40` | 32 buffer + 8 saved RBP |
| 10 | address of `gg()` in hex? | `0x401176` | `nm` (no PIE → fixed) |

Because the socket streams ANSI-coloured tutorial text and re-asks the same
question on a wrong answer, the robust approach is a keyword-matched
read-until-`>>` loop rather than fixed sleeps.

Create `solve.py`:

```python
from pwn import *
import re
context.log_level = 'error'
HOST, PORT = 'TARGET_HOST', 0   # set to the spawned instance

def clean(b):
    return re.sub(rb'\x1b\[[0-9;]*[A-Za-z]', b'', b).decode(errors='replace')

def answer(q):
    s = q.lower()
    if '32-bit' in s and '64-bit' in s: return '64-bit'
    if 'linking' in s or 'linked' in s or 'dynamic' in s or 'static' in s: return 'dynamic'
    if 'stripped' in s: return 'not stripped'
    if 'protections' in s and 'enabled' in s: return 'NX'     # combined Q -> only NX
    if 'function' in s and 'main' in s: return 'vuln()'
    if 'never called' in s: return 'gg()'
    if 'buffer overflow' in s and 'function' in s: return 'fgets()'
    if 'buffer' in s and 'size' in s: return '32'
    if 'segmentation fault' in s or 'segfault' in s: return '40'
    if 'address' in s and 'gg' in s: return '0x401176'
    return None

io = remote(HOST, PORT)
while True:
    txt = clean(io.recvuntil(b'>>', timeout=10))
    if 'HTB{' in txt:
        print(re.search(r'HTB\{[^}]+\}', txt).group(0)); break
    lines = [l.strip() for l in txt.splitlines() if l.strip()]
    qidx = max((i for i, l in enumerate(lines) if 'Question number' in l), default=None)
    qtext = ' '.join(lines[qidx + 1:]) if qidx is not None else ' '.join(lines[-3:])
    io.sendline(answer(qtext).encode())
```

Run it against the live instance and it walks all ten questions and prints the
flag:

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

The quiz only checks string-equality against the expected token in the format its
`(e.g. ...)` hint shows (`64-bit`, `vuln()`, `0x401176`). A wrong answer simply
re-asks, so a keyword bot converges with zero risk. The one subtlety: strip the
ANSI escapes before matching, key off the question *text* (not its position), and
put the combined "which protections are enabled" branch *before* the
per-protection branches — otherwise the word `canary` matches first and you answer
"no" forever on a question whose real answer is `NX`.

## Fix / defense

There is nothing to "fix" — this is a teaching challenge. The real-world lesson is
the primitive it points at: `char buffer[0x20]` fed by `fgets(buffer, 0x100, stdin)`
with no canary and no PIE is the textbook
[stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html). The fix
is to bound the read to the buffer size (`fgets(buffer, sizeof(buffer), stdin)`) and
to compile with `-fstack-protector-all -pie -fPIE` so a canary and address-space
randomization stand between an overflow and the return address.
