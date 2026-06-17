---
title: "Hunting License"
date: 2026-10-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, elf, objdump, xor, hard-coded-credentials, static-analysis]
description: "A Very Easy Reversing challenge where the download is an ELF but the scoring container is a static-analysis quiz about it. Answer ten questions about the binary - format, architecture, main's address, the hard-coded passwords - to earn the flag."
---

## Overview

`Hunting License` is a Very Easy HackTheBox **Reversing** challenge. You download an ELF
named `license`, but the remote container is not the binary - it is a ten-question quiz
*about* the binary. Answer every question correctly (file format, CPU architecture, the
line-reading library, the address of `main`, how many `puts()` calls it makes, and the three
hard-coded passwords) and the server prints the flag. Every answer comes from static analysis
of the local ELF - no dynamic execution required.

## The technique

The challenge is a tour of [hard-coded credentials](https://cwe.mitre.org/data/definitions/798.html)
(CWE-798) "protected" by obfuscation that is not encryption. The `exam()` function checks three
passwords:

1. **First password** - a plain `strcmp` against an unobfuscated `.rodata` string.
2. **Second password** - the program reverses a stored string before comparing, so the password
   is the stored string read backwards.
3. **Third password** - a `.data` blob is XOR-decoded with a single-byte key (read straight from
   the disassembly) before comparison.

String reversal and a single-byte XOR are trivially invertible: the key and ciphertext sit right
next to each other in the binary.

## Solution

Identify the binary and pull the easy facts:

```bash
file license          # ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
ldd license           # libreadline.so.8  -> readline reads the user's answers
objdump -d -M intel license | grep '<main>:'   # 0000000000401172 <main>:
```

`main` makes exactly **5** `puts()` calls (the intro text). The interesting work is in `exam()`.
The second password is stored reversed in `.data`, and the third is a single-byte XOR blob:

```bash
objdump -s -j .data license
# 404060  30775464 72307773 73345000  -> "0wTdr0wss4P"
# 404070  477b7a61 77527d77 557a7d72 7f323232 13  -> XOR key 0x13
```

Decode both:

```bash
python3 -c "print('0wTdr0wss4P'[::-1])"
# P4ssw0rdTw0
python3 -c "d=bytes([0x47,0x7b,0x7a,0x61,0x77,0x52,0x7d,0x77,0x55,0x7a,0x7d,0x72,0x7f,0x32,0x32,0x32,0x13]); print(''.join(chr(b^0x13) for b in d if b^0x13))"
# ThirdAndFinal!!!
```

That gives every answer the quiz wants:

| # | Question | Answer | Source |
|---|----------|--------|--------|
| 1 | file format | `elf` | `file` |
| 2 | CPU architecture | `x86_64` | `file` |
| 3 | library that reads lines | `readline` | `ldd` |
| 4 | address of `main` | `0x401172` | `objdump` / symbol table |
| 5 | `puts` calls in `main` | `5` | `objdump` of `main` |
| 6 | first password | `PasswordNumeroUno` | rodata strcmp |
| 7 | reversed form of 2nd pw | `0wTdr0wss4P` | the stored string |
| 8 | real second password | `P4ssw0rdTw0` | reverse it |
| 9 | XOR key for 3rd pw | `0x13` | the `xor()` argument |
| 10 | third password | `ThirdAndFinal!!!` | XOR-decode `.data` |

Rather than type ten answers by hand (and risk the three-strikes lockout), a small script drives
the quiz against the live target. It matches each question against a pattern and replies:

Create `solve.py`:

```python
import socket, time, sys, re

H, P = sys.argv[1], int(sys.argv[2])

# question-text pattern -> ordered candidate answers (all from static analysis)
QA = [
    ("fmt",  r"file format",             ["elf"]),
    ("arch", r"CPU architecture",        ["x86_64"]),
    ("lib",  r"library is used to read", ["readline"]),
    ("main", r"address of the .*main",   ["0x401172"]),
    ("puts", r"calls to .*puts",         ["5"]),
    ("pw1",  r"first password",          ["PasswordNumeroUno"]),
    ("rev2", r"reversed form of the second", ["0wTdr0wss4P"]),
    ("pw2",  r"real second password",    ["P4ssw0rdTw0"]),
    ("xor",  r"XOR key",                 ["0x13"]),
    ("pw3",  r"(?<!encode the )third password", ["ThirdAndFinal!!!"]),
]

def strip(x): return re.sub(r'\x1b\[[0-9;]*m', '', x)

def current(transcript):
    best, pos = None, -1
    for e in QA:
        for m in re.finditer(e[1], transcript, re.I):
            if m.start() > pos:
                pos, best = m.start(), e
    return best

s = socket.socket(); s.settimeout(8); s.connect((H, P))
transcript = ""; tried = {}; flag = None; end = time.time() + 90
while time.time() < end:
    try: d = s.recv(65535).decode(errors="replace")
    except socket.timeout: d = ""
    if d:
        clean = strip(d); transcript += clean
        sys.stdout.write(clean); sys.stdout.flush()
        m = re.search(r'HTB\{[^}]+\}', transcript)
        if m: flag = m.group(0); break
        if "Try again" in clean: break
    if transcript.rstrip().endswith(">"):
        key, _, cands = current(transcript)
        used = tried.setdefault(key, set())
        nxt = next((c for c in cands if c not in used), None)
        if nxt is None: break
        used.add(nxt); s.sendall(nxt.encode() + b"\n")
        transcript += "\n[sent]\n"; time.sleep(0.4)

if flag: print("\n[+] FLAG:", flag)
s.close()
```

Run it against the spawned instance:

```bash
python3 solve.py <target-ip> <target-port>
# ... [+] Correct! x10
# [+] Here is the flag: HTB{...}
```

## Why it worked

Nothing in this binary is actually secret. The passwords are baked into the executable, and the
only "protection" - one string reversal and one single-byte XOR - is reversible directly from the
disassembly, because the XOR key (`0x13`) is a literal in the code and the ciphertext sits beside
it in `.data`. Static analysis recovers all three passwords in seconds.

Two scripting details are worth noting for anyone automating one of these quizzes. First, do not
detect "the current question" by a trailing `?` - two of the question lines end in a parenthetical
hint such as `"...for user answers? (\`ldd\` may help)"`, so the last character is `)`. Match on the
question's content instead. Second, beware substring collisions: the question *"What is the XOR key
used to encode the third password?"* contains the phrase `third password`, which also matches the
*"What is the third password?"* rule. A naive picker answers the wrong question and burns into the
three-strikes lockout - here a negative lookbehind keeps the two apart.

## Fix / defense

Never store secrets in a shipped binary, reversed or XORed or not - a single-byte XOR is not
encryption, and anything compiled into the client is already public. If a check must run on the
client, treat the embedded value as disclosed; real authorization must happen server-side against a
secret the client never holds.
