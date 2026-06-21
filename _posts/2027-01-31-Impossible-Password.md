---
title: "Impossible Password"
date: 2027-01-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, crackme, patch, xor, prng, anti-debug]
description: "An Easy reversing crackme whose second password is regenerated from srand(time()) on every run — literally impossible to type. But the flag-printer just XORs bytes already baked into the binary, so the random check is a gate, not a key. NOP the conditional jump and the flag falls out."
---

## Overview

Impossible Password is an Easy HackTheBox **Reversing** challenge: a stripped
64-bit ELF that asks for two passwords. The first is a hardcoded string; the
second is regenerated from `srand(time())` + `rand()` on every run, so it can
**never** be typed correctly. The catch is that the routine which prints the
flag doesn't actually depend on getting the second password right — the flag is
already inside the binary, [XOR-encoded](https://cwe.mitre.org/data/definitions/798.html)
with a one-byte key. Patch the conditional jump that guards it, or decode the
bytes statically, and the flag drops out.

## The technique

Looking at `main`, the flow is:

1. `scanf("%20s")` then `strcmp` against the hardcoded string **`SuperSeKretKey`**
   (it's right there in `strings`). Wrong → `exit`.
2. A second `scanf`, then a generator seeds `srand(time(0) * k + ctr)` and fills
   a buffer with a `rand()` loop — **a new random string every run** — and
   `strcmp`s it against your input. Because your input is read *before* the
   target is generated, this comparison is unwinnable by design.
3. On a match it calls a flag-printer.

The flag-printer is the whole game. Disassembled:

```text
mov BYTE PTR [rbp-0xd], 0x9          ; XOR key = 0x09
...
movzx eax, BYTE PTR [rax]            ; next stored byte
xor   al,  BYTE PTR [rbp-0xd]        ; ^ 0x09
call  putchar
```

It XORs 20 bytes that `main` pre-loaded onto the stack with `0x09` and prints
them. The random password never feeds the decode — it only decides *whether* the
decode runs. This is the classic [use of an insufficiently random value as a
security gate](https://cwe.mitre.org/data/definitions/330.html): the "impossible"
check is a branch, not a key derivation.

## Solution

Two equivalent paths land the same value, which is the tell that the secret
never depended on runtime input.

**Static** — XOR the stored bytes yourself:

```python
b = [0x41,0x5d,0x4b,0x72,0x3d,0x39,0x6b,0x30,0x3d,0x30,
     0x6f,0x30,0x3b,0x6b,0x31,0x3f,0x6b,0x38,0x31,0x74]
print(''.join(chr(x ^ 9) for x in b))      # HTB{...}
```

**Dynamic** — patch the conditional jump so the flag-printer always runs, then
execute the patched copy. After the second comparison the disassembly reads
`test eax,eax ; jne <skip>`, i.e. bytes `85 c0 75 0c`. Turning the `jne`
(`75 0c`) into `nop nop` (`90 90`) makes the win-branch run for any input.

Create `solve.py`:

```python
import subprocess, os, stat

src = "impossible_password.bin"
data = bytearray(open(src, "rb").read())
i = data.find(bytes.fromhex("85c0750c"))   # test eax,eax ; jne skip
assert i != -1, "patch site not found"
data[i+2:i+4] = b"\x90\x90"                 # jne -> nop nop : never skip the flag
open("/tmp/patched", "wb").write(data)
os.chmod("/tmp/patched", os.stat("/tmp/patched").st_mode | stat.S_IEXEC)

out = subprocess.run(["/tmp/patched"],
                     input=b"SuperSeKretKey\nx\n",
                     capture_output=True, timeout=10).stdout
print(out.decode(errors="replace"), end="")
```

Run it:

```bash
python3 solve.py
# * [SuperSeKretKey]
# ** HTB{...}
```

Flag value redacted. Both the patched run and the static XOR produce the same
`HTB{...}`.

## Why it worked

The unwinnable `srand(time())+rand()` comparison is a **gate, not a key
derivation**. The flag is statically present in the binary the whole time; the
only thing protecting it is a single 2-byte conditional jump. Cracking the PRNG
was never required — you either NOP the jump or decode the bytes directly.

## Fix / defense

- Never gate a secret you *ship* behind a runtime check. If the plaintext (or a
  trivially reversible form of it) lives in the binary, it is recoverable.
  Derive the key *from* the user's input with a KDF so that a wrong answer can't
  decrypt anything.
- A single conditional jump is not a security boundary against anyone who can
  edit the file. Real tamper-resistance binds the secret cryptographically to
  the correct input rather than branch-gating a hardcoded value.
