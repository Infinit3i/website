---
layout: post
title: "Flash-ing Logs"
date: 2028-04-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, spi-flash, w25q128, pyftdi, security-register, crc, cwe-1191]
description: "An external SPI flash chip stores encrypted smart-lock logs. The XOR key hides in the chip's Security Register — readable with one documented SPI command — and the flag is released only after you correctly patch a record on the chip: decrypt it, edit a field, recompute its CRC, and reprogram the flash."
---

## Overview

Flash-ing Logs is a Hard HackTheBox Hardware challenge. The instance exposes a `pyftdi` SPI-bridge to an emulated **W25Q128** NOR flash storing encrypted smart-lock event logs. The decryption key lives in the chip's [Security Register](https://cwe.mitre.org/data/definitions/1191.html) — readable with the standard `0x48` command — and the flag is unlocked only after you correctly patch the on-chip records. This is a clean lesson in why a flash "security register" is not a vault and why an unkeyed CRC does not make a log tamper-evident.

## The technique

The challenge ships two files. `client.py` shows the wire protocol: a JSON blob names a byte sequence to clock out over SPI and a read length to clock back:

```json
{"tool":"pyftdi","cs_pin":0,"url":"ftdi://ftdi:2232h/1","data_out":["0x9f"],"readlen":3}
```

`data_out` is opcode + address + data; the reply is a JSON array of the bytes read on MISO. This is exactly what a cheap FT2232H probe does against a real board.

`log_event.c` (the device firmware) gives the data model: each log is a 16-byte record — a 12-byte `SmartLockEvent` struct **XOR-encrypted** with a 12-byte key, followed by a 4-byte **plaintext** CRC32. Critically, the key is fetched with `read_security_register(1, 0x52, key)` — it sits in the chip's own security register.

## Solution

**Step 1 — read the key from the Security Register.** The W25Q "Read Security Registers" command is `0x48` + a 24-bit address + one dummy byte. Register 1 is based at `0x001000`, so the key at offset `0x52` is address `0x001052`:

```python
key = exchange([0x48, 0x00, 0x10, 0x52], 12)
```

**Step 2 — decode the logs.** Read the log region with `0x03` (Read Data) and decode per 16-byte block. The key realigns at every record, so decrypt block by block, not as a continuous stream:

```python
mem = exchange([0x03, 0x00, 0x00, 0x00], 2560)
for blk in range(0, len(mem), 16):
    b = mem[blk:blk+16]
    dec = bytes(b[i] ^ key[i % 12] for i in range(12))
    # timestamp u32 @0, eventType @4, userId u16 @6, method @8, status @9, CRC @12
```

All 160 records validate against a standard CRC-32 (polynomial `0xEDB88320`, init `0xFFFFFFFF`, final NOT).

**Step 3 — patch the chip.** The brief: alter only the logs with `user_id = 0x5244` so they point to a different user. Four records match. Decrypt each, change the userId, recompute the CRC32 over the new plaintext, and re-encrypt. NOR flash can only flip bits `1 → 0`, so you cannot overwrite in place — erase the whole 4 KB sector and rewrite every record (the untouched ones re-encrypt identically):

Create `patch.py` (core loop):

```python
def crc32(d):
    c = 0xFFFFFFFF
    for x in d:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    return (~c) & 0xFFFFFFFF

for blk in range(0, len(mem), 16):
    dec = bytearray(mem[blk+i] ^ key[i % 12] for i in range(12))
    if struct.unpack("<H", dec[6:8])[0] != 0x5244:
        continue
    struct.pack_into("<H", dec, 6, 0x001c)
    enc = bytes(dec[i] ^ key[i % 12] for i in range(12)) + struct.pack("<I", crc32(dec))
    mem[blk:blk+16] = enc

wren(); exchange([0x20, 0, 0, 0]); wait_wip()
for pg in range(0, 2560, 256):
    wren()
    exchange([0x02, (pg >> 16) & 0xff, (pg >> 8) & 0xff, pg & 0xff] + list(mem[pg:pg+256]))
    wait_wip()
```

`wren` sends `0x06` (Write Enable) before every erase/program; `wait_wip` polls the status register (`0x05`, bit 0 = write-in-progress).

**Step 4 — read the flag.** Before the patch, the flag address reads all `0xFF`. After the correct patch it returns the flag:

```python
flag = exchange([0x03, 0x52, 0x52, 0x52], 100)
# HTB{...}
```

## Why it worked

A flash **security register is not a vault** — it rides the same SPI bus and answers the documented `0x48` read to anyone with the chip and a cheap probe. The logs then used a repeating-key XOR whose key sits *on that same chip*, so decryption is trivial once the key is read. And the integrity check was a **plaintext CRC with a public polynomial** — a CRC detects accidental corruption, not a motivated editor, so recomputing it after the edit makes the tampered record validate.

## Fix / defense

Keep keys in MCU OTP fuses that never cross an external bus, and encrypt flash contents at rest with a key held off-device. Lock the security registers (SRP/SRL) and enable read protection. Most importantly, authenticate logs with a keyed MAC (HMAC), not an unkeyed CRC — integrity that anyone can recompute is not integrity.
