---
layout: post
title: "Secure Digital"
date: 2027-06-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, spi, logic-analyzer, saleae, sd-card, forensics]
---

## Overview

HTB Hardware challenge (Very Easy, retired). The artifact is a Saleae Logic 2 `.sal` capture of an SPI bus connected to a microSD card. The flag is stored in plaintext on the SD card — a textbook case of [cleartext transmission of sensitive information](https://cwe.mitre.org/data/definitions/319.html) over an unprotected physical bus ([CWE-319](https://cwe.mitre.org/data/definitions/319.html)).

The key insight: the `.sal` internal binary format is proprietary and cannot be parsed manually. The only path is to use Logic 2's own gRPC automation API to run its SPI analyzer and export a decoded CSV.

---

## The capture

```
trace_captured.sal  — Saleae Logic 2 ZIP archive
  ├── digital-0.bin  (MISO, ch0 — SD card → master)
  ├── digital-1.bin  (MOSI, ch1 — master → SD card)
  ├── digital-2.bin  (CS,   ch2 — always LOW = active)
  ├── digital-3.bin  (CLK,  ch3 — ~5 MHz clock)
  └── meta.json      (50 MHz sample rate, 3.84 s, Saleae Logic 8)
```

The `digital-N.bin` files use Saleae's internal render-tree format (magic `<SALEAE>`, version=1, type=100) — **not** the documented Binary Export v1 (f64 transition times). Every attempt to hand-parse the tail section as RLE or LEB128 produces garbage. Logic 2 itself is the only decoder.

---

## Solution

### 1. Extract Logic 2 without FUSE

```bash
curl -sL "https://logic2api.saleae.com/download?os=linux&arch=x64" -o Logic2.AppImage
chmod +x Logic2.AppImage && ./Logic2.AppImage --appimage-extract
```

This drops everything into `squashfs-root/`.

### 2. Start headlessly under Xvfb

```bash
Xvfb :99 -screen 0 1024x768x24 &
DISPLAY=:99 squashfs-root/Logic --automation --no-sandbox --disable-gpu &
sleep 8
ss -tlnp | grep 10430
```

The `--automation` flag opens a gRPC server on `localhost:10430`.

### 3. Install the Python automation library

```bash
pip3 install grpcio-tools logic2-automation --break-system-packages
python3 -m grpc_tools.protoc \
  -I /path/to/logic2-automation/proto \
  --python_out=~/.local/lib/python3.x/site-packages \
  --grpc_python_out=~/.local/lib/python3.x/site-packages \
  /path/to/logic2-automation/proto/saleae/grpc/saleae.proto
```

The gRPC stubs must be compiled from the `proto/` directory bundled with `logic2-automation`. If Python raises `ModuleNotFoundError: saleae.grpc`, run the `grpc_tools.protoc` step above.

### 4. Decode the SPI trace

`solve.py`:

```python
#!/usr/bin/env python3
from saleae import automation
import time, csv, re, os

SAL = 'trace_captured.sal'

with automation.Manager.connect(port=10430) as manager:
    capture = manager.load_capture(SAL)

    spi = capture.add_analyzer('SPI', label='d', settings={
        'MISO': 0,
        'MOSI': 1,
        'Clock': 3,
        'Enable': 2,
        'Bits per Transfer': '8 Bits per Transfer (Standard)',
        'Clock State': 'Clock is Low when inactive (CPOL = 0)',
        'Clock Phase': 'Data is Valid on Clock Leading Edge (CPHA = 0)',
        'Enable Line': 'Enable line is Active Low (Standard)',
        'Significant Bit': 'Most Significant Bit First (Standard)',
    })

    time.sleep(12)
    capture.export_data_table('/tmp/spi.csv', analyzers=[spi])

rows = list(csv.reader(open('/tmp/spi.csv')))
hdr = rows[0]
mi = hdr.index('miso')

FF = {'\xff', 'ÿ', '\x00', '\\0', ''}
miso = ''.join(r[mi] for r in rows[1:] if r[1] == 'result' and r[mi] not in FF)

print(re.search(r'HTB\{[^}]+\}', miso).group())
```

Run it:

```bash
python3 solve.py
```

Output:

```
HTB{...}
```

Two things to get exactly right:

- **Setting strings must match Logic 2's exact labels** — `'8 Bits per Transfer (Standard)'` not `'8 Bits per Transfer'`, `'Enable line is Active Low (Standard)'` not the default variants. Wrong strings cause the analyzer to silently fail.
- **MISO bytes export as raw Latin-1 characters**, not hex — `0xFF` becomes `'ÿ'`. Filter the `FF` set before concatenating or the flag is buried in noise.

The raw MISO stream (filtered) begins with the SD card's FAT16 boot sector then the flag:

```
...MSDOS5.0...NO NAME    FAT16...HTB{...}
```

---

## Why it works

The SD card stores the flag as a plain UTF-8 file on its FAT16 filesystem. The SPI MISO line carries every byte read from the card back to the master — in cleartext, no transport-layer protection. Any attacker with access to the `.sal` capture file can recover the complete filesystem contents without any cryptanalysis.

The SPI protocol itself provides no confidentiality or authentication — it is a raw electrical bus. Physical access to a logic analyzer capture equals logical access to everything the bus carried.

---

## Fix / defense

- **Encrypt secrets before writing to removable media.** AES-256-GCM with a key that never appears on the SPI bus is the baseline.
- **Store the key in a secure element or MCU OTP region**, not on the same storage device or bus that carries the ciphertext.
- **Physically harden the device** against logic-analyzer attachment — conformal coating, potting, tamper-evident enclosures.
- If a `.sal` file must be shared (as in challenge artifacts), strip or encrypt the channel data first.
