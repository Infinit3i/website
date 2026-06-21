---
title: "Man In The Middle"
date: 2027-06-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, forensics, bluetooth, btsnoop, hid, wireshark, tshark]
description: "An Easy Misc challenge: a BTSnoop capture of a sniffed Bluetooth keyboard. Because the keyboard pairs without link encryption, the HID input reports travel in cleartext over L2CAP — decode report-id 0x01 and you read back every keystroke that was typed."
---

## Overview

Man In The Middle is an Easy Misc/forensics challenge. You're handed a single file, `mitm.log`, which turns out to be a **BTSnoop** Bluetooth HCI capture of a wireless keyboard. Because the keyboard was paired without link encryption, its HID input reports are sent in [cleartext over the air](https://cwe.mitre.org/data/definitions/319.html). Pull the Bluetooth L2CAP payloads out with `tshark`, decode the keyboard reports as HID usage codes, and the flag is simply what the victim typed.

## The technique

A Bluetooth keyboard sends each keypress as a HID "input report". Over a Bluetooth Classic link those reports ride the **L2CAP** layer. In a BTSnoop capture there's no dedicated HID dissector, so the bytes sit in the raw `btl2cap.payload` field — this is the trap, because the data *looks* like a USB-HID challenge but there's no `usb.capdata` field to grab.

A keyboard input report is laid out like this:

```
a1 01 [modifier] [reserved] [keycode] 00 00 00 00
 │  │      │                    └ HID Usage ID (the key)
 │  │      └ bit 0x02 / 0x22 = Shift held
 │  └ report id 0x01 = keyboard
 └ HID DATA / Input
```

Mouse movement is a separate report-id (`0x02`, `a1 02 …`) and is pure decoy noise here — 4399 mouse reports versus 87 keyboard reports. Each keypress appears as a key-down (keycode set) followed by a key-up (keycode `0x00`), so simply keeping every report whose keycode is non-zero, in order, reconstructs the typed sequence — no state machine required.

## Solution

Identify the file and confirm the protocol layout:

```bash
file mitm.log
# mitm.log: BTSnoop version 1

tshark -r mitm.log -q -z io,phs
# ... bthci_acl -> btl2cap (everything is L2CAP)
```

Dump the raw HID reports:

```bash
tshark -r mitm.log -T fields -e btl2cap.payload | sort | uniq -c | sort -rn | head
# a1 02 ... -> mouse (noise)
# a1 01 ... -> keyboard (what we want)
```

Then decode the keyboard reports. Create `solve.py`:

```python
#!/usr/bin/env python3
import subprocess

HID = {i: (chr(93 + i), chr(61 + i)) for i in range(4, 30)}        # 0x04..0x1d = a..z / A..Z
HID.update({i: (d, sh) for i, d, sh in                            # 0x1e..0x27 = 1..0
            zip(range(30, 40), "1234567890", "!@#$%^&*()")})
HID.update({0x28: ("\n", "\n"), 0x2c: (" ", " "), 0x2d: ("-", "_"),
            0x2e: ("=", "+"), 0x2f: ("[", "{"), 0x30: ("]", "}")})

reports = subprocess.check_output(
    ["tshark", "-r", "mitm.log", "-T", "fields", "-e", "btl2cap.payload"]
).decode().split("\n")

flag = ""
for line in reports:
    if not line.startswith("a101"):     # keyboard reports only
        continue
    b = bytes.fromhex(line)
    mod, key = b[2], b[4]               # modifier byte, keycode byte
    if key == 0:                        # key-up -> skip
        continue
    if key in HID:
        flag += HID[key][1 if (mod & 0x22) else 0]   # shifted variant if Shift held

print(flag)
```

Run it:

```bash
python3 solve.py
# HTB{...}
```

## Why it worked

The keyboard was paired with no link-layer encryption (legacy / "just works" pairing), so the HID input reports were broadcast in plaintext and captured intact in the BTSnoop log. Anyone within radio range could read — or replay — the exact keystrokes. The flag, fittingly, is about compromised keystrokes.

## Fix / defense

This is [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html). To stop it:

- Pair HID devices using **Secure Simple Pairing (SSP)** / **LE Secure Connections** so the link is encrypted and MITM-protected.
- Disable legacy / Just-Works pairing for keyboards and mice.
- Re-pair devices only in a trusted environment.
