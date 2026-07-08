---
layout: post
title: "Deadly Arthropod"
date: 2027-12-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, usb, hid, keystroke-decode, pcap, tshark]
---

A single packet capture and a one-line objective: *retrieve the flag*. The capture turns out to be USB traffic, and the "arthropod" in the title is the giveaway — it's a **bug**, i.e. a USB keyboard whose keystrokes were recorded on the wire. Decoding USB HID reports back into typed text is a standard forensics primitive; the only wrinkle here is that the typist used the arrow keys, so the characters were entered out of order.

## Overview

`Deadly Arthropod` is a Medium **Forensics** challenge. You get `deadly_arthropod.pcap` and nothing else. `file` identifies it as a USBPcap capture; the data is an 8-byte USB HID boot-keyboard report stream. Decode the reports into characters, simulate a text-editor cursor to undo the arrow-key navigation, and the typed text contains the flag.

## The technique

A USB boot-protocol keyboard sends 8-byte interrupt reports shaped like `[modifier, reserved, key1, key2, key3, key4, key5, key6]`:

- **byte 0** is a modifier bitmask — bit `0x02` is Left Shift, `0x20` is Right Shift.
- **byte 2** is the HID **usage code** of the first pressed key (`0x00` = key released).

The usage codes map to characters: `0x04`–`0x1d` → `a`–`z`, `0x1e`–`0x27` → `1`–`0`, `0x2c` = space, `0x28` = Enter, `0x2a` = Backspace, and `0x4f`/`0x50` = Right/Left arrow.

First confirm where the bytes live. Linux `usbmon` captures expose them as `usb.capdata`, but **this Windows USBPcap capture puts them in `usbhid.data`** — `usb.capdata` returns nothing, so always check both:

```bash
file deadly_arthropod.pcap
tshark -r deadly_arthropod.pcap -T fields -e usbhid.data
```

That gives an ordered list of reports like `0000080000000000` (key `0x08` = `e`), `0000000000000000` (release), and so on.

## The twist — cursor navigation

A naive left-to-right decode produces an email and a password cleanly, but the third line comes out as garbage full of `[LEFT]`/`[RIGHT]` markers. The typist moved the cursor with the arrow keys (`0x50` = Left, `0x4f` = Right) and inserted characters **out of order**. To reconstruct the real string you have to model a text editor: keep a buffer plus a cursor index and apply each event — insert at the cursor, Backspace deletes before it, the arrows move it, Enter starts a new line.

## Solution

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, subprocess
PCAP = sys.argv[1] if len(sys.argv)>1 else "deadly_arthropod.pcap"
hidmap={0x04:('a','A'),0x05:('b','B'),0x06:('c','C'),0x07:('d','D'),0x08:('e','E'),0x09:('f','F'),
0x0a:('g','G'),0x0b:('h','H'),0x0c:('i','I'),0x0d:('j','J'),0x0e:('k','K'),0x0f:('l','L'),
0x10:('m','M'),0x11:('n','N'),0x12:('o','O'),0x13:('p','P'),0x14:('q','Q'),0x15:('r','R'),
0x16:('s','S'),0x17:('t','T'),0x18:('u','U'),0x19:('v','V'),0x1a:('w','W'),0x1b:('x','X'),
0x1c:('y','Y'),0x1d:('z','Z'),0x1e:('1','!'),0x1f:('2','@'),0x20:('3','#'),0x21:('4','$'),
0x22:('5','%'),0x23:('6','^'),0x24:('7','&'),0x25:('8','*'),0x26:('9','('),0x27:('0',')'),
0x2d:('-','_'),0x2e:('=','+'),0x2f:('[','{'),0x30:(']','}'),0x31:('\\','|'),0x33:(';',':'),
0x34:("'",'"'),0x35:('`','~'),0x36:(',','<'),0x37:('.','>'),0x38:('/','?'),0x2c:(' ',' ')}
ENTER=0x28; BKSP=0x2a; LEFT=0x50; RIGHT=0x4f; HOME=0x4a; END=0x4d
data=subprocess.run(["tshark","-r",PCAP,"-T","fields","-e","usbhid.data"],
                    capture_output=True,text=True).stdout
lines_buf=[[]]; li=0; cur=0
for ln in data.splitlines():
    ln=ln.strip().replace(':','')
    if not ln: continue
    b=bytes.fromhex(ln)
    if len(b)<3: continue
    mod=b[0]; key=b[2]
    if key==0: continue
    shift=bool(mod & 0x22)
    buf=lines_buf[li]
    if key==ENTER:
        lines_buf.append([]); li+=1; cur=0
    elif key==BKSP:
        if cur>0: del buf[cur-1]; cur-=1
    elif key==LEFT:
        if cur>0: cur-=1
    elif key==RIGHT:
        if cur<len(buf): cur+=1
    elif key==HOME: cur=0
    elif key==END: cur=len(buf)
    elif key in hidmap:
        buf.insert(cur, hidmap[key][1 if shift else 0]); cur+=1
for l in lines_buf:
    print(''.join(l))
```

Run it against the capture:

```bash
python3 solve.py deadly_arthropod.pcap
```

It prints three lines — an email address, a decoy password, and the flag:

```
eks@hackthebox.eu
Th1sC0uldB3MyR3alP@ssw0rd
HTB{...}
```

## Why it worked

The USB HID boot protocol is fully standardized and transmitted in the clear, so any keyboard capture is mechanically decodable byte-for-byte. The challenge's only obstacle is misdirection: the cursor navigation scrambles the on-wire order of the flag characters relative to their final positions. Modelling the editor instead of concatenating keypresses removes that obstacle and reveals the original text — this is a [plaintext transmission of sensitive information](https://cwe.mitre.org/data/definitions/319.html) ([CWE-319](https://cwe.mitre.org/data/definitions/319.html)) weakness.

## Fix / defense

Never carry secrets over an unencrypted USB HID link that an attacker (or a captured host) can record — the boot protocol has no confidentiality. On the blue-team side, recognise that a USBPcap capture plus this decode is a standard insider-exfil/keylogger forensic primitive, and treat captured HID streams as fully recoverable plaintext.
