---
layout: post
title: "Artifact Of Dangerous Sighting"
date: 2027-08-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, vhdx, ntfs, alternate-data-streams, powershell, invoke-obfuscation, dfir, anti-forensics]
---

A Windows-forensics challenge that chains four small tricks into one clean DFIR exercise: reconstructing a **dynamic VHDX** disk with no mounter, recovering malware from an **NTFS Alternate Data Stream**, and peeling a layered **PowerShell obfuscation** without ever executing it. Everything below runs headless on Kali — no Windows host, no `sudo`.

## Overview

Pandora snapshots her box after noticing the Windows Event Viewer open on the Security log. The single artifact is a `*.vhdx` disk image. Someone planted a payload and tried to cover their tracks — and the whole story is still recoverable from the disk.

## The technique

Five steps, each defeating one layer of hiding:

1. Parse a **dynamic VHDX** straight to a raw image (no `qemu-nbd`/`guestmount`/`vhdimount`).
2. Carve the NTFS volume and repair a **sabotaged boot sector**.
3. Read the PowerShell command history to find where the payload was stashed.
4. Pull the payload out of an **NTFS Alternate Data Stream** ([T1564.004](https://attack.mitre.org/techniques/T1564/004/)).
5. Statically decode an **Invoke-Obfuscation "token-all"** PowerShell stage to read the flag — without running the malware.

## Solution

### 1. Dynamic VHDX → raw, no mounter

A dynamic VHDX is not a flat image — it has a region table and a **Block Allocation Table (BAT)** mapping 32&nbsp;MB blocks to file offsets. With no mounter and no `sudo`, parse it directly: the region table at `0x30000` points to the BAT and Metadata regions by GUID; the metadata gives `BlockSize`, `VirtualDiskSize`, `LogicalSectorSize`. The BAT interleaves one sector-bitmap entry after every `chunk_ratio` payload entries, so the real index for payload block `i` is `i + i//chunk_ratio`. Copy each `FULLY_PRESENT` block to its virtual offset.

> `7z` *looks* like it can open a VHDX but mis-parses the inner volume into garbage — write the BAT parser instead.

### 2. Carve NTFS and fix the boot sector

```bash
mmls disk.raw                       # NTFS partition at sector 63
dd if=disk.raw of=part.ntfs bs=512 skip=63 status=none
```

The carved boot sector's first three bytes were **zeroed** (`00 00 00` instead of the standard jump `EB 52 90`), which makes both Sleuth Kit and ntfsprogs reject the filesystem. Patch the jump back:

```bash
printf '\xeb\x52\x90' | dd of=part.ntfs bs=1 seek=0 count=3 conv=notrunc status=none
```

### 3. PowerShell history → the hiding spot

```bash
ntfscat part.ntfs '/C/Users/Pandora/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt'
```

```
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
wevtutil.exe cl "Windows PowerShell"
Remove-EventLog -LogName Microsoft-Windows-PowerShell/Operational
```

The `file.dll:stream` syntax is an **NTFS Alternate Data Stream** — a second `$DATA` attribute riding inside a legit-looking DLL. The `wevtutil cl` / `Remove-EventLog` lines are the attacker clearing logs (an anti-forensics tell — but the PowerShell *history* is a separate artifact and survives).

### 4. Extract the ADS headless

```bash
ntfsls -i -p /C/Windows/Tasks part.ntfs        # find the DLL's inode (321)
ntfsinfo -i 321 part.ntfs                       # two $DATA attrs: the DLL + named 'hidden.ps1'
ntfscat -i 321 -a 128 -n hidden.ps1 part.ntfs > hidden.ps1
```

`-a 128` selects the `$DATA` attribute type; `-n` names the alternate stream.

### 5. Decode the PowerShell without running it

`hidden.ps1` is `powershell -enc <base64>`, where `-enc` is base64 of **UTF-16LE**. Inside is Invoke-Obfuscation "token-all": digits built from `$()`/`++`, characters from indexing `"$(@{})"` and `"$?"`, ending in `…[char]N + … | iex" |& iex`. Rather than execute unknown malware, **strip the trailing `|& iex`** so the script's last statement is just the giant interpolated string, let PowerShell *emit* it, then rebuild the characters in Python.

The full, runnable solver — `solve.py`:

```python
#!/usr/bin/env python3
import base64, re, struct, subprocess, sys, uuid, glob

VHDX = glob.glob('files/HostEvidence_PANDORA/*.vhdx')[0]

def vhdx_to_raw(src, dst):
    f = open(src, 'rb')
    rd = lambda o, n: (f.seek(o), f.read(n))[1]
    BAT_GUID  = uuid.UUID('2DC27766-F623-4200-9D64-115E9BFD4A08')
    META_GUID = uuid.UUID('8B7CA206-4790-4B9A-B8FE-575F050F886E')
    sig, _, cnt, _ = struct.unpack('<4sIII', rd(0x30000, 16)); assert sig == b'regi'
    regions = {}
    for i in range(cnt):
        e = rd(0x30000 + 16 + i*32, 32)
        regions[uuid.UUID(bytes_le=e[:16])] = struct.unpack('<QII', e[16:32])[:2]
    bat_off, meta_off = regions[BAT_GUID][0], regions[META_GUID][0]
    assert rd(meta_off, 8) == b'metadata'
    mcnt = struct.unpack('<H', rd(meta_off+10, 2))[0]; meta = {}
    for i in range(mcnt):
        e = rd(meta_off + 32 + i*32, 32)
        meta[uuid.UUID(bytes_le=e[:16])] = meta_off + struct.unpack('<I', e[16:20])[0]
    BS  = uuid.UUID('CAA16737-FA36-4D43-B3B6-33F0AA44E76B')
    VDS = uuid.UUID('2FA54224-CD1B-4876-B211-5DBED83BF4B8')
    LSS = uuid.UUID('8141BF1D-A96F-4709-BA47-F233A8FAAB5F')
    block_size = struct.unpack('<I', rd(meta[BS], 4))[0]
    vds        = struct.unpack('<Q', rd(meta[VDS], 8))[0]
    lss        = struct.unpack('<I', rd(meta[LSS], 4))[0]
    chunk_ratio = (2**23 * lss) // block_size
    out = open(dst, 'wb'); out.truncate(vds)
    for i in range((vds + block_size - 1) // block_size):
        entry = struct.unpack('<Q', rd(bat_off + (i + i//chunk_ratio)*8, 8))[0]
        if (entry & 0x7) == 6 and (entry >> 20):
            out.seek(i*block_size); out.write(rd((entry >> 20) << 20, block_size))
    out.close()

vhdx_to_raw(VHDX, 'disk.raw')

mmls = subprocess.check_output(['mmls', 'disk.raw']).decode()
start = [l.split()[2] for l in mmls.splitlines() if 'NTFS' in l][0]
subprocess.run(['dd', 'if=disk.raw', 'of=part.ntfs', 'bs=512', f'skip={start}', 'status=none'], check=True)
with open('part.ntfs', 'r+b') as p:
    p.seek(0); p.write(b'\xeb\x52\x90')

ls = subprocess.check_output(['ntfsls', '-i', '-p', '/C/Windows/Tasks', 'part.ntfs']).decode()
inode = [l.split()[0] for l in ls.splitlines() if 'ActiveSyncProvider' in l][0]
ads = subprocess.check_output(['ntfscat', '-i', inode, '-a', '128', '-n', 'hidden.ps1', 'part.ntfs'])

b64 = re.search(rb'-enc\s+([A-Za-z0-9+/=]+)', ads).group(1)
layer1 = base64.b64decode(b64).decode('utf-16le')
stripped = layer1.rstrip()
open('layer1b.ps1', 'w').write(stripped[:stripped.rfind('|&')].rstrip())
sval = subprocess.check_output(['pwsh', '-NoProfile', '-File', 'layer1b.ps1']).decode()

layer2 = ''.join(chr(int(n)) for n in re.findall(r'\[Char\](\d+)', sval))
print('[+] FLAG:', re.search(r'HTB\{[^}]+\}', layer2).group(0))
```

The recovered layer-2 script is the real malware — it downloads 7-Zip over Tor and zips Pandora's documents for exfil. The flag is its kill-switch variable:

```powershell
$TopSecretCodeToDisableScript = "HTB{...}"
```

(Flag value redacted — re-run `solve.py` to derive it.)

## Why it worked

Every hiding step still left a recoverable trace. The dynamic-VHDX format is fully documented, so it parses without a mounter. NTFS Alternate Data Streams are visible to anything that enumerates `$DATA` attributes. And PowerShell obfuscation has to *eventually* materialise real characters — which you can capture by **emitting instead of executing**. Clearing the event log didn't help, because PowerShell's PSReadline history is a separate on-disk artifact that recorded the entire attack.

## Fix / defense

- **EDR/AMSI** flags `-enc` plus token-all obfuscation regardless of how the characters are assembled.
- **Alert on ADS writes** to system directories — `Get-Item -Stream *` and Sysmon `FileCreateStreamHash` surface them.
- **Forward logs off-host** so `wevtutil cl` can't erase them; collect PSReadline history during triage.
- **Script-block logging / Constrained Language Mode** would have logged the deobfuscated payload as it ran.
