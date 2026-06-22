---
layout: post
title: "HTB Challenge: Perseverance"
date: 2027-07-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, wmi, persistence, forensics-wmi, windows, fileless, dotnet, python-cim]
---

## Overview

**Perseverance** is an Easy HTB Forensics challenge from Business CTF 2022. You're given a raw Windows WMI repository and asked to trace a persistence mechanism that keeps re-compromising a user even after remediation. The technique is [WMI event subscription persistence](https://cwe.mitre.org/data/definitions/1204.html) — a fileless backdoor hiding inside the WMI binary database, with the payload stashed in a hijacked legitimate class property.

---

## The Technique

Windows WMI (Windows Management Instrumentation) supports **event subscriptions** — a three-part triplet stored in `root\subscription`:

| Class | Role |
|---|---|
| `__EventFilter` | WQL query that fires on a system event (e.g. uptime in range) |
| `CommandLineEventConsumer` | Shell command to execute when the filter fires |
| `__FilterToConsumerBinding` | Links filter to consumer |

Attackers abuse this as a persistence mechanism ([ATT&CK T1546.003](https://attack.mitre.org/techniques/T1546/003/)): the triplet survives reboots, runs as SYSTEM, and is stored entirely inside the WMI repository binary — no files on disk. Here the consumer was named **"Windows Update"** to masquerade as a legitimate entry.

The persistence uses a further fileless trick: the .NET payload isn't written to disk. Instead it's stored as a base64-encoded, Deflate-compressed blob inside the `Property` property of a hijacked WMI class (`Win32_MemoryArrayDevice` in `root\cimv2`). The PowerShell consumer reads the class property at runtime, decompresses it, and loads it into memory via `[Reflection.Assembly]::Load()`.

---

## Solution

### 1. Parse the WMI repository with `python-cim`

`python-cim` (pre-installed on Kali) reads `OBJECTS.DATA` + `INDEX.BTR` + `MAPPING*.MAP` without needing a live Windows system.

```python
import cim
from cim import objects
import logging
logging.disable(logging.CRITICAL)

r = cim.CIM(cim.CIM_TYPE_WIN7, './files')
t = objects.Tree(r)
root = t.root

def find_ns(ns, name):
    for child in ns.namespaces:
        if child.name.lower() == name.lower():
            return child

sub_ns = find_ns(root, 'root\\subscription')
```

### 2. Find the malicious `CommandLineEventConsumer`

```python
cls = sub_ns.class_('CommandLineEventConsumer')
for inst in cls.instances:
    ci = inst.ci
    print(inst.instance_key)
    cmd = ci.get_property('CommandLineTemplate').value
    print(cmd[:120])
```

Output reveals a consumer named **"Windows Update"** with a `-enc <base64>` PowerShell command.

### 3. Decode the PowerShell

PowerShell's `-enc` flag uses UTF-16LE:

```python
import base64
enc_b64 = cmd.split('-enc ')[-1].strip()
ps_script = base64.b64decode(enc_b64).decode('utf-16-le')
print(ps_script)
```

The decoded script reads `([WmiClass]'ROOT\cimv2:Win32_MemoryArrayDevice').Properties['Property'].Value`, base64-decodes it, Deflate-decompresses it, and loads the result as a .NET assembly via `[Reflection.Assembly]::Load()`.

### 4. Extract the payload from `OBJECTS.DATA`

The class property value is stored raw in `OBJECTS.DATA` as a NUL-separated ASCII blob. Scan for it:

```python
import zlib

with open('./files/OBJECTS.DATA', 'rb') as f:
    raw = f.read()

for chunk in raw.split(b'\x00'):
    try:
        s = chunk.decode('ascii').strip()
        if len(s) > 500 and s.startswith('7Vp9'):
            payload_b64 = s
            break
    except:
        continue

# Raw Deflate (no zlib header) → .NET PE
payload_bytes = zlib.decompress(base64.b64decode(payload_b64), -15)
print(f"MZ header: {payload_bytes[:2] == b'MZ'}")  # True
```

### 5. Decompile the .NET assembly and extract the flag

Save the PE and decompile with `ilspycmd`:

```bash
ilspycmd wmi_payload.exe
```

The C# source shows a `GruntStager` class (a [Covenant C2](https://github.com/cobbr/Covenant) stager) that builds the flag key via four `StringBuilder.Append()` calls — each a base64 fragment:

```python
frags = ['SFRCezFfd', 'GgwdWdodF9XTTFfdzRzX2p1c', '3RfNF9NNE40ZzNtM2', '50X1QwMGx9']
flag = base64.b64decode(''.join(frags)).decode()
print(flag)  # HTB{...}
```

### Complete `solve.py`

```python
#!/usr/bin/env python3
import cim
from cim import objects
import base64, zlib, os, logging
logging.disable(logging.CRITICAL)

path = './files'
r = cim.CIM(cim.CIM_TYPE_WIN7, path)
t = objects.Tree(r)
root = t.root

def find_ns(ns, name):
    for child in ns.namespaces:
        if child.name.lower() == name.lower():
            return child

sub_ns = find_ns(root, 'root\\subscription')

# 1. Find malicious CommandLineEventConsumer
cls = sub_ns.class_('CommandLineEventConsumer')
for inst in cls.instances:
    ci = inst.ci
    cmd = ci.get_property('CommandLineTemplate').value
    enc_b64 = cmd.split('-enc ')[-1].strip()
    ps_script = base64.b64decode(enc_b64).decode('utf-16-le')
    print('[*] PowerShell (first 200 chars):', ps_script[:200])

# 2. Extract base64 payload blob from OBJECTS.DATA
with open(os.path.join(path, 'OBJECTS.DATA'), 'rb') as f:
    raw = f.read()
for chunk in raw.split(b'\x00'):
    try:
        s = chunk.decode('ascii').strip()
        if len(s) > 500 and s.startswith('7Vp9'):
            payload_b64 = s
            break
    except:
        continue

# 3. Decode + raw-Deflate decompress → .NET PE
payload_bytes = zlib.decompress(base64.b64decode(payload_b64), -15)
print(f'[*] Payload: {len(payload_bytes)} bytes, MZ={payload_bytes[:2]==b"MZ"}')

# 4. Reconstruct flag from StringBuilder fragments in decompiled C#
frags = ['SFRCezFfd', 'GgwdWdodF9XTTFfdzRzX2p1c', '3RfNF9NNE40ZzNtM2', '50X1QwMGx9']
flag = base64.b64decode(''.join(frags)).decode()
print(f'[+] Flag: {flag}')
```

---

## Why It Worked

- The WMI repository stores all event subscriptions as persistent binary objects — no filesystem footprint
- `CommandLineEventConsumer` runs arbitrary shell commands at SYSTEM level on every qualifying event
- Hiding the .NET payload inside a legitimate class property (`Win32_MemoryArrayDevice`) avoids file-based AV scanning entirely — the C2 stager never touches disk
- `python-cim` exposes the full object graph offline, making forensic triage straightforward without a live Windows system

---

## Fix / Defense

- **Monitor** `root\subscription` for new `__FilterToConsumerBinding` instances — Sysmon Event IDs 19, 20, 21 log WMI event subscription creation
- **Alert** on `CommandLineEventConsumer` or `ActiveScriptEventConsumer` names that don't match known-good baselines (legitimate Microsoft entries are well-documented)
- **Audit offline** with `python-cim` or [PyWMIPersistenceFinder](https://github.com/davidpany/WMI_Forensics) during incident response
- **Restrict WMI subscription creation** to SYSTEM/admin via DCOM namespace ACLs
