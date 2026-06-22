---
layout: post
title: "HackTheBox Challenge: Scripts and Formulas"
date: 2027-09-29 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, lnk, lolbas, vbscript, deobfuscation, powershell, scriptblock-logging, evtx, cloud-c2, google-sheets, shellcode, maldoc]
---

Scripts and Formulas is an easy forensics challenge that drops you into a real fileless-malware intrusion: a clerk opened a malicious "invoice" and you're handed the lure (`Invoice_01.lnk`, `invoice.vbs`) plus the machine's entire Windows event-log tree. A Q&A service quizzes you on exactly how the attacker chained a shortcut → VBScript → a Google Sheets cell → in-memory shellcode, and answering all seven questions in one session prints the flag. The whole point the flag celebrates: a trusted cloud API makes a great firewall-bypassing C2.

## Overview

The intrusion is a four-stage [embedded malicious code](https://cwe.mitre.org/data/definitions/506.html) ([CWE-506](https://cwe.mitre.org/data/definitions/506.html)) chain. Each stage hides the next, and the final payload runs only in memory — so the recovery relies on **PowerShell ScriptBlock logging (Event ID 4104)**, which captured every script the attacker executed.

## The technique

**Stage 0 — the shortcut.** A `.lnk` stores its target and command-line arguments as a wide (UTF‑16LE) string, so plain `strings` misses them — you need `strings -e l`. Doing so reveals:

```
powershell.exe -Nop -sta -noni -w hidden -c cp C:\Windows\System32\cscript.exe .\calc.exe;.\calc.exe Invoice.vbs
```

This is a **LOLBAS masquerade**: the legitimate Windows script host `cscript.exe` is copied and renamed to `calc.exe`, then the renamed binary runs the VBS. Name-based detection (and parent/child heuristics that trust `calc.exe`) get fooled. The tell-tale IOC is a process whose running image name differs from its PE `OriginalFilename`.

**Stage 1 — the VBScript.** `invoice.vbs` hides its strings behind a helper function that keeps a character only when `c = LCase(c) And Not IsNumeric(c)` — i.e. it strips UPPERCASE letters and digits and keeps lowercase letters and symbols. Real digits in the final command come from plain string literals (`"32"`, `"64"`, `Chr(34)`, `"|iex"`) concatenated between the helper calls. Reassembling everything rebuilds the `powershell.exe` path and a base64-encoded next-stage URL.

**Stage 2 — the Google Sheets dead-drop.** The PowerShell base64-decodes a `https://sheets.googleapis.com/v4/spreadsheets/<id>?key=<API>&ranges=Sheet1!O37&includeGridData=true` URL, reads the cell's `formattedValue` (which is base64 of a DeflateStream-compressed PowerShell), and `iex`-executes it. Using `googleapis.com` as the C2 channel sails past egress filtering and domain reputation — MITRE ATT&CK T1102 (Web Service C2).

**Stage 3 — the injector.** The final script is a classic reflective loader (`func_get_proc_address` / `func_get_delegate_type` / `VirtualAlloc` RWX / `Marshal::Copy` / delegate invoke). Its shellcode is obfuscated with a single-byte `-bxor 35`.

> Forensic twist: the Google API key dies after the challenge retires, so the live cell can't be fetched. But ScriptBlock logging (**EID 4104**) in `Microsoft-Windows-PowerShell%4Operational.evtx` captured the exact stage-2 and stage-3 scripts — the logs *are* the malware sample.

## Solution

Static analysis proves every answer; a small socket harness then drives the oracle.

Deobfuscate the VBScript helper and decode the next-stage URL:

```python
import base64

def deob(t):
    # invoice.vbs helper: keep lowercase letters + symbols, drop UPPERCASE + digits
    return "".join(c for c in t if c == c.lower() and not c.isdigit())

b64url = "aHR0cHM6Ly9zaGVldHMuZ29vZ2xlYXBpcy5jb20vdjQvc3ByZWFkc2hlZXRz..."  # from the VBS
print(base64.b64decode(b64url).decode())
# https://sheets.googleapis.com/v4/spreadsheets/<id>?key=<API>&ranges=Sheet1!O37&includeGridData=true
```

Recover the in-memory stages from ScriptBlock logging (EID 4104) with `python-evtx`:

```python
from Evtx.Evtx import Evtx
import re, html

log = "Microsoft-Windows-PowerShell%4Operational.evtx"
with Evtx(log) as f:
    for r in f.records():
        x = r.xml()
        if "4104" in x and "ScriptBlockText" in x:
            m = re.search(r'<Data Name="ScriptBlockText">(.*?)</Data>', x, re.S)
            print(html.unescape(m.group(1)))   # stage-2 fetcher + stage-3 injector
```

The stage-3 injector decrypts its shellcode with `for ($x=0; ...) { $var_code[$x] = $var_code[$x] -bxor 35 }` — the XOR key is `35`.

Drive the oracle (each question on a fresh connection, so replay prior answers):

```python
import socket, re

ANSWERS = [
    "cscript.exe:calc.exe",                          # program copied + renamed
    "LLdunAaXwVgKfowf",                              # VBS deobfuscation function
    "powershell.exe",                                # next-stage executor
    "1HpB4GqqYwI6X71z4p2EK88FoJjrsW2DKbSkx-ro5lQQ",  # spreadsheet id
    "Sheet1:O37",                                    # sheet + cell
    "4104",                                          # PowerShell ScriptBlock EID
    "35",                                            # shellcode XOR key
]

s = socket.socket(); s.connect((HOST, PORT))
for a in ANSWERS:
    s.send(a.encode() + b"\n")
    out = s.recv(8192).decode(errors="replace")
    if "HTB{" in out:
        print(re.search(r"HTB\{[^}]+\}", out).group(0))
```

The oracle returns the flag (`HTB{...}`, redacted here).

## Why it worked

Every stage relied on hiding from the *wrong* defender:

- **LOLBAS rename** beats image-name allow-lists but not `OriginalFilename` comparison.
- **VBScript char-filter obfuscation** beats `strings`/grep but is trivially reimplemented.
- **Cloud-API C2** beats domain reputation and egress allow-lists — there's no bad-domain to block.
- **Fileless execution** beats on-disk AV scanning — but **ScriptBlock logging records the script anyway**, which is the entire reason this challenge is solvable offline.

## Fix / defense

- Enable PowerShell ScriptBlock + Module logging (EID 4104/4103) and forward to a SIEM — it defeats fileless stages.
- Alert on `Invoke-RestMethod` / `DownloadString` to `*.googleapis.com` from non-browser processes.
- Use WDAC/AppLocker to block script hosts and flag any process whose image name ≠ its PE `OriginalFilename`.
- Treat email-delivered `.lnk` as untrusted, and enable ASR rules that block obfuscated scripts and Office/script-host child processes.
