---
layout: post
title: "Downgrade"
date: 2027-08-28 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, evtx, ntlm, kerberos, windows-event-logs, netntlm-downgrade, cwe-757]
---

## Overview

**Downgrade** is an Easy HTB forensics challenge built around a single Windows event-log artifact. A Windows 2012 server "does not force network authentication," so an attacker coerced a login over the legacy **NTLM** protocol instead of Kerberos — a *downgrade*. Among ~18,000 Security-log events, exactly one successful logon stands out by its authentication package, and its timestamp is the answer the challenge service wants.

## The technique

In an Active Directory environment the **default** authentication protocol is **Kerberos**. A NetNTLM downgrade/coercion attack forces the weaker legacy protocol, which leaves a clear forensic fingerprint in `Security.evtx`:

- Logon/logoff auditing lives in the **Security** event log.
- A **successful** logon is **Event ID 4624**.
- Almost every 4624 here uses `Negotiate`/Kerberos. The one suspicious login carries `AuthenticationPackageName = NTLM` — the outlier *is* the downgrade.
- The strongest downgrade markers on a 4624: `LmPackageName = NTLM V1`, `KeyLength = 0`, `TargetUserName = ANONYMOUS LOGON`, `LogonType 3` (network), empty `WorkstationName`.

The challenge's Q&A service walks exactly this reasoning chain:

```
Security  →  4624  →  Kerberos  →  NTLM  →  <suspicious-login timestamp, UTC>  →  flag
```

## Solution

Parse `Security.evtx` with the `python-evtx` library and bucket every 4624 by its authentication package — the NTLM logons fall right out:

```python
from Evtx.Evtx import Evtx
from collections import Counter
import re

def field(x, n):
    m = re.search(r"<Data Name=['\"]" + n + r"['\"][^>]*>(.*?)</Data>", x, re.S)
    return m.group(1) if m else None

dist = Counter()
with Evtx("Logs/Security.evtx") as log:
    for rec in log.records():
        x = rec.xml()
        m = re.search(r"<EventID[^>]*>(\d+)</EventID>", x)
        if not m or m.group(1) != "4624":
            continue
        ap = field(x, "AuthenticationPackageName")
        dist[ap] += 1
        if ap == "NTLM":                       # the outlier == the downgrade
            t = re.search(r'SystemTime="([^"]+)"', x).group(1)
            print(t, field(x, "TargetUserName"),
                  field(x, "LmPackageName"), "LogonType", field(x, "LogonType"))

print(dist)   # {'-': 9, 'Negotiate': 1855, 'NTLM': 17}  -> NTLM stands out
```

Answer the service in order — `Security` → `4624` → `Kerberos` → `NTLM` → the suspicious-login UTC timestamp (`yyyy-MM-ddTHH:mm:ss`) — and it returns the flag:

```
[+] Here is the flag: HTB{...}
```

(Flag value redacted.)

### Two tooling gotchas

- Kali's `evtx_dump` CLI shim is broken (`ModuleNotFoundError: No module named 'scripts'`). Parse with the **`python-evtx` library** directly (current versions need the `with`/context form shown above).
- `python-evtx` can **silently drop chunks** — if an expected event is missing, cross-check with `chainsaw` and `strings -e l file.evtx` (raw UTF-16LE).

## Why it worked

The server still negotiated the legacy NTLM protocol where Kerberos was expected. That is an **algorithm-downgrade weakness — [CWE-757](https://cwe.mitre.org/data/definitions/757.html)**: the protocol negotiation falls back to a weaker scheme the attacker chose, here NetNTLMv1, whose response is trivially crackable. The mismatch between the expected and actual authentication package is the entire detection.

## Fix / defense

- Disable NTLM (or at minimum enforce **NTLMv2**) and require **SMB signing** so a downgrade can't be negotiated.
- In a SIEM, alert on any 4624 with `LmPackageName = NTLM V1` and on **ANONYMOUS LOGON** network (LogonType 3) authentications — these are the high-signal indicators of a downgrade or relay.
