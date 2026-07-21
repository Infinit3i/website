---
layout: post
title: "Space Heist"
date: 2028-06-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, apk, reverse-engineering, side-channel, power-analysis, bluetooth, hardcoded-secret]
description: "A Medium Hardware challenge with two locks: reverse the companion Android APK to replay a SHA1 challenge-response built on a hard-coded secret, then recover a 16-digit passcode from the safe's power-consumption traces using a difference-of-means power-analysis attack."
---

## Overview

Space Heist is a Medium **Hardware** challenge. You get an Android app (`lunar_safe.apk`) that controls a Bluetooth "Lunar Safe", a reference client (`client.py`), and a TCP server that emulates the safe. The safe has **two locks**: a mobile authentication step whose secret lives inside the app, and a numeric passcode you recover from the safe's power traces. The path is: reverse the APK to replay the auth handshake, then run a [power side-channel](https://cwe.mitre.org/data/definitions/1300.html) attack on the passcode check.

## The technique

**Lock 1 — hard-coded secret in the app.** The server's `auth` command starts a "Mobile Authentication Procedure" that imitates the phone app talking to the safe. Because the app itself performs the handshake, the secret is baked into the APK — a textbook case of [use of a hard-coded credential](https://cwe.mitre.org/data/definitions/798.html). Decompiling reveals a static `SECRET` and a challenge-response: the safe sends a random challenge, and the app answers `SHA1(challenge + SECRET)`. Anyone who unzips the APK can replay it.

**Lock 2 — early-exit compare leaks through power.** The `password` command is a power-analysis oracle: submit any guess and it hands back arrays of floats recording the safe's power consumption while it checked your guess. The check compares the passcode **digit-by-digit and stops at the first wrong digit**. When a digit is correct, the CPU does a little extra work before it stops — and that extra work is visible in the power trace. That observable-work-from-a-secret-comparison is [CWE-208](https://cwe.mitre.org/data/definitions/208.html), and returning the raw trace to the client is what makes it exploitable.

## Solution

### Reverse the APK

Kali ships no `jadx`/`apktool`, but the `androguard` Python library decompiles fine:

```python
from androguard.misc import AnalyzeAPK
a, d, dx = AnalyzeAPK("lunar_safe.apk")
# read com.example.android.lunar_safe.DeviceControlActivity
```

Inside `DeviceControlActivity` you find `SECRET = "qvb4a1b07E870B"` and the response builder `getSha1Hex(challenge + SECRET)`. The device sends `postC:<9-char challenge>`; the app replies `SHA1(challenge + SECRET)`. The app splits the reply into three Bluetooth writes, but the TCP server wants the whole answer on **one line**: `resp:<challenge>:<40-hex-sha1>`. Passing this yields `[*] Authenticated` and a `passcode>` prompt.

### Recover the passcode by power analysis

The trace is noisy, so single readings are useless. For each digit position, fix the digits already known, sweep every candidate 0–9, and **average ~5 traces** per candidate. Then score each candidate by how far its average trace is from the average of all ten candidate-averages. Nine wrong digits cluster together; the one correct digit is a lone outlier at roughly twice the score (~218 vs ~100).

You don't guess the length either — you detect it. Keep recovering positions while the best score is clearly above the runner-up (ratio > ~1.4). At position 16 the ratio collapses to ~1.0, meaning there is no more digit: the passcode is 16 digits long.

The digit-recovery core (`attack.py`):

```python
# per position: sweep 0-9, average N traces, pick the outlier vs the overall mean
means = {d: avg_trace(prefix, pos, d, N=5) for d in range(10)}
overall = mean_of(means.values())
best = max(range(10), key=lambda d: abs(means[d] - overall).sum())   # the correct digit
```

> The trace length is actually constant (10001 samples) — the leak is in the sample *values*, not the count. An apparent length difference early on was just a socket read getting out of sync when reading multiple guesses on one connection.

### Put it together (`solve.py`)

```python
import socket, hashlib
SECRET   = "qvb4a1b07E870B"        # hard-coded in lunar_safe.apk
PASSCODE = "<16-digit code>"       # recovered by power analysis (attack.py)

def rb(s, n):
    b = b''
    while len(b) < n: b += s.recv(n - len(b))
    return b
def ru(s, tok):
    b = b''
    while tok not in b: b += rb(s, 1)
    return b

s = socket.socket(); s.connect((HOST, PORT))
ru(s, b'cmd> ')
s.send(b'auth'); ru(s, b'mcmd> ')
s.send(b'getChallenge\n')
chal = ru(s, b'mcmd> ').decode().split("postC:")[1][:9]
digest = hashlib.sha1((chal + SECRET).encode()).hexdigest()
s.send(("resp:" + chal + ":" + digest + "\n").encode())   # ONE line
ru(s, b'passcode> ')
s.send(PASSCODE.encode() + b'\n')                          # -> "[*] Safe unlocked!" + flag
print(s.recv(4096).decode())
```

Running it prints `[*] Safe unlocked!` and the flag `HTB{...}`.

## Why it worked

Two design mistakes stacked. The shared secret was shipped inside the client app, so the authentication was replayable by anyone who read the APK. And the passcode comparison bailed out on the first wrong digit, making the amount of work — and therefore the power draw — depend on how many digits were correct. Handing that power trace back to the caller turned a 16-digit passcode into a one-digit-at-a-time oracle needing only a few hundred queries.

## Fix / defense

- Don't hard-code secrets in client software; provision per-device keys and verify them server-side.
- Compare secrets in **constant time** — hash both sides and use `hmac.compare_digest`, so the runtime never depends on how many characters match.
- Never return a raw power/timing trace of a secret-dependent operation to an untrusted client. If a hardware side-channel is unavoidable, add masking, random delays, or dummy operations.
