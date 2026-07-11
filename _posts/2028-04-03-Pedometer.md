---
layout: post
title: "Pedometer"
date: 2028-04-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, android, bytecode-vm, anti-tamper, emulation, cwe-656]
description: "An Android step-counter hides its flag in a hand-rolled bytecode VM that runs one instruction per step you take, gated by anti-tamper checks on charging and airplane mode. Read the opcode table out of the smali, emulate the VM in Python, and force every device-state gate to pass."
---

## Overview

Pedometer is a Hard HackTheBox Mobile challenge. The Android app claims to use you as a power supply for a hidden machine — and it literally does: the APK ships a small **stack-based bytecode VM** whose program is an app asset, and it executes **one instruction for every step you take** (accelerometer events). The final instruction prints the flag, but a chain of anti-tamper opcodes gate execution on live device state (charging, airplane mode, connectivity). Rather than satisfy those on a real phone, we emulate the VM offline and force every check to pass. This is [CWE-656](https://cwe.mitre.org/data/definitions/656.html) — reliance on security through obscurity.

## The technique

Decompile the APK. Neither jadx nor apktool is on stock Kali, but both are self-contained java fat jars from GitHub releases:

```bash
jadx -d out pedometer.apk
apktool d pedometer.apk -o smali_out
```

`MainActivity` registers an accelerometer listener and a step-reader that opens the asset holding the VM program:

```java
InputStream open = mainActivity.getAssets().open("a");   // 143-byte VM program
this.stack = new Stack();
```

`onSensorChanged` (decompile with `jadx --show-bad-code`) is the interpreter. Each step (`abs(values[0]) > 6`, throttled to 300 ms) reads one byte, XORs it with a **self-modifying running key**, and dispatches on the opcode:

```java
int op = inputStream.read() ^ this.key;
switch (opcodeOrdinal(op)) {
    case PUSH: stack.push(inputStream.read() ^ key); ...
    case XOR:  int r = pop() ^ pop(); push(r); key = r; ...   // key mutates
    case CHRG: push(batteryManager.isCharging() ? 1 : 0); ... // anti-tamper
    case FLAG: for (i=0;i<21;i++) sb.append((char) pop()); flagView.setText(sb); ...
}
```

**The key gotcha:** jadx mangles the opcode enum — it renders the constructor as `b(String)`, but the real signature is `b(int ordinal, int value, String name)`. You must read the true opcode *values* from the smali `<clinit>`:

```
invoke-direct {v0, 0x0, 0x0,  "STOP"}     # ordinal 0, value 0x00
invoke-direct {v5, 0x3, 0x10, "ADD"}      # ordinal 3, value 0x10
```

Recovered opcode table (value → mnemonic): `STOP=0x00 PUSH=0x01 POP=0x02 ADD=0x10 SUB=0x11 MUL=0x12 DIV=0x13 MOD=0x14 EQ=0x20 LT=0x21 GT=0x22 NOT=0x30 XOR=0x31 IF=0x40 JMP=0x41 CHRG=0xf0 AIRPLN=0xf1 INTRNT=0xf2 ENC=0xf3 DEC=0xf4 FLAG=0xff`. The smali `.packed-switch` block maps each case by **ordinal**, so read that table rather than trusting decompiler label numbers.

The anti-tamper is the interesting part. `CHRG`, `AIRPLN`, and `INTRNT` push live device state, and the program gates execution with `EQ` + `IF` against constants baked into the program header. Trace it statically and the gates are **contradictory** — one check wants the device charging, a later one wants it not charging. That's the design: the intended solve toggles charging / airplane / wifi *in sequence* as you keep walking, one gate per step.

We don't need the phone. Emulate the VM and make each environment opcode return the value that satisfies its own gate — return the current **stack top**, which is exactly the constant the following `EQ` compares against. Every gate then evaluates true and `IF` skips the `STOP` byte guarding the flag routine.

## Solution

Create `solve.py`:

```python
import sys
data = open(sys.argv[1], 'rb').read()          # assets/a
OPC = {0x00:'STOP',0x01:'PUSH',0x02:'POP',0x10:'ADD',0x11:'SUB',0x12:'MUL',
       0x13:'DIV',0x14:'MOD',0x20:'EQ',0x21:'LT',0x22:'GT',0x30:'NOT',0x31:'XOR',
       0x40:'IF',0x41:'JMP',0xf0:'CHRG',0xf1:'AIRPLN',0xf2:'INTRNT',0xf3:'ENC',0xf4:'DEC',0xff:'FLAG'}
pos = 0; key = 0; st = []
def rd():
    global pos
    b = data[pos]; pos += 1; return b
while pos < len(data):
    nm = OPC[rd() ^ key]
    if   nm == 'STOP': break
    elif nm == 'PUSH': st.append(rd() ^ key)
    elif nm == 'POP':  st.pop()
    elif nm == 'ADD':  a=st.pop(); b=st.pop(); st.append(a+b)
    elif nm == 'SUB':  a=st.pop(); b=st.pop(); st.append(a-b)
    elif nm == 'MUL':  a=st.pop(); b=st.pop(); st.append(a*b)
    elif nm == 'DIV':  a=st.pop(); b=st.pop(); st.append(a//b if b else 0)
    elif nm == 'MOD':  a=st.pop(); b=st.pop(); st.append(a%b if b else 0)
    elif nm == 'EQ':   a=st.pop(); b=st.pop(); st.append(1 if a==b else 0)
    elif nm == 'LT':   a=st.pop(); b=st.pop(); st.append(1 if a<b else 0)
    elif nm == 'GT':   a=st.pop(); b=st.pop(); st.append(1 if a>b else 0)
    elif nm == 'NOT':  st.append(1 if st.pop()==0 else 0)
    elif nm == 'XOR':  a=st.pop(); b=st.pop(); key=a^b; st.append(key)
    elif nm == 'IF':
        if st.pop() == 1: pos += st.pop()
    elif nm == 'JMP':  pos += st.pop()
    elif nm in ('CHRG','AIRPLN','INTRNT'): st.append(st[-1])   # force gate to pass
    elif nm == 'ENC':  key = st.pop()
    elif nm == 'DEC':  key = 0
    elif nm == 'FLAG':
        print(''.join(chr(st.pop() & 0xff) for _ in range(21)))
        break
```

```
$ python3 solve.py assets/a
HTB{...}
```

## Why it worked

Both the interpreter and its program live inside the APK, so nothing is actually secret — a faithful re-implementation reproduces the entire computation offline. The device-state checks look like tamper-resistance, but each only compares a runtime value to a constant already present in the program, so an emulator just returns the expected value. The custom opcodes, self-modifying XOR key, and environment gating raise the effort to read the smali; they add no real protection.

## Fix / defense

- Never keep a secret — or the logic that reveals it — on the device. Serve it from a backend behind an authenticated request.
- If tamper-resistance is genuinely required, use platform attestation (Play Integrity) verified server-side, not local `isCharging()` / `airplane_mode_on` reads an emulator can fake.
- Treat any bundled interpreter as reverse-engineerable; obscuring an opcode table buys time, not security.
