---
layout: post
title: "Quantum Conundrum"
date: 2028-06-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, quantum, qiskit, teleportation, bell-pair]
description: "A Medium Misc challenge that hands you a Qiskit 'communication system' and asks you to fix its broken quantum circuit. The server already implements the receiver's Pauli corrections, which pins the whole thing as quantum teleportation — you just supply the Bell pair and the sender's two gates, then wait out a deliberately slow 100-iteration test."
---

## Overview

Quantum Conundrum is a Medium **Misc** challenge built on **Qiskit**. A TCP service
initializes an unknown 1-qubit state on qubit 0, lets you inject a short list of gates,
then measures and applies corrections and checks whether that unknown state was faithfully
reproduced on qubit 2 — 100 times in a row. The whole puzzle is recognizing the setup as
**quantum teleportation** and supplying the four gates that make up the sender's half of
the protocol.

## The technique

Read `communication_system/__init__.py` and the puzzle gives itself away. The server
fixes the "receiver" half of a teleportation circuit:

```python
self._information = random_state(1)                        # unknown state |ψ⟩
self._motherboard.circuit.append(Initialize(self._information), [0])   # loaded onto q0
self._motherboard.circuit.barrier()
# ... your gates get inserted here ...

def measure_qubits(self):
    self._motherboard.circuit.measure(q[0], 0)             # q0 -> classical bit c0
    self._motherboard.circuit.measure(q[1], 1)             # q1 -> classical bit c1

def decode(self):
    self._motherboard.circuit.x(2).c_if(creg[1], 1)        # X on q2 if c1 == 1
    self._motherboard.circuit.z(2).c_if(creg[0], 1)        # Z on q2 if c0 == 1
```

Those two classically-conditioned Pauli gates — `X` on q2 if c1, `Z` on q2 if c0 — are
exactly the corrections a teleportation *receiver* applies. If the server did the
receiver's half, then the missing half you must provide is the *sender's*: build the Bell
pair and rotate the source into the Bell basis.

## Solution

The server accepts a `;`-separated list of JSON gate instructions (`hadamard`/`cnot`,
each with `register_indexes`, up to 10 gates). The four gates of the teleportation sender
are:

1. `H(q1)` then `CNOT(q1 → q2)` — entangle q1 and q2 into a Bell pair.
2. `CNOT(q0 → q1)` then `H(q0)` — entangle the source qubit with the pair and rotate to
   the Bell basis.

After the server measures q0/q1 and applies its `X`/`Z` corrections, qubit 2 collapses to
the original |ψ⟩ for every random test, so all 100 checks pass and the flag is returned.

The full solver — the durable artifact:

```python
import json, socket, sys

HOST, PORT = sys.argv[1], int(sys.argv[2])

# Server already does measure(q0,q1) + X/Z corrections on q2 (the receiver's half).
# We supply the sender's half: a Bell pair (q1,q2) then entangle+rotate the source q0.
gates = [
    {"type": "hadamard", "register_indexes": [1]},    # H q1    Bell pair (q1,q2)
    {"type": "cnot",     "register_indexes": [1, 2]},  # CX q1,q2
    {"type": "cnot",     "register_indexes": [0, 1]},  # CX q0,q1  entangle source
    {"type": "hadamard", "register_indexes": [0]},     # H q0      Bell-basis rotation
]
payload = ";".join(json.dumps(g) for g in gates)

s = socket.create_connection((HOST, PORT), timeout=300)   # server is SLOW: >=120s
s.recv(4096)                        # banner + "> " prompt
s.sendall(payload.encode() + b"\n")

data = b""
while b"HTB{" not in data and b"failed" not in data.lower():
    chunk = s.recv(4096)            # flag arrives ~100s later
    if not chunk:
        break
    data += chunk
print(data.decode(errors="replace"))
```

Run it against the live instance:

```bash
python3 solve.py <host> <port>
```

The flag (`HTB{...}`) prints roughly 100 seconds after you send the gates.

## Why it worked

Teleportation transfers an unknown quantum state using a shared Bell pair plus two
classical correction bits, and the correction rule is canonical: `X` conditioned on the
partner qubit's measured bit and `Z` conditioned on the source qubit's bit. Because the
server exposed exactly that correction step, it fully determined which qubit was the
source (q0, the `Initialize` target) and which pair carried the state (q1/q2). Supplying
the standard sender gates makes q2 hold |ψ⟩ deterministically, independent of the random
measurement outcome — so the statevector equality check passes on every one of the 100
runs.

The one practical trap is timing: `test_output()` runs 100 iterations each with a
`time.sleep(1)`, so the flag doesn't come back for ~100 seconds on a single connection
(the server-side alarm is 300s). A short socket timeout throws `recv timed out` on the
second read and makes a *correct* circuit look wrong. Set the timeout to at least 120
seconds and wait.

## Fix / defense

This is a CTF puzzle rather than a security bug, but it carries a real lesson for
homemade quantum and cryptographic protocols: **when you publish the reconciliation or
correction step of a protocol, you leak its structure.** The exposed `X.c_if / Z.c_if`
corrections told an attacker precisely how the qubits were wired. Any scheme that reveals
its per-symbol reconciliation data — teleportation corrections, QKD sifting relations,
basis-reconciliation hints — hands that structure away and lets the rest of the protocol
be reconstructed. Keep the reconciliation half of a protocol private if its secrecy
depends on it.
