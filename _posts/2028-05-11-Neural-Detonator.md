---
layout: post
title: "Neural Detonator"
date: 2028-05-11 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, keras, deserialization, marshal, cve-2024-3660, model-supply-chain]
description: "A single mlcious.keras file hides a two-stage, self-decoding Python payload inside a Keras Lambda layer. The flag is reconstructed at runtime from the model's own weights — so the whole thing is reversed statically, without ever executing the payload."
---

## Overview

Neural Detonator is a **Hard** HackTheBox **AI/ML** challenge. You are handed one file, `mlcious.keras`, and nothing else. It is a weaponised model: a Keras `Lambda` layer carries a base64 **marshalled Python code object** that Keras would run at `load_model()` / inference time — the [CVE-2024-3660](https://nvd.nist.gov/vuln/detail/CVE-2024-3660) class of model-supply-chain attack. The twist is that the flag is not a plain string; it is rebuilt at runtime from the model's own **weights**. The clean way to solve it is to reverse the decoder **statically** and never detonate the payload.

## The technique

A `.keras` file is just a zip archive:

```
metadata.json        # keras_version 3.8.0
config.json          # the architecture — contains the malicious Lambda layer
model.weights.h5      # the weights (and the hidden flag)
```

Inside `config.json`, one layer is a `Lambda` named `activation_adapter` whose `function` field is base64 of a **marshalled Python code object**. That is the signature of a malicious Keras model. The key insight for analysis: `marshal.loads()` only *deserializes* a code object — it does **not** execute it — so you can inspect the payload's logic (its `co_names` and `co_consts`) safely, without ever calling `load_model()`.

## Solution

Decode the Lambda's code object and read its constant/name tree (disassembly is unreliable because the bytecode was compiled by a different Python version, but `co_names`/`co_consts` are stable):

```python
import json, base64, marshal, zipfile
c = json.loads(zipfile.ZipFile("mlcious.keras").read("config.json"))
fn = [l for l in c["config"]["layers"] if l["class_name"] == "Lambda"][0]["config"]["function"][0]
co = marshal.loads(base64.b64decode(fn))
print(co.co_names)      # ('marshal','tensorflow','tf','random','struct','hashlib','trampoline')
```

The payload is a **two-stage self-decoder keyed by the model's own weights**:

- **Stage 1** (`trampoline`): derive a seed from the `seed_dense` layer's weights, expand it into a 32-byte keystream, XOR-decrypt an embedded blob, then `marshal.loads` + `exec` it (stage 2).
- **Stage 2**: the flag bytes live in the `payload_dense/bias` weights, scaled to bytes and XOR'd with the *same* key. A baked-in constant, `22`, is the flag length.

`solve.py` reconstructs the whole thing from the weights offline — zero code execution:

```python
import json, base64, marshal, zipfile, hashlib, struct, random
import numpy as np, h5py

KERAS = "mlcious.keras"

def main():
    z = zipfile.ZipFile(KERAS)
    z.extract("model.weights.h5", "/tmp/nd_w")
    f = h5py.File("/tmp/nd_w/model.weights.h5", "r")
    g = lambda p: np.array(f[p][()])
    # keras 3 renames layers in the h5: dense = seed_dense, dense_1 = payload_dense
    sk, sb = g("layers/dense/vars/0"), g("layers/dense/vars/1")   # seed_dense kernel + bias
    pb = g("layers/dense_1/vars/1")                                # payload_dense/bias holds the flag
    src = np.ascontiguousarray(sk).tobytes() + np.ascontiguousarray(sb).tobytes()
    seed = struct.unpack("<I", hashlib.sha1(src).digest()[:4])[0]
    key = random.Random(seed).randbytes(32)
    enc = np.clip(np.round(pb * 255.0), 0, 255).astype(np.uint8).tobytes()
    dec = bytes(enc[i] ^ key[i % 32] for i in range(len(enc)))
    print("FLAG:", (dec.split(b"}")[0] + b"}").decode())

if __name__ == "__main__":
    main()
```

Running it re-derives the flag live:

```bash
python3 solve.py
# seed: 772214859
# FLAG: HTB{...}
```

## Why it worked

A saved model file is **code, not data**. Keras `Lambda` layers serialize arbitrary Python, so loading an untrusted `.keras`/`.h5` is equivalent to running attacker code (`exec(marshal.loads(...))`) — a [deserialization of untrusted data](https://cwe.mitre.org/data/definitions/502.html) weakness ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)). Hiding the decryption key inside the `seed_dense` weights and the flag inside the `payload_dense/bias` weights is just obfuscation: the weights are fully readable with `h5py`, and `marshal.loads` lets you read the payload's logic without detonating it. The seed being a function of the weights only means the payload decrypts against this exact model — reproducing it offline is trivial once you see the SHA-1 → `random.Random` → XOR chain.

## Fix / defense

- **Never `load_model()` an untrusted model.** Keras 3 ships `safe_mode=True` by default, which blocks `Lambda`-layer deserialization — do not disable it; TensorFlow/Keras patched [CVE-2024-3660](https://nvd.nist.gov/vuln/detail/CVE-2024-3660) along these lines.
- Prefer weights-only formats and rebuild the architecture from trusted code; avoid formats that can carry executable layers (`Lambda`, custom objects).
- Statically triage models before loading: unzip the `.keras`, scan `config.json` for `Lambda` layers with base64 `function` blobs, and `marshal.loads` + inspect (never `exec`) any suspicious code object.
- Scan model artifacts with tooling that flags embedded code, and require provenance / signing for models pulled from a registry.
