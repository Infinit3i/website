---
layout: post
title: "Decision Gate"
date: 2028-03-03 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, decision-tree, sklearn, model-inversion, adversarial]
description: "A flag gated behind a scikit-learn decision tree. Read the model, spot the backdoor class hiding among a thousand, and solve its root-to-leaf path constraints to forge the input that opens the gate."
---

## Overview

Decision Gate is a Medium AI/ML challenge. You get a saved scikit-learn model (`tree_model.joblib`) and an example input, and a network service that says:

```
Submit a 5D float vector (comma-separated) to unlock the flag.
```

Behind the service is a `DecisionTreeClassifier` with five features, a thousand classes, and 3363 nodes. It unlocks only when your vector is classified as one specific hidden class. Because the model is in your hands, this is a white-box model-inversion problem, not a guessing game.

## Finding the backdoor class

Loading the model, the classes are `class_000` through `class_998` — 999 of them following an obvious `class_%03d` pattern. The thousandth is the tell: a class literally named **`UNLOCK_FLAG_PATH`**. That's the "concealed execution path" from the brief. The gate opens when `predict(vector) == UNLOCK_FLAG_PATH`.

(If the target class weren't so obvious, you could discover it by brute force: the service loops with `Try again` on a single connection, so send one crafted input per reachable class over one persistent socket — only 614 of the 1000 classes are ever the majority class of any leaf, and the special one reveals itself immediately. Reconnecting per guess is a trap: these ML instances are short-lived and rate-limited, so spawn and brute in one process.)

## Crafting the input

A decision tree is a set of axis-aligned rules, so any leaf is reachable by solving the inequalities along its path. Find the leaf whose majority class is `UNLOCK_FLAG_PATH`, walk from it up to the root collecting each split's constraint (left child means `feature <= threshold`, right means `feature > threshold`), intersect them into a `[lo, hi]` interval per feature, and pick any value inside each interval.

Create `solve.py`:

```python
#!/usr/bin/env python3
import socket, sys, joblib, numpy as np, warnings
warnings.filterwarnings('ignore')
m = joblib.load('tree_model.joblib'); t = m.tree_; cl = m.classes_

leaves = [i for i in range(t.node_count) if t.children_left[i] == -1]
parent = {}
for n in range(t.node_count):
    for ch in (t.children_left[n], t.children_right[n]):
        if ch != -1: parent[ch] = n

def craft(L):
    lo, hi, node = [-1e6]*5, [1e6]*5, L
    while node in parent:
        p = parent[node]; f = t.feature[p]; thr = t.threshold[p]
        if t.children_left[p] == node: hi[f] = min(hi[f], thr)
        else:                          lo[f] = max(lo[f], thr)
        node = p
    return [0.0 if hi[i] > 1e5 and lo[i] < -1e5
            else (lo[i]+1 if hi[i] > 1e5 else (hi[i]-1 if lo[i] < -1e5 else (lo[i]+hi[i])/2))
            for i in range(5)]

leaf = [L for L in leaves if cl[int(np.argmax(t.value[L][0]))] == 'UNLOCK_FLAG_PATH'][0]
v = craft(leaf)
assert m.predict(np.array(v).reshape(1, -1))[0] == 'UNLOCK_FLAG_PATH'

ip, port = sys.argv[1].split(':')
s = socket.socket(); s.connect((ip, int(port))); s.recv(4096)
s.sendall((",".join("%.10f" % x for x in v) + "\n").encode())
print(s.recv(4096).decode())
```

Sending that vector returns:

```
Correct! Flag: HTB{...}
```

## Why it worked

Nothing about a decision tree is secret once you hold the model file — it's a transparent set of thresholds, and every leaf (including a hidden "authorize" leaf) is reachable by solving a handful of linear inequalities. The distractors here (a few leaves with anomalous sample counts, a max depth of 40) are noise; the actual signal was a single class name that broke the naming scheme.

## Fix / defense

Don't use a shipped ML model as an authorization mechanism, and never distribute the model that guards a secret — a white-box classifier is trivially inverted. If a model must gate access, keep it server-side, require authenticated inputs, and treat "reaching a class" as a signal, not a credential. A backdoor class baked into the tree is exactly the kind of hidden decision path defenders should be auditing models for.
