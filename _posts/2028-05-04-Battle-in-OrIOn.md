---
layout: post
title: "Battle in OrIOn"
date: 2028-05-04 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, model-inversion, adversarial-ml, pytorch, gradient-descent, cwe-1039]
description: "The ship's neural network verifies your sensor override before it obeys — but it ships its own weights. Because the model is white-box and the input is unconstrained, you can run gradient descent on the input tensor itself to force any output distribution you like, no dataset required."
---

## Overview

Battle in OrIOn is a Medium HackTheBox AI/ML challenge. A Flask "Manual Override Terminal"
hosts a PyTorch CNN and asks you to upload a `.npy` "sensor configuration" whose model output
matches a **Required Power Distribution** (`Laser Canons` / `Thrusters`) to at least 99.99%
accuracy. The distribution is randomized per instance. Because the model weights ship with the
challenge and the input is unconstrained real-valued data, this is a textbook white-box
[model inversion](https://cwe.mitre.org/data/definitions/1039.html): run gradient descent on
the *input* tensor to force whatever output the page demands.

## The technique

You are given `net.py` and `model.pth`. The network is a small classifier:

```
Conv2d(1,16,k3,s2,p0) -> ReLU -> MaxPool2       # input 1x1x224x224
Conv2d(16,32,k3,s2,p0) -> ReLU -> MaxPool2      # -> 32x13x13 = 5408
fc1(5408->10) -> ReLU -> fc2(10->2) -> softmax  # 2-way power distribution
```

The `fc1` in-features of `5408 = 32*13*13` pin the input to **(1,1,224,224)** float32 (224 is
the standard size; every side length in 213–228 floors down to 13×13 through the two
stride-2 convolutions and pools).

The server passes the challenge when `softmax(model(x))` equals the required `[Laser, Thruster]`
vector. Since `x` is just "sensor data" with no constraints, we don't need to find a natural
input — we treat `x` as a free variable and minimize the distance between the model's output and
the target with an optimizer. The mapping is differentiable end-to-end, so a few thousand Adam
steps drive the output to the target almost exactly.

## Solution

The crafter reads a target `[laser, thruster]` and produces `config.npy`. Note the two things
that make it robust: `model.pth` is a *full pickled module object* (not a `state_dict`), so it
loads with `weights_only=False` after aliasing the class into `__main__`; and a learning rate
that is too high collapses the softmax to a saturated `[~0, ~1]` for near-balanced targets, so we
decay the LR and restart with a fresh initialization if a run fails to converge.

Create `craft.py`:

```python
import sys, os, numpy as np, torch, torch.nn as nn
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files', 'misc_battle_in_orion'))
import net as netmod
sys.modules['__main__'].net = netmod.net          # model.pth pickles __main__.net

def main():
    laser, thr = float(sys.argv[1]), float(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) > 3 else 'config.npy'
    m = torch.load('files/misc_battle_in_orion/model.pth', map_location='cpu', weights_only=False).eval()
    for p in m.parameters():
        p.requires_grad_(False)
    t = torch.tensor([[laser, thr]], dtype=torch.float32)
    tgt = np.array([laser, thr])

    def attempt(scale):
        x = nn.Parameter(torch.randn(1, 1, 224, 224) * scale)
        for lr in (0.03, 0.01, 0.003, 0.001):     # decay: high LR collapses softmax
            opt = torch.optim.Adam([x], lr=lr)
            for _ in range(1200):
                opt.zero_grad()
                loss = ((m(x) - t) ** 2).mean()   # forward() already softmaxes
                loss.backward(); opt.step()
                if loss.item() < 1e-13:
                    break
        with torch.no_grad():
            o = m(x).numpy()[0]
        return x.detach().numpy().astype(np.float32), o, 1 - abs(o - tgt).max()

    best = None
    for r in range(5):                            # restart until >= 99.99% accurate
        arr, o, acc = attempt(0.1 if r == 0 else 0.1 + 0.15 * r)
        if best is None or acc > best[2]:
            best = (arr, o, acc)
        if acc >= 0.9999:
            break
    np.save(out, best[0])
    sys.stderr.write("achieved %s acc %.6f\n" % (best[1], best[2]))

main()
```

Read the live target, craft, and upload:

```bash
curl -s http://<ip>:<port>/ | grep -oE '(Laser Canons|Thrusters): [0-9.]+'
python3 craft.py 0.8811 0.1189 config.npy
curl -s -F "file=@config.npy" http://<ip>:<port>/upload    # HTB{...} in the response
```

The upload form field is `file` and accepts `.npy`. A single accepted upload with a matching
config returns the flag in the HTML response.

```
HTB{...}
```

## Why it worked

The application gates a real decision on a model output that is fully controlled by
attacker-supplied input, and it distributes the model weights that make the decision. That makes
the classifier white-box and its output space reachable by gradient descent: every attainable
distribution has a preimage you can compute offline in seconds. Gating on a client-controlled
model input is therefore equivalent to no gate at all — this is exactly the
[inadequate handling of adversarial input perturbations](https://cwe.mitre.org/data/definitions/1039.html)
weakness class (a cousin of the few-pixel evasion attack, but here we invert toward an arbitrary
output vector rather than perturb a fixed image toward a class).

## Fix / defense

Never let a client-supplied tensor drive a security-relevant decision, and never ship production
model weights to untrusted clients. Gate the action server-side on a validated, signed,
human-meaningful input instead of on a model score the client can shape. If a model must stay in
the loop, add input preprocessing (recompression/smoothing), reject low-margin predictions, and
train against adversarial perturbations so the decision boundary is not trivially invertible.
