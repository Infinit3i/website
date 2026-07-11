---
layout: post
title: "Death's Glance"
date: 2028-03-01 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, deep-leakage-from-gradients, dlg, idlg, model-inversion, federated-learning, pytorch]
description: "A shared gradient is a differentiable function of its training input — so with the exact model in hand you can invert it. Rebuild the seeded LeNet, L-BFGS-match the leaked gradient, and the reconstructed 32x32 image turns out to be a QR code carrying the flag."
---

## Overview

Death's Glance is a Medium AI/ML challenge. There's no server — you get `challenge.py` (a **LeNet** classifier with a fixed random seed) and `forbidden_spell.pt`. Loading the `.pt` reveals a **list of ten tensors whose shapes exactly match the model's parameters**: it's a *gradient*, not a saved model. That single detail is the whole challenge — it's the **Deep Leakage from Gradients (DLG)** attack, where a gradient shared during federated learning leaks the exact private sample it was computed on.

## The technique

DLG (Zhu, Liu & Han, NeurIPS 2019) turns reconstruction into optimization. Because a gradient is a differentiable function of the input, if you own the same model you can search for a dummy input whose gradient matches the leaked one:

1. **Reproduce the exact model.** `challenge.py` sets `torch.manual_seed(50)` *before* creating the LeNet and applying a `uniform_(-0.5, 0.5)` weight init, so the weights are fully deterministic. Replicating that sequence gives you the identical network that produced the gradient — the single most important step (a mismatched model reconstructs noise).
2. **Recover the label for free (iDLG).** For a single-sample `CrossEntropyLoss`, the final layer's gradient is negative only at the true class, so `label = argmin(sum(grad_last_layer, dim=1))`. No joint optimization needed.
3. **Match gradients.** Initialize a random `dummy` of shape `[1,1,32,32]`, and with L-BFGS minimize the squared difference between the dummy's gradient and the leaked one, keeping the graph differentiable so the loss flows back to the pixels.

## Solution

```python
torch.manual_seed(50)                        # deterministic weights (must precede net())
net = LeNet(); net.apply(weights_init)
real_grad = [g.detach() for g in torch.load("forbidden_spell.pt", weights_only=False)]

label = torch.argmin(torch.sum(real_grad[8], dim=-1)).reshape(1)   # iDLG label

dummy = torch.randn(1, 1, 32, 32, requires_grad=True)
opt = torch.optim.LBFGS([dummy], lr=1.0)
for _ in range(60):
    def closure():
        opt.zero_grad()
        loss = criterion(net(dummy), label)
        g = torch.autograd.grad(loss, net.parameters(), create_graph=True)   # 2nd-order graph
        diff = sum(((a - b) ** 2).sum() for a, b in zip(g, real_grad))
        diff.backward()
        return diff
    opt.step(closure)
```

Convergence is quick — the grad-match loss fell `116 → 0.0012` by iteration 10 and reached `0` by iteration 30. The reconstructed 32×32 image is a **QR code**. Decode it by handing the *grayscale* reconstruction to a robust reader (its adaptive binarizer beats a naive threshold):

```python
import zxingcpp, numpy as np
qr = ((img - img.min()) / (img.max() - img.min()) * 255).astype(np.uint8)
print(zxingcpp.read_barcodes(qr)[0].text)     # -> HTB{...}
```

`zxing-cpp` is a self-contained wheel (`pip install --break-system-packages zxing-cpp`) — no system `libzbar` required, and it succeeded where `cv2.QRCodeDetector` failed.

## Why it worked

The gradient is not anonymous: it encodes the input that produced it, so for a small model it can be *inverted* back to that input — an [information exposure (CWE-200)](https://cwe.mitre.org/data/definitions/200.html). Two conditions made it trivial: the attacker had the **exact weights** (a fixed seed), and the sample was a **single image**, so no batch averaging obscured it. The flag states the moral outright.

## Fix / defense

- **Never share raw per-sample gradients** — use secure aggregation so the server only sees a sum over many clients.
- **Differential privacy**: clip gradients and add calibrated noise so the gradient no longer uniquely determines one sample.
- **Large batches + gradient compression / sparsification** make reconstruction computationally intractable.
