---
layout: post
title: "Sigma Technology"
date: 2028-01-23 09:00:00 -0500
categories: [HackTheBox, Challenges, AI-ML]
tags: [hackthebox, challenge, ai-ml, adversarial-ml, one-pixel-attack, differential-evolution, keras]
---

## Overview

Sigma Technology is a Medium **AI/ML** challenge. Tex's steam-powered robots classify
captured animals with a CIFAR-10 neural network called *SigmaNet* and fuse them into
hybrid monsters. You get the model file (`sigmanet.h5`) and a web app that shows the
"robot's vision" — a picture of your dog — plus a "laser" form that lets you flip **up to
5 pixels** (`x,y,r,g,b`). The goal is a classic **adversarial example**: perturb a handful
of pixels so the robot no longer sees a dog, using the [One-Pixel Attack](https://arxiv.org/abs/1710.08864)
driven by differential evolution.

## The technique

Neural image classifiers are brittle: a tiny number of pixels in the right place can
dominate the final feature map and flip the softmax output. The
[One-Pixel Attack](https://cwe.mitre.org/data/definitions/1039.html) exploits this in a
pure black-box way — it never needs gradients, only the ability to *query* the model's
confidence, which is exactly what shipping `sigmanet.h5` with the challenge gives you.
The search is done with `scipy.optimize.differential_evolution`, an evolutionary optimiser
that evolves a population of candidate pixel-sets toward a chosen target class.

The key realisation is the **win condition**. Merely making the model misclassify is not
enough — if it still reads an *animal* (say you flip dog → horse), the app happily reports
a "horse-scorpion hybrid" and gives nothing. You have to push the classification to a
**vehicle** class (airplane, automobile, ship, truck) — a non-organism Tex can't fuse — so
the attack must be **targeted**, not just any flip.

## Solution

Three details had to be right to reproduce the server's decision locally:

1. **Load the model despite a version clash.** `sigmanet.h5` was saved with Keras 2 and
   embeds an SGD optimizer using the old `lr=` argument, which Keras 3 rejects on load
   (`Argument(s) not recognized: {'lr': ...}`). Load with `compile=False` — inference
   doesn't need the optimizer.
2. **Reproduce the preprocessing exactly.** SigmaNet normalises each channel as
   `(x - mean) / std` with the CIFAR-10 statistics. Get this wrong and your local
   predictions won't match the server, so your "winning" pixels won't win.
3. **Target a vehicle, and score the whole population in one batch.** The objective
   maximises `P(airplane)`. Running differential evolution with `vectorized=True` scores
   the entire DE population in a single `model.predict`, which is roughly 100× faster than
   one image at a time — it converges to `P(airplane)=0.93`, `P(dog)=0.016` in ~200
   generations with 5 pixels.

Create `solve.py`:

```python
import os; os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import numpy as np
from PIL import Image
from scipy.optimize import differential_evolution
from tensorflow.keras.models import load_model

class_names = ['airplane','automobile','bird','cat','deer','dog','frog','horse','ship','truck']
VEHICLES = [0, 1, 8, 9]                                          # airplane, automobile, ship, truck
MEAN = np.array([125.307, 122.95, 113.865], dtype='float32')    # SigmaNet.color_process
STD  = np.array([62.9932, 62.0887, 66.7048], dtype='float32')

model = load_model('sigmanet.h5', compile=False)                # compile=False: skip legacy SGD 'lr' kwarg
base  = np.array(Image.open('dog.png').convert('RGB'), dtype=np.uint8)   # (32,32,3)

def predict_batch(imgs):
    return model.predict((imgs.astype('float32') - MEAN) / STD, verbose=0)

def make_batch(P):                                              # P: (25, popsize) -> (popsize,32,32,3)
    Pt = P.T if P.ndim == 2 else P[None]
    out = np.repeat(base[None], Pt.shape[0], axis=0)
    for cand, params in zip(out, Pt):
        for i in range(0, 25, 5):
            x, y, r, g, b = params[i:i+5]
            cand[int(round(y)), int(round(x))] = [int(round(r)), int(round(g)), int(round(b))]
    return out

bounds = [(0, 31), (0, 31), (0, 255), (0, 255), (0, 255)] * 5   # 5 pixels x,y,r,g,b

def attack(target):                                            # maximise P(target vehicle)
    obj = lambda P: -predict_batch(make_batch(P))[:, target]
    res = differential_evolution(obj, bounds, maxiter=200, popsize=40,
                                 mutation=(0.5, 1), recombination=0.7, seed=7,
                                 polish=False, vectorized=True)  # batch the whole population
    return res.x, predict_batch(make_batch(res.x))[0]

for t in VEHICLES:                                             # first vehicle that becomes argmax wins
    x, conf = attack(t)
    if int(np.argmax(conf)) in VEHICLES:
        pix = [tuple(int(round(v)) for v in x[i:i+5]) for i in range(0, 25, 5)]
        # server maps the first field to the row (img[y][x]) -> emit y,x,r,g,b
        print('&'.join(f'p{k+1}={y},{px},{r},{g},{b}' for k,(px,y,r,g,b) in enumerate(pix)))
        break
```

There is one last trap. Locally the perturbation was applied as `img[y, x]`, but the
server maps the **first** submitted field to the row — i.e. `img[a][b]` with `a = y`.
Submitting the raw `x,y` leaves the image a dog; you must swap to `y,x`:

```bash
curl -s -X POST http://<target>/point-laser \
  --data "p1=14,13,12,219,204&p2=18,25,3,12,98&p3=24,11,12,29,97&p4=4,17,173,87,113&p5=5,13,9,235,99"
```

The robot now reports `Scanned object: airplane`, no hybrid can be built, and the page
returns the flag — `HTB{...}` (redacted).

## Why it worked

The model was deployed with no adversarial robustness whatsoever — no adversarial
training, no input preprocessing, and the app trusts the raw `argmax` with no
confidence-margin check. Under those conditions a handful of carefully chosen pixels are
enough to steer the softmax to any class the attacker wants, and because the weights ship
with the challenge, the whole search runs offline against a perfect copy of the target.

## Fix / defense

- **Adversarial training** on FGSM/PGD/one-pixel perturbations to smooth the decision
  boundary.
- **Input preprocessing** before inference — JPEG recompression, spatial smoothing, or
  feature squeezing wipe out most single-pixel noise before it reaches the model.
- **Randomized smoothing** for certified robustness bounds.
- **Reject low-margin predictions** — if the top-2 confidence gap or predictive entropy is
  poor, refuse to act on `argmax` instead of blindly trusting it. And don't distribute
  production model weights to clients.
