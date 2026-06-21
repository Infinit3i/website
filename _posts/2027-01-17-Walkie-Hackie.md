---
title: "Walkie Hackie"
date: 2027-01-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, sdr, 2fsk, iq, gnuradio, numpy, signal-analysis]
description: "A Very Easy Hardware challenge: four GNU Radio .complex IQ captures of walkie-talkie traffic. Demodulate the 2FSK signal in pure numpy — the instantaneous frequency's sign is the bit — to recover the selective-call codes, no Universal Radio Hacker or inspectrum GUI required."
---

## Overview

`Walkie Hackie` is a Very Easy HackTheBox **Hardware** challenge. The field team
captured four transmissions from the guards' walkie-talkies (`1-4.complex`) and we
need to "interrupt their communication." The whole challenge is one skill: take a
raw SDR capture and **demodulate the 2FSK signal** to recover the on-air addressing
codes. The intended tools are GUI signal analyzers (Universal Radio Hacker,
inspectrum) — but it's a five-line numpy job.

## The technique

A `.complex` file is GNU Radio's native recording format: **interleaved 32-bit
floats, I then Q per sample** — i.e. numpy `complex64`. The radios use **2FSK**
(binary frequency-shift keying): each bit is sent as one of two tones.

The key identity is that the **instantaneous frequency** of an IQ stream is just the
phase change between consecutive samples:

```
f[n] = angle( x[n] · conj(x[n-1]) )
```

For 2FSK this comes out **bimodal** — one cluster well below zero, one well above —
so the *sign* of `f[n]` **is the bit**. Everything else is timing:

1. **Find the burst** — most of the file is silence; gate on magnitude `|x| > 0.3·max`.
2. **Find the symbol rate** — run-length-encode the sign bits; the shortest run is one
   symbol. Here every run length was a multiple of **100**, so 100 samples/symbol.
3. **Slice** the sign at each symbol centre (`i·100 + 50`).
4. **Group** the bits into nibbles → hex.

## Solution

Create `solve.py`:

```python
import numpy as np

def demod(fn, sps=100):
    x = np.fromfile(fn, dtype=np.complex64)        # interleaved float32 I/Q
    inst = np.angle(x[1:] * np.conj(x[:-1]))       # FSK demod = instantaneous frequency
    mag = np.abs(x[1:])
    act = np.where(mag > mag.max() * 0.3)[0]       # gate on the active burst
    s, e = act[0], act[-1] + 1
    n = (e - s) // sps                             # 100 samples/symbol (from run-length)
    bits = ''.join('1' if inst[s:e][i*sps + sps//2] > 0 else '0' for i in range(n))
    return ''.join('%x' % int(bits[i:i+4], 2) for i in range(0, len(bits)//4*4, 4))

for fn in (f'files/{i}.complex' for i in (1, 2, 3, 4)):
    print(fn, demod(fn))
```

Run it:

```bash
python3 solve.py
```

Output — sync preamble, group code, per-radio address:

```
files/1.complex: aaaaaaaa 73214693 a2ff84
files/2.complex: aaaaaaaa 73214693 a1ff14
files/3.complex: aaaaaaaa 73214693 b2ff24
files/4.complex: aaaaaaaa 73214693 b1ff57
```

- `aaaaaaaa` = `1010…`, the **clock-sync preamble** the receiver locks onto.
- `73214693` = the constant **group / selective-call code** shared by all four radios.
- the last field = each radio's **address**.

Knowing the selcall codes, you could forge frames to address — and jam — the guards'
radios, which is the challenge's "interrupt their communication." The flag is the
lesson itself (`B4s1c_r4d10_fund4s` = "basic radio fundamentals"):

```
HTB{...}
```

## Why it worked

Walkie-talkie selective calling here is unauthenticated, unencrypted 2FSK. Anyone who
can receive the burst can demodulate it, and anyone who can demodulate it can replay
or forge it. The `angle(x·conj(prev))` identity collapses any 2FSK/FM signal into a
per-sample sign decision, and the fixed symbol period falls straight out of
run-length analysis — so no GUI and no guessing the baud rate are needed.

## Fix / defense

- **Encrypt and authenticate** the air interface (AES-based DMR/TETRA, rolling codes)
  so a captured frame can't be replayed.
- Use **frequency-hopping / spread-spectrum** so a static narrowband capture can't
  recover a stable bitstream.
- Treat selective-call addresses as **non-secret** — never gate anything sensitive on
  them.
