---
title: "Milkshake"
date: 2027-03-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, stego, audio, spectrogram, mpg123, scipy]
description: "An Easy Misc/Stego challenge that hides its flag where no byte tool can see it — painted as text into the frequency spectrum of an MP3. Decode the audio, render a spectrogram, and read the letters off the picture, all headless without Sonic Visualiser."
---

## Overview

**Milkshake** is an Easy HackTheBox **Misc** (steganography) challenge. You get a
single file — `Milkshake.mp3` — and the cheeky prompt *"Can you bring all the boys
to the yard?"* The flag isn't in the metadata, isn't a trailing blob, and you can't
hear it: it's **drawn as text into the frequency spectrum** of the audio. Render the
MP3 as a spectrogram and the flag is sitting there in the high band, waiting to be read.

## The technique

This is classic **audio spectrogram steganography**. The author shaped the sound so
that when you plot **frequency vs. time** with magnitude as brightness, the bright
pixels spell out characters. The payload lives in a *visual* representation of the
audio (the Short-Time Fourier Transform magnitude), not in any ID3 tag, appended
bytes, or sample-level LSBs — so `strings`, `exiftool`, and `binwalk` all come up
empty. The prompt is the hint: *"bring all the boys to the **yard**"* is the Kelis
song the file is built from, and the answer is to **see** it. The textbook tool is
Sonic Visualiser (Pane → Add Spectrogram); below we do the same thing entirely
headless.

## Solution

First, unzip with the standard HTB challenge password and confirm what we have:

```bash
unzip -P hackthebox files.zip
file Milkshake.mp3        # ID3 v2.4.0, MPEG ADTS layer III, 128 kbps, 44.1 kHz
exiftool Milkshake.mp3    # nothing useful — LAME 3.99 encoder, no hidden tags
strings -n 6 Milkshake.mp3 | grep -i htb   # empty
```

Nothing in the bytes. The next move for any audio Misc file that resists `strings`
is to render a spectrogram. This box has neither `sox` nor `ffmpeg`, but `mpg123`
decodes the MP3 to WAV, and `scipy`/`matplotlib` draw the rest:

```bash
mpg123 -w milkshake.wav Milkshake.mp3
```

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys
import numpy as np
from scipy.io import wavfile
from scipy.signal import spectrogram
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

wav = sys.argv[1] if len(sys.argv) > 1 else "files/milkshake.wav"
rate, data = wavfile.read(wav)
if data.ndim > 1:
    data = data.mean(axis=1)
data = data.astype(np.float64)

f, t, Sxx = spectrogram(data, fs=rate, nperseg=8192, noverlap=8192 - 1024)
Sdb = 10 * np.log10(Sxx + 1e-12)

plt.figure(figsize=(40, 10))
plt.pcolormesh(t, f, Sdb, shading="auto", cmap="magma")
plt.ylim(0, 22000)
plt.savefig("spectrogram.png", dpi=120)
print("wrote spectrogram.png")
```

Run it and open the image:

```bash
python3 solve.py
```

The flag text sits in the **~1500–3000 Hz** band over the first ~14 seconds of the
track, reading `HTB{...}`. If the song's own harmonics drown the letters, two tricks
make them legible: stay on the `magma` colormap (a flat grayscale lets the loud
music dominate and the glyphs vanish), and crop the region with PIL + autocontrast:

```python
from PIL import Image, ImageOps
im = Image.open("spectrogram.png"); w, h = im.size
c = im.crop((int(w*.03), int(h*.18), int(w*.40), int(h*.34)))
ImageOps.autocontrast(ImageOps.grayscale(c)).resize((c.width*2, c.height*3)).save("zoom.png")
```

The zoomed crop renders the flag cleanly.

## Why it worked

A spectrogram is just a heatmap of the STFT magnitude. By depositing energy at the
right frequencies and times, the author paints arbitrary pixels — including readable
text — into a dimension that byte-level inspection never touches. The MP3 plays as
ordinary music; only when you transform the samples into the frequency domain does
the hidden image appear.

## Fix / defense

This is a CTF hiding trick rather than a software flaw, but the defensive lesson
generalizes: never trust "inaudible/invisible" channels. Data-loss-prevention and
media-integrity tooling should spectrogram-scan audio crossing a trust boundary,
not just grep its bytes, and untrusted media should be re-encoded (a lossy transcode
at a lower sample/bit budget destroys fragile frequency-domain payloads). Treat every
media file as a potential covert channel — metadata, LSBs, *and* frequency content.
