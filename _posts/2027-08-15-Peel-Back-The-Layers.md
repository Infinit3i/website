---
layout: post
title: "Peel Back The Layers"
date: 2027-08-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, docker, supply-chain, whiteout, CWE-912, CWE-506]
---

## Overview

**Peel Back The Layers** is an Easy HackTheBox **Forensics** challenge. A rival hacker backdoored the public Docker image `steammaintainer/gearrepairimage` on Docker Hub by hiding a malicious reverse-shell shared library inside a lower image layer, then concealing it in the final layer with an OCI [whiteout](https://cwe.mitre.org/data/definitions/912.html) marker. The goal is to pull the image, peel back its layers with `docker save`, and extract the backdoor to recover the flag.

## The technique

Docker images are built as a stack of read-only OCI layers — each one a tar archive of filesystem changes applied in order. When a `RUN rm` instruction removes a file, Docker does **not** erase it from the layer where it was added. Instead, it writes a **whiteout marker** (`.wh.<filename>`, or `.wh..wh..opq` for an entire directory) into the new layer. The container runtime honors these markers at mount time via overlayfs — the file disappears from the running container's view.

The hiding mechanism:

```
Layer 2 (20 KB):  ADD  usr/share/lib/librs.so   ← backdoor planted here
Layer 3 ( 2.5 KB): usr/share/.wh.lib             ← whiteout hides lib/ at runtime
```

At runtime the `lib/` directory is invisible. But `docker save` dumps the **raw layer tars** — it bypasses overlay merging entirely. The whiteout is just another file in layer 3; the backdoor is still byte-for-byte present in layer 2 and extractable with `tar`.

This is a [hidden functionality](https://cwe.mitre.org/data/definitions/912.html) ([CWE-912](https://cwe.mitre.org/data/definitions/912.html)) supply-chain attack: consumers pull and run the backdoor without any visible indicator in the container filesystem.

## Solution

### Step 1 — Pull and save the image

```bash
docker pull steammaintainer/gearrepairimage
docker save steammaintainer/gearrepairimage > /tmp/peel.tar
mkdir -p /tmp/peelfs && tar xf /tmp/peel.tar -C /tmp/peelfs
```

After extraction, `manifest.json` lists three layer blobs in order. The smallest blob (2.5 KB) is an immediate red flag — a production layer that small is almost certainly whiteout-only.

### Step 2 — Scan all layers for whiteouts and hidden files

```bash
for l in /tmp/peelfs/blobs/sha256/*; do
  echo "--- $(du -sh $l | cut -f1) ---"
  tar tf "$l" 2>/dev/null | grep -E '\.wh\.|\.so$|/lib'
done
```

Output reveals the pattern:

```
--- 72M ---      (base OS — nothing interesting)
--- 20K ---
usr/share/lib/
usr/share/lib/librs.so          ← backdoor added in layer 2
--- 4.0K ---
usr/share/.wh.lib               ← whiteout in layer 3 hides lib/
```

### Step 3 — Extract the backdoor from layer 2

```bash
# Layer 2 SHA: 0a9080e8e7...
tar xf /tmp/peelfs/blobs/sha256/0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26 \
  usr/share/lib/librs.so -O > /tmp/librs.so
file /tmp/librs.so
# ELF 64-bit LSB shared object, x86-64 — reverse-shell .so
```

### Step 4 — Recover the flag

```bash
strings /tmp/librs.so | grep -A5 HTB
```

The flag is stored as sequential 8-byte chunks in the ELF `.rodata` section (an alignment artifact — each chunk ends with the first byte of the next):

```
HTB{1_r3H
4lly_l1kH
3_st34mpH
unk_r0b0H
ts!!!}
```

Strip the trailing `H` from each chunk and concatenate:

**Flag: `HTB{...}`**

The full automated solve:

```python
#!/usr/bin/env python3
"""
HTB - Peel Back The Layers (Forensics, Easy)
Pull image, save to tar, extract layer 2, recover flag from librs.so ELF chunks.
"""
import subprocess, tarfile, os

IMAGE    = "steammaintainer/gearrepairimage"
LAYER2   = "0a9080e8e7b0e66532e403a406ccdbc7c58fea8493928a3baaf5ca83e2943e26"
LIBPATH  = "usr/share/lib/librs.so"
WORKDIR  = "/tmp/peel_work"

os.makedirs(WORKDIR, exist_ok=True)
tar_path = f"{WORKDIR}/img.tar"
if not os.path.exists(tar_path):
    subprocess.run(f"docker save {IMAGE} > {tar_path}", shell=True, check=True)

imgfs = f"{WORKDIR}/imgfs"
if not os.path.exists(imgfs):
    os.makedirs(imgfs)
    with tarfile.open(tar_path) as tf:
        tf.extractall(imgfs)

librs = f"{WORKDIR}/librs.so"
layer2_tar = f"{imgfs}/blobs/sha256/{LAYER2}"
with tarfile.open(layer2_tar) as tf:
    with tf.extractfile(LIBPATH) as src, open(librs, "wb") as dst:
        dst.write(src.read())

result = subprocess.run(["strings", librs], capture_output=True, text=True)
chunks = [l for l in result.stdout.splitlines()
          if any(x in l for x in ["HTB{", "r34", "l1k", "st34", "r0b0", "ts!!!}"])]

flag = "".join(c.rstrip("H") for c in chunks)
print(f"[+] FLAG: {flag}")
```

## Why it worked

`docker save` is a raw export of the OCI image layout — it produces the layer tars exactly as they were pushed, with no overlay merging. Whiteout markers are only honored by the container runtime at mount time; they have no meaning to `tar` or to `strings`. A deleted file in the final container view is still physically present in the lower layer blob and requires no special tooling to recover — just `tar tf` and `tar xf`.

The backdoor itself (`librs.so`) is an [embedded malicious shared object](https://cwe.mitre.org/data/definitions/506.html) ([CWE-506](https://cwe.mitre.org/data/definitions/506.html)) that exports a constructor calling `fork()` + `connect()` + `dup2()` + `execve("/bin/sh")` — any dynamic binary in the container that loaded it would silently spawn a reverse shell.

## Fix / defense

- **Pin image digests** — use `image@sha256:<digest>` instead of `:latest`; a new malicious tag cannot override a pinned digest.
- **Scan all layers, not just the final filesystem** — `trivy image`, `grype`, and `docker scout cves` inspect every layer blob; a `.so` hidden by a whiteout still triggers a finding.
- **Use Docker Content Trust / Sigstore** — `DOCKER_CONTENT_TRUST=1` or cosign attestation confirms the image came from the expected signer.
- **Multi-stage builds from minimal bases** — a `FROM scratch` or `FROM distroless` image has no dynamic linker and no room for layer-hiding tricks.
- **Audit layer history** — `docker history <image>` exposes every `RUN` command and layer size; a tiny top layer over a larger mid-layer is a classic whiteout-hiding red flag.
