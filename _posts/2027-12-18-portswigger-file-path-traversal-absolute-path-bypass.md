---
layout: post
title: "PortSwigger: File path traversal, traversal sequences blocked with absolute path bypass"
date: 2027-12-18 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, PathTraversal]
tags: [portswigger, path-traversal, lfi, absolute-path, filter-bypass, cwe-22]
---

A product image endpoint that reads whatever filename you give it is a textbook [path traversal](https://cwe.mitre.org/data/definitions/22.html) ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)). This lab bolts on a filter that blocks `../` — and then forgets that an **absolute path** never needs `../` in the first place.

## Overview

The shop serves each product image with a request like `GET /image?filename=50.jpg`. Whatever lands in `filename` is read straight off disk, so in principle you can read files outside the images directory. To stop that, the developer rejects any `filename` containing `../`. The goal is to read `/etc/passwd` anyway.

## The technique

Filenames resolve in one of two ways:

- **Relative** — `images/50.jpg` is resolved starting from the app's working directory. To climb out you need `../`, and that's exactly what the filter rejects.
- **Absolute** — `/etc/passwd` begins with `/`, so the operating system resolves it from the filesystem root and ignores the working directory entirely.

An absolute path contains no `../`, so the filter never triggers. You walk straight out of the base directory without ever using the sequence the filter watches for.

## Walkthrough

First confirm the filter is active — the relative traversal is rejected:

```
GET /image?filename=../../../etc/passwd     → HTTP 400
```

Now supply an absolute path instead:

```bash
curl -sk "https://<lab-id>.web-security-academy.net/image?filename=/etc/passwd"
```

The server returns `HTTP 200` with the file:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

Reading the file flips the lab's status widget to **Solved**.

## Why it works

The filter encodes an incomplete model of "escaping the directory." It assumes escape always looks like `../`, so it blocks that string. But the filesystem offers a second, simpler way out: a path that starts at the root. Because the code passes the filename straight to a file read without anchoring it to the base directory, a leading `/` is honoured and the base directory is bypassed.

## The fix

Don't blocklist `../`. Resolve the input to a canonical real path and confirm it stays inside the intended directory:

```python
full = os.path.realpath(os.path.join(BASE, filename))
if not full.startswith(os.path.realpath(BASE) + os.sep):
    abort(400)
open(full).read()
```

`realpath` collapses both `../` sequences and absolute paths down to one canonical location, and the `startswith` check rejects anything that escaped `BASE`. Better yet, never accept a raw path: map a known ID to a filename server-side, or use `os.path.basename()` so only a bare leaf name can ever be used.

The takeaway for testing: whenever relative `../` traversal is blocked, try a plain absolute path first (`/etc/passwd` on Linux, a drive letter or UNC path on Windows). It's the cheapest bypass in the traversal family, and any filter that only strips `../` is blind to it.
