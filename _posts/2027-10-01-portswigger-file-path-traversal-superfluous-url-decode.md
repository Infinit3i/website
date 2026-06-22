---
layout: post
title: "PortSwigger: File Path Traversal, Traversal Sequences Stripped With Superfluous URL-Decode"
date: 2027-10-01 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, PathTraversal]
tags: [portswigger, path-traversal, directory-traversal, lfi, file-read, double-encoding, url-decode, filter-bypass, etc-passwd, cwe-22]
---

This lab is the "simple case" with a twist: this time there *is* a filter. The image loader strips `../` out of the filename before reading the file — so the plain traversal that worked in the simple case now bounces with a `400`. But the developer made one extra mistake that hands the whole thing back to you: after stripping `../`, the app [URL-decodes the value a second time](https://cwe.mitre.org/data/definitions/22.html). Decode-after-validate is a self-defeating order, and double-encoding the slashes walks straight through it.

## Overview

The lab is a [file path traversal](https://portswigger.net/web-security/file-path-traversal) ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) where the only defence is a blocklist that removes literal `../` sequences. The catch is that the server performs a **superfluous (redundant) URL-decode** on the filename *after* that strip runs. Because the security check happens before the final decode, an attacker can hide the traversal behind an extra layer of URL-encoding: the filter sees harmless text, then the second decode reconstitutes `../` and the file read escapes the image directory. The objective is to read `/etc/passwd`.

## The technique

Every product image is served like this:

```
GET /image?filename=10.jpg
```

The straightforward traversal — the one that solves the no-filter "simple case" lab — is now blocked:

```
GET /image?filename=../../../etc/passwd
→ HTTP/1.1 400 Bad Request
No such file
```

That `400` tells us the filter is doing its job: it found `../` and stripped it, leaving a broken path. To get past it, encode each slash **twice**. A normal encoded slash is `%2f`; encode the `%` again and you get `%252f`:

```
GET /image?filename=..%252f..%252f..%252fetc/passwd
→ HTTP/1.1 200 OK
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Walk the payload through the server's own logic:

1. **Strip pass** — the app looks for the literal string `../`. The input contains only `..%252f`, which is not `../`, so nothing is removed. The payload survives the filter untouched.
2. **First decode** — the framework URL-decodes the request normally: `%252f` becomes `%2f`.
3. **Second (superfluous) decode** — the app decodes *again* before opening the file: `%2f` becomes `/`.

After both decodes the string is back to `../../../etc/passwd` — but the filter already ran two steps earlier and waved it through. The thing that was validated is not the thing that was used.

The moment the back-end returns a file from outside the image directory, the lab status flips to **Solved**.

## Why it worked

The defence failed on **ordering**, not on logic. Stripping `../` is a reasonable thing to attempt; doing it *before* the final decode makes it worthless, because the decode can manufacture a fresh `../` that no check ever sees.

This is the close cousin of the `....//` bypass, where a non-recursive `str.replace('../','')` removes the inner `../` and leaves a valid one behind — same root cause, different mechanism. Both come down to: **the app sanitises one representation of the path and then reads from a different one.** If a stack happens to add yet another decode layer, you simply add another layer of encoding (`%25252f`).

`/etc/passwd` is only the demonstration. The same primitive reads application source, configuration, and secrets — `.env` files, private keys, anything the web process can open.

## The fix

- **Canonicalise first, then validate.** Fully decode and resolve the path to its absolute real form *before* any security check — never decode after validating.
- **Verify containment.** Resolve the real path (e.g. `realpath`) and confirm it still begins with the intended base directory (`base + "/"`); reject anything that escapes, and reject any `..` that survives canonicalisation.
- **Decode exactly once.** If the value is still percent-encoded after one decode pass, treat that as hostile and reject it — repeated decoding is the entire bug here.
- **Best of all:** don't let users name filesystem paths. Map an opaque ID to a server-side filename through an allowlist so a traversal string never reaches the file API.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger: File path traversal](https://portswigger.net/web-security/file-path-traversal)
- OWASP A01:2021 – Broken Access Control
