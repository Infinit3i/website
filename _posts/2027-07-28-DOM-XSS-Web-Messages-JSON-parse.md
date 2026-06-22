---
layout: post
title: "PortSwigger: DOM XSS using web messages and JSON.parse"
date: 2027-07-28 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, dom-xss, postMessage, json-parse, CWE-79, web-messages, iframe-src, javascript-url]
---

## Lab

**Topic:** DOM-based Cross-Site Scripting via web message source with JSON.parse ([CWE-79](https://cwe.mitre.org/data/definitions/79.html))  
**Goal:** Exploit a `postMessage` handler that parses incoming JSON and assigns a `url` field directly to an `iframe`'s `src` attribute to call `print()` in the victim's browser.

---

## Overview

The target page registers a `message` event listener that calls `JSON.parse(e.data)` and dispatches on a `type` field. When `type` is `"load-channel"`, the handler assigns `d.url` directly to a dynamically-created `iframe`'s `src` — no scheme validation, no origin check. Sending `{"type":"load-channel","url":"javascript:print()"}` via `postMessage` from an attacker-controlled page sets the iframe src to a `javascript:` URI, executing `print()` in the victim's browsing context.

---

## The Technique

`window.postMessage` allows cross-origin frame communication. When a page registers a `message` listener without validating `e.origin` and then feeds attacker-controlled message data directly into a URL-type DOM sink, the attacker controls what the browser navigates to or loads. In this variant the sink is `iframe.src` — a property that accepts `javascript:` URIs and executes them in the frame's context.

The `JSON.parse` step is a structural detail, not a defence. It only requires the payload to be valid JSON; the URL value inside is never checked.

---

## Vulnerable code

```javascript
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
    document.body.appendChild(iframe);
    try {
        d = JSON.parse(e.data);
    } catch(e) { return; }
    switch(d.type) {
        case "page-load":
            ACMEplayer.element.scrollIntoView();
            break;
        case "load-channel":
            ACMEplayer.element.src = d.url;  // sink — no scheme check
            break;
        case "player-height-changed":
            ACMEplayer.element.style.width = d.width + "px";
            ACMEplayer.element.style.height = d.height + "px";
            break;
    }
}, false);
```

There are three missing controls: no `e.origin` validation, no allowlist of permitted `type` values, and no scheme guard on `d.url`.

---

## Solution

Host the following on an exploit server and deliver to the victim:

```html
<iframe src=https://VICTIM/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'></iframe>
```

**Step by step:**
1. The outer iframe loads the target page.
2. `onload` fires immediately; `postMessage` delivers the JSON string to the target frame (`"*"` as targetOrigin — accepted by the listener unconditionally).
3. The target's listener calls `JSON.parse`, hits the `"load-channel"` case, and executes `ACMEplayer.element.src = "javascript:print()"`.
4. The browser evaluates `print()` in the inner iframe's context — lab solved.

**HTML quoting note:** the `onload` attribute uses single quotes. The JSON payload contains double-quotes; a double-quoted `onload` attribute would cause the browser's HTML parser to treat the first `"` inside the JSON as closing the attribute, silently breaking the payload before it ever runs.

---

## Why it worked

- `e.origin` is never checked — any cross-origin sender can post a message.
- The `type` switch has no default rejection — unknown types are ignored, but known types are processed without further validation.
- `iframe.src` accepts `javascript:` URIs as a valid scheme and executes the expression in the frame's context.

All three gaps are independent: any one fixed would have blocked this attack.

---

## Fix

```javascript
window.addEventListener('message', function(e) {
    // 1. Validate origin against a strict allowlist
    if (e.origin !== 'https://trusted-origin.example.com') return;

    var d;
    try { d = JSON.parse(e.data); } catch(err) { return; }

    // 2. Allowlist permitted type values
    const ALLOWED_TYPES = new Set(['page-load', 'load-channel', 'player-height-changed']);
    if (!ALLOWED_TYPES.has(d.type)) return;

    if (d.type === 'load-channel') {
        // 3. Enforce https?:// before assigning to any URL-type sink
        if (!/^https?:\/\//.test(d.url)) return;
        ACMEplayer.element.src = d.url;
    }
    // ... other cases
}, false);
```

Apply all three controls together. An anchored `^https?://` regex on the URL rejects `javascript:` and `data:` schemes; an origin allowlist blocks messages from untrusted pages; a type allowlist prevents undocumented dispatch cases from being added silently later.
