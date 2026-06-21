---
layout: post
title: "PortSwigger: Reflected XSS in canonical link tag (accesskey + onclick)"
date: 2027-06-12 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [portswigger, xss, cwe-79, canonical-link, accesskey, onclick, attribute-injection, reflected-xss]
---

A reflected [cross-site scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html) lab where the injection context is the `href` attribute of a `<link rel="canonical">` tag in the page `<head>`. Angle brackets are escaped — but single quotes are not, enabling attribute breakout to inject `accesskey` and `onclick` onto a non-rendering element.

## Overview

**Lab:** Reflected XSS in canonical link tag  
**Source:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-canonical-link-tag)  
**Vuln class:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## The vulnerability

The application reflects the request URL into a `<link rel="canonical">` tag in the `<head>`:

```html
<link rel="canonical" href="https://victim.com/current-page">
```

The server escapes `<` and `>`, which blocks classic tag injection — but it does **not** encode single quotes. Inside an HTML attribute the unescaped single quote terminates the attribute value and everything after it is parsed as additional attributes on the same element.

### Why this context is tricky

`<link>` is a non-rendering head element. Techniques that rely on the element loading a resource (`onerror`, `onload`) don't apply — `<link>` doesn't display or fetch in a way that triggers those handlers. Standard attribute-context payloads like `" onmouseover=alert(1)` also fail if the `href` is double-quote delimited (you'd need a `"` to break out, which gets HTML-encoded).

The single-quote bypass works because the `href` here is rendered with double-quote delimiters but the **value** contains an unescaped `'`. When the browser parser sees `href="...'accesskey='x'onclick='alert(1)"`, it treats the `'` as closing the (non-existent) single-quote attribute delimiter context and parses `accesskey="x"` and `onclick="alert(1)"` as separate attributes on the `<link>` tag.

---

## Working payload

```
?'accesskey='x'onclick='alert(1)
```

Rendered in the page:

```html
<link rel="canonical" href="https://victim.com/?" accesskey="x" onclick="alert(1)">
```

**Trigger:** Press **Alt+Shift+X** (Linux/Windows) — the browser fires the `onclick` handler via the registered access key.

> Chrome honours `accesskey` + `onclick` on non-anchor elements including `<link>`. Firefox does not.

---

## Executing with Selenium

Since the payload requires keyboard interaction, a browser driver is needed:

```python
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

driver.get(f"https://victim.com/?'accesskey='x'onclick='alert(1)")
ActionChains(driver).key_down(Keys.ALT).key_down(Keys.SHIFT) \
    .send_keys('x').key_up(Keys.SHIFT).key_up(Keys.ALT).perform()
```

The `alert()` fires in the headless browser, which PortSwigger's lab instrumentation captures to mark the lab solved.

---

## CWE-79 — The fix

Context-aware output encoding. When reflecting user input into an HTML attribute value, encode **all four** HTML metacharacters: `<`, `>`, `"`, and `'`.

**Vulnerable:**
```php
echo '<link rel="canonical" href="' . $_SERVER['REQUEST_URI'] . '">';
```

**Fixed:**
```php
echo '<link rel="canonical" href="' . htmlspecialchars($_SERVER['REQUEST_URI'], ENT_QUOTES) . '">';
```

`ENT_QUOTES` is critical — without it, PHP only encodes double quotes, leaving single-quote breakout possible. A Content Security Policy adds defense-in-depth but cannot substitute for fixing the root encoding failure.

---

## Key takeaway

Non-rendering elements like `<link>`, `<meta>`, and `<base>` are still injection surfaces. When angle-bracket filtering is the only defense:

- `<link>`: `accesskey` + `onclick` (Chrome only, requires user or Selenium keyboard trigger)  
- `<base>`: `href` injection redirects all relative URLs on the page  
- `<meta>`: HTTP-equiv refresh can redirect the user

Always encode `'` as well as `<>` in attribute values, regardless of whether you use single- or double-quote delimiters.
