---
layout: post
title: "Reflected XSS with Event Handlers and href Attributes Blocked"
date: 2027-06-20 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, reflected-xss, svg, smil, animate, href-bypass, waf-bypass, portswigger]
---

## Overview

PortSwigger lab: *Reflected XSS with event handlers and href attributes blocked.*

The application reflects `?search=` input into the HTML response but runs it through a filter that blocks all event handler attributes and the `href` attribute on `<a>` tags. The correct bypass uses SVG SMIL's `<animate>` element to write `href=javascript:alert(1)` onto an anchor at runtime — entirely without event attributes.

**CWE-79** — Reflected Cross-Site Scripting.

---

## Why this works

SVG includes an animation subsystem called SMIL (Synchronized Multimedia Integration Language). The `<animate>` element belongs to this subsystem: it carries no `on*` attributes and instead instructs the browser's SMIL engine to set a named attribute on the parent element at a given time.

The key property: `attributeName=href` tells the browser to animate the `href` attribute of the parent `<a>` element. Combined with `values=javascript:alert(1)`, the SMIL engine writes `href=javascript:alert(1)` onto the anchor immediately when the page loads.

The server-side filter never sees `href` as a static attribute on `<a>` — it sees only the `<animate>` element and its SMIL properties, which it passes through. The browser then executes SMIL and the href is set dynamically. Clicking the rendered "Click me" text fires the `javascript:` scheme.

---

## Payload

```html
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>
```

- `<svg>` opens the SVG namespace so SMIL is parsed
- `<a>` is the anchor that will receive the dynamic href
- `<animate attributeName=href values=javascript:alert(1) />` — SMIL sets `href` on the parent `<a>` to `javascript:alert(1)` at page-load time with no event attribute
- `<text x=20 y=20>Click me</text>` — visible SVG text, nested inside the anchor and therefore clickable

---

## Comparing SMIL bypass techniques

Two SVG SMIL bypasses exist for XSS filter evasion — they address different filter configurations:

| Technique | Event attribute used? | Fires automatically? |
|-----------|----------------------|----------------------|
| `<svg><animatetransform onbegin=alert(1)>` | Yes — `onbegin` | Yes, on page load |
| `<svg><a><animate attributeName=href values=javascript:alert(1) />` | None | No — requires one click |

The `<animatetransform onbegin>` bypass works when a WAF misses SVG namespace events but still passes `on*` attribute names. This lab's filter is stricter — ALL `on*` attributes are blocked regardless of namespace. The `<animate attributeName=href>` technique wins here because it carries zero event attributes; it exploits SMIL's attribute-write mechanism instead.

---

## Detection

When fuzzing the reflected parameter:
- Tags `<svg>`, `<a>`, `<animate>`, `<text>` all return HTTP 200
- Every `<tag on*=1>` combination returns HTTP 400

This pattern — comprehensive event-handler blocking combined with SVG tag allowlisting — is the signal for the `attributeName=href` technique.

---

## Fix

The correct defence is **output encoding**, not tag/attribute filtering. HTML-encoding `<` and `>` before reflecting input turns the payload into inert literal text:

```
&lt;svg&gt;&lt;a&gt;&lt;animate attributeName=href ...
```

The browser renders that as plain text, not markup. No SMIL engine ever parses it.

Denylist filtering (block event attributes, block href) is structurally fragile: the browser's tag and attribute set grows across specs (SVG, MathML, ARIA, SMIL), and new bypass vectors emerge with every new API. Encode output by context; do not try to enumerate attacker techniques.
