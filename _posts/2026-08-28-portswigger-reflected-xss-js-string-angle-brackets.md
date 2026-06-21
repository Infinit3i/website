---
layout: post
title: "PortSwigger: Reflected XSS into a JavaScript String with Angle Brackets HTML Encoded"
date: 2026-08-28 09:00:00 -0500
categories: [Web Security, XSS]
tags: [portswigger, xss, cwe-79, javascript, reflected-xss, web-security-academy]
---

A common partial fix for XSS is encoding angle brackets — it blocks `<script>` tag injection but misses a whole class of attacks where the reflection lands inside JavaScript itself. This lab demonstrates exactly that gap.

## The setup

The search feature reflects the query into a JavaScript string:

```html
<script>
    var searchTerms = 'USER_INPUT';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='
        + encodeURIComponent(searchTerms) + '">');
</script>
```

The app encodes `<` and `>`, so you cannot inject a `<script>` tag or an `<img onerror=...>` handler. At first glance it looks protected.

## The context is the key

When the reflection lands **inside a `<script>` block**, you are already in JavaScript. Angle brackets are irrelevant — you do not need to inject an HTML element. You need to break the **string literal**.

Single quotes are not encoded. The payload:

```
'-alert(1)-'
```

transforms the server's code to:

```javascript
var searchTerms = ''-alert(1)-'';
```

JavaScript parses this as `('' - alert(1) - '')`. The `-` operator is subtraction — `alert(1)` fires as a subexpression, calling the dialog. The surrounding empty strings coerce to `0` and the overall expression evaluates to `NaN`, but the alert already executed.

## Confirming it

A raw `curl` reflects the payload in the response body, but the lab is solved by actually running the JavaScript. Driving the URL through headless Chromium confirms the `alert()` fires and the lab marks `is-solved`.

## The fix

HTML-encoding angle brackets is not enough when user input is embedded in a JavaScript context. The encoding rules are **context-specific**:

| Where the value lands | What must be escaped |
|---|---|
| HTML body | `<` `>` `&` |
| HTML attribute | `<` `>` `"` `'` `&` |
| JavaScript string | `'` `"` `\` (backslash-escape) |
| URL (`href`/`src`) | percent-encode; validate scheme |

The real fix is to avoid embedding raw user input inside `<script>` blocks at all. Pass server-side data via a `data-*` attribute (HTML-entity-encoded), then read it in JavaScript through the DOM:

```html
<!-- Pass data safely via attribute -->
<div id="tracker" data-terms="{{ query | escape }}"></div>

<script>
  // Read from DOM — no string interpolation into JS
  var searchTerms = document.getElementById('tracker').dataset.terms;
</script>
```

This way the HTML parser handles the encoding (it knows the context), and JavaScript never receives raw interpolated input.

## CWE

[CWE-79 — Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)](https://cwe.mitre.org/data/definitions/79.html)
