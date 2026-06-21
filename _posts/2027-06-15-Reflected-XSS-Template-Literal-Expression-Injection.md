---
layout: post
title: "Reflected XSS into a JavaScript Template Literal via ${} Expression Injection"
date: 2027-06-15 09:00:00 -0500
categories: [Web Security, XSS]
tags: [xss, reflected-xss, template-literal, javascript, portswigger, cwe-79]
---

## Lab Overview

This PortSwigger Web Security Academy lab covers a reflected XSS where the server applies character-level Unicode escaping to all the obvious dangerous characters — angle brackets, quotes, backslash, and even backtick — making HTML breakout and JS string breakout impossible. The bypass comes from the server missing the `$` and `{` characters, which together open a JavaScript template literal expression that executes on page load.

**Vulnerability:** Reflected Cross-Site Scripting (CWE-79)  
**Difficulty:** Practitioner  
**Status:** Solved

---

## The Injection Context

The search endpoint reflects user input into the page source inside a JavaScript template literal:

```javascript
var message = `0 search results for 'USER_INPUT'`;
```

Template literals (backtick strings) are ES6's string interpolation feature. They support embedded expressions via `${...}` — anything inside those delimiters is evaluated as JavaScript when the string is constructed.

---

## Why the Filter Fails

The server's sanitiser applies a Unicode-escape list to the input before embedding it:

| Character | Output |
|-----------|--------|
| `<` | `<` |
| `>` | `>` |
| `"` | `"` |
| `'` | `'` |
| `\` | `\` |
| `` ` `` | `` ` `` |

This looks comprehensive for HTML-context injection: you cannot inject tags, break out of the JS string with a backtick, or use `\"` tricks. But the escape list was designed with HTML and classic JS strings in mind — it never considered `$` or `{`, the two characters that open a template expression. Both pass through the filter unchanged.

---

## The Exploit

Payload:

```
${alert(1)}
```

After the server embeds this into the page:

```javascript
var message = `0 search results for '${alert(1)}'`;
```

The JavaScript engine evaluates `${alert(1)}` immediately when this line executes — before anything else on the page runs. No user interaction, no HTML parsing, no breakout of the string context required.

The lab's instrumented `alert()` fires and the lab marks itself solved.

---

## The Fix

Extend the escape list to include the template interpolation openers:

```javascript
// Add these two replacements to your existing escaper
.replace(/\$/g, '$')   // neutralise $
.replace(/{/g, '{');   // neutralise {
```

The better fix is to avoid this pattern entirely. Never embed user input inside a `<script>` block or a JS template literal. Instead, store the value in a `data-*` attribute and read it client-side via `dataset`, or use a JSON data island with `JSON.stringify()`:

```html
<!-- Safe pattern: data attribute -->
<div id="search-msg" data-term="{{ user_input | html_escape }}"></div>
<script>
  const term = document.getElementById('search-msg').dataset.term;
  const message = `0 results for '${term}'`; // safe — term came from the DOM, not raw HTML
</script>
```

---

## Key Takeaway

Character-level escape lists are inherently fragile — they protect only against the characters the author thought of at the time of writing. JavaScript template literals introduced a new expression context in ES6 that predates most web framework escaping libraries. The `${}` delimiters are a JS-level feature and invisible to HTML-context encoders.

Whenever user input can land inside a backtick string, the sanitiser must also neutralise `$` and `{` — or, better, avoid the pattern so there is nothing to escape.
