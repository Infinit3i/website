---
layout: post
title: "Clobbering DOM Attributes to Bypass HTML Filters"
date: 2027-08-06 09:00:00 -0500
categories: [PortSwigger, DOM-Based]
tags: [portswigger, dom-clobbering, xss, CWE-79, htmljanitor, stored-xss, javascript, html-injection, sanitizer-bypass]
---

## Overview

This PortSwigger Practitioner lab demonstrates a second form of DOM clobbering: instead of overwriting a JavaScript global variable, the attacker overwrites the `attributes` property of a DOM node to **blind the HTML sanitizer's own attribute-filtering loop**. The sanitizer (HTMLJanitor) trusts `node.attributes` to enumerate a tag's attributes — but `HTMLFormElement` has a named getter that lets an attacker-controlled child element intercept that property read. Result: the loop condition evaluates to `0 < undefined` (always false), the loop never runs, and a dangerous event handler like `onfocus=print()` survives sanitization verbatim.

**CWE:** [CWE-79 — Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)

---

## The Technique

### Why HTMLFormElement is special

In JavaScript, accessing a property on an `HTMLFormElement` uses a **named getter** defined in the HTML spec. When you write `form['x']`, the browser first checks whether any child element has `id="x"` or `name="x"`. If it finds one, it returns that element — not any prototype property named `x`.

This means `form['attributes']` does **not** always return the standard `NamedNodeMap` of the form's own attributes. If the form contains a child `<input id=attributes>`, the named getter intercepts the read and returns the `<input>` element instead.

### How HTMLJanitor uses node.attributes

HTMLJanitor's attribute-removal pass:

```js
for (var a = 0; a < node.attributes.length; a += 1) {
  var attr = node.attributes[a];
  if (shouldRejectAttr(attr, allowedAttrs, node)) {
    node.removeAttribute(attr.name);
    a = a - 1;
  }
}
```

When `node` is a `<form>` element with a child `<input id=attributes>`:

- `node.attributes` → the `<input>` element (not a NamedNodeMap)
- `node.attributes.length` → `undefined` (HTMLElement has no `.length`)
- `0 < undefined` → `false`
- The loop body never executes → no attributes are removed

### The payload

```
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

Both tags pass HTMLJanitor's node allow-list (`form:{id:true}`, `input:{name:true,type:true,value:true}`). The `<input id=attributes>` child clobbers the form's `attributes` property, making the sanitizer blind. `onfocus=print()` survives. `tabindex=0` makes the form focusable.

---

## Exploit Delivery

A form with `tabindex=0` fires `onfocus` when it receives focus. The URL fragment `#x` causes the browser to focus the element with `id=x`. The exploit is delivered from the exploit server as an iframe that appends `#x` to its src after the page's XHR comment load completes:

```html
<iframe src=https://TARGET/post?postId=1
  onload="setTimeout(()=>this.src=this.src+'#x',500)">
</iframe>
```

The 500ms delay ensures the comments (loaded asynchronously via XHR) are rendered in the DOM before the fragment navigation fires. The victim's browser auto-focuses the form, `onfocus` fires, and the lab is solved.

**Note:** This only works in Chrome. Firefox does not auto-focus elements in cross-origin iframes on fragment navigation.

---

## Root Cause

The root cause is that HTMLJanitor iterates `node.attributes` — a DOM property that can be intercepted by the `HTMLFormElement` named getter — rather than using a clobbering-safe alternative like `Array.from(node.attributes)` or `node.getAttributeNames()`.

---

## The Fix

1. **Remove `<form>` and `<input>` from the allow-list.** Blog comments don't need form elements; removing them eliminates the clobbering vector entirely.
2. **Strip `id` and `name` from allowed `<form>`/`<input>` attributes.** The named getter requires a child with matching `id` or `name` — blocking those attrs prevents the clobber.
3. **Use a clobbering-safe attribute iterator:**

```js
// Vulnerable: node.attributes is clobberable on <form> elements
for (var a = 0; a < node.attributes.length; a++) { ... }

// Safe: Array.from() returns a real array, bypasses the named getter
const attrs = Array.from(node.attributes);
for (var a = 0; a < attrs.length; a++) { ... }
```

4. **Replace HTMLJanitor with a maintained sanitizer** such as DOMPurify ≥ 2.0.17, which accounts for this and related DOM clobbering patterns.
