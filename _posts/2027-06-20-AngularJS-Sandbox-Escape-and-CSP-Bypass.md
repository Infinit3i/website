---
layout: post
title: "Reflected XSS with AngularJS Sandbox Escape and CSP Bypass"
date: 2027-06-20 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, angularjs, csp-bypass, ng-csp, composedPath, orderBy, sandbox-escape, portswigger]
---

## Overview

This PortSwigger lab combines two hardened defences — `ng-csp` mode and a strict `Content-Security-Policy` — and demonstrates why neither is sufficient when AngularJS itself is hosted on the target origin. The technique uses the `ng-focus` directive and `$event.composedPath()` to reach `window.alert` without ever calling `Function` or `eval`.

**Vuln class:** Reflected XSS / AngularJS Client-Side Template Injection (CWE-79)  
**AngularJS version:** 1.4.4 with `ng-csp`  
**CSP:** `default-src 'self'; script-src 'self'`

---

## The Setup

The search page reflects the `?search=` parameter raw into the HTML (no encoding), inside an AngularJS application:

```html
<body ng-app ng-csp>
  <h1>0 search results for 'SEARCH_TERM_HERE'</h1>
```

- `ng-app` — the whole page is an AngularJS scope; reflected HTML becomes live AngularJS directives
- `ng-csp` — disables AngularJS's use of `eval()` and the `Function` constructor internally

The CSP blocks all inline scripts:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
```

### Why the standard payloads fail

The classic AngularJS CSTI payload `{{$on.constructor('alert(1)')()}}` invokes `Function` under the hood — blocked by `ng-csp`.

The no-string sandbox escape (`toString().constructor.prototype.charAt=[].join; [1]|orderBy:toString().constructor.fromCharCode(...)`) also routes through `Function` — same block.

---

## The Working Technique: composedPath + orderBy

### Payload

```
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

Injected via:
```
/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x
```

### How it works

**Step 1 — Injection:** The raw `<input id=x>` tag lands in the DOM inside the `ng-app` scope, so AngularJS processes all its directives.

**Step 2 — Auto-focus:** The URL fragment `#x` instructs the browser to focus the element with `id=x` after the page loads. No user interaction required.

**Step 3 — ng-focus fires:** AngularJS evaluates the `ng-focus` expression when the focus event occurs:
```
$event.composedPath()|orderBy:'(z=alert)(document.cookie)'
```

**Step 4 — composedPath():** `$event` is the native DOM focus event. `$event.composedPath()` returns the event's composed path — an array of every DOM node from the target up to the root:
```
[input, h1, section, div, body, html, document, window]
```

**Step 5 — orderBy executes the expression:** The `orderBy` filter iterates over the array. For each element it evaluates `(z=alert)(document.cookie)` using that element as the local scope.

**Step 6 — window context:** When the element is `window`, `alert` is accessible as a property. The expression:
- `(z=alert)` — assigns the global `alert` function to `z`
- `(z)(document.cookie)` — calls `alert(document.cookie)`

### Why this bypasses ng-csp

`ng-csp` restricts `Function` and `eval` — but the AngularJS `orderBy` filter's expression evaluator uses neither. It walks the expression's syntax tree directly (via `$parse`). The window-scope access happens because `window` is literally in the array being iterated, making its properties the current scope.

### Why this bypasses script-src 'self'

AngularJS is loaded from `'self'` (the same origin), so the CSP permits it. The `ng-focus` expression runs **within AngularJS's own expression evaluator** — it is not a new inline `<script>` block. The CSP has no mechanism to restrict what AngularJS evaluates once it is running.

---

## Delivery

Because the exploit needs a real browser (AngularJS is client-side), it is delivered via a PortSwigger exploit server redirect. The exploit server page has no restrictive CSP, so the inline script there runs freely:

```html
<script>
location='https://<lab-id>.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

The victim bot visits the exploit server, gets redirected to the lab, and the XSS fires on the lab origin.

---

## The Fix

1. **HTML-encode all reflected output** — if `<` is encoded to `&lt;`, the `<input>` tag never enters the DOM, and no AngularJS directive is ever processed
2. **Never put user input into an AngularJS template scope** — treat `ng-app` context as a JavaScript execution boundary
3. **`ng-csp` is not a security mitigation** — it restricts AngularJS internals but cannot restrict what an injected directive's expression does
4. **Migrate off AngularJS 1.x** — EOL since December 2021; Angular 2+ removes the client-side template injection vector entirely
