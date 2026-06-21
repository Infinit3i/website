---
layout: post
title: "PortSwigger: Reflected DOM XSS"
date: 2026-09-02 09:00:00 -0500
categories: [PortSwigger, XSS]
tags: [xss, dom-xss, reflected-xss, eval, json, javascript, CWE-79]
---

## Overview

This lab demonstrates a **reflected DOM-based XSS** vulnerability where the
server reflects user input inside a JSON response, and client-side JavaScript
passes that JSON to `eval()` — executing the attacker's payload as code.

**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

---

## The Vulnerability

The search feature sends the query to `/search-results`:

```
GET /search-results?search=test
```

```json
{"searchTerm":"test","results":[...]}
```

Client-side JavaScript in `searchResults.js` evaluates this response:

```javascript
eval('var searchResultsJson = ' + responseText);
```

The server attempts to sanitise input by escaping double-quotes (`"` → `\"`),
but it does **not** escape backslashes (`\`). This asymmetry is the bug.

---

## How the Exploit Works

Injecting `\"-alert(1)}//` exploits the incomplete escaping in three steps:

1. **Backslash neutralises the server's own escape** — the server escapes the
   injected `"` to `\"`, but the preceding `\` is left raw, producing `\\"` in
   the response
2. **`eval()` parses `\\` as a literal backslash** — the `"` after it closes
   the JavaScript string literal
3. **`-alert(1)}//` executes** — `}` closes the object literal, `//` comments
   out the trailing `"` the server appended

The JSON response looks like this:

```json
{"results":[],"searchTerm":"\\"-alert(1)}//"}
```

When `eval()` runs this as JavaScript source, the alert fires.

---

## Confirming the Escape Asymmetry

Before firing the payload, probe with a bare backslash:

```
GET /search-results?search=%5C%22
→ {"results":[],"searchTerm":"\\""}
```

The backslash appears un-escaped in the JSON (`\\"` not `\\\\"`). That confirms
the server only escapes quotes, not backslashes — making the bypass possible.

---

## Execution

Because the sink is entirely client-side (`eval()` in the browser), the exploit
cannot be confirmed with `curl` — the server response contains only the JSON
data. The alert fires when a real JavaScript engine loads the page.

Drive with headless Chromium (selenium):

```
URL: /?search=%5C%22-alert%281%29%7D//
FIRED: '1'
ALERT_FIRED: True
```

PortSwigger's lab instrumentation hooks `alert()` and marks the lab solved when
it fires.

---

## The Fix

Replace `eval()` with `JSON.parse()`:

```javascript
// vulnerable
eval('var searchResultsJson = ' + responseText);

// fixed
var data = JSON.parse(responseText);
renderResults(data.results);
```

`JSON.parse()` interprets the input as a data structure, not executable code.
If `eval()` must be used, escape **both** `\` (→ `\\`) and `"` (→ `\"`) in
all string values before embedding them in a JavaScript context.

---

## Key Takeaway

Incomplete JSON escaping (quoting `"` but not `\`) combined with `eval()` is a
classic reflected DOM XSS pattern. The backslash lets the attacker neutralise
the server's own sanitisation. The distinction from pure DOM XSS: the data
makes a server round-trip and is reflected in JSON — but the dangerous
evaluation is fully client-side, which is why the server's response alone never
reveals the vulnerability.
