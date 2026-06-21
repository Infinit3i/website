---
layout: post
title: "PortSwigger: Stored XSS into Anchor href Attribute with Double Quotes HTML-Encoded"
date: 2026-08-29 09:00:00 -0500
categories: [Web Security, XSS]
tags: [portswigger, xss, cwe-79, stored-xss, href, javascript-uri, web-security-academy]
---

Encoding double quotes in an HTML attribute stops attackers from breaking out of it — but it's only half the story when that attribute is a `href`. The `javascript:` URI scheme executes without needing any quotes at all.

## The setup

A blog comment form has a "Website" field. When the comment is rendered, the value ends up in an anchor tag:

```html
<a id="author" href="WEBSITE_VALUE">AuthorName</a>
```

The app HTML-encodes `"` → `&quot;`, so a payload like `" onmouseover=alert(1) x="` turns into harmless text inside the attribute. Attribute breakout is blocked.

## Why `javascript:` still works

There are two distinct threats in an `href`:

1. **Attribute breakout** — use `"` to end the attribute and inject new HTML. Blocked here.
2. **javascript: scheme** — the URL itself is executable. Not blocked.

When a browser sees `href="javascript:alert(1)"`, it executes the expression on click. The quote encoding never touches the scheme or the payload — there are no double quotes in `javascript:alert(1)`.

## The exploit

Submit a comment with `javascript:alert(1)` as the Website value. The form submission is a `POST` to `/post/comment` with a CSRF token bound to your session:

```
POST /post/comment HTTP/2
Content-Type: application/x-www-form-urlencoded

csrf=<token>&postId=1&comment=test&name=xsstest&email=t@t.com&website=javascript%3Aalert%281%29
```

A `302` response confirms the comment was stored. The page now contains:

```html
<a id="author" href="javascript:alert(1)">xsstest</a>
```

Every visitor who clicks the author name triggers the payload. Lab solved.

## The fix

**Allowlist the URL scheme.** Reject any `href` value whose scheme is not `http://`, `https://`, or a relative path. HTML-encoding the surrounding attribute quotes is necessary to prevent breakout, but it must be paired with scheme validation:

```python
from urllib.parse import urlparse

def safe_url(value):
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https', ''):
        raise ValueError("Invalid URL scheme")
    return value
```

Character encoding is not input validation. When the attribute content is a URL, validate the URL separately.
