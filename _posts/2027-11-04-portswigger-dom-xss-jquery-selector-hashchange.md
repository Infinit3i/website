---
layout: post
title: "PortSwigger: DOM XSS in jQuery selector sink using a hashchange event"
date: 2027-11-04 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, XSS]
tags: [portswigger, xss, dom-xss, jquery, hashchange, location-hash, cwe-79]
---

A blog page uses jQuery to scroll you to a post whose title matches whatever you put after the `#` in the URL. The author reached for `$( ... )` to find that heading — not realizing that in old jQuery, `$()` will happily turn a string containing `<img>` into a real element. Feed it `<img src=x onerror=print()>` and the browser runs your code. This is a **DOM-based XSS** ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)): the dangerous data never touches the server — it flows entirely client-side, from `location.hash` into a jQuery sink.

## Overview

The goal is to make the victim's browser call `print()`. The vulnerable code sits in an inline script on the blog index:

```js
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

It reads the URL fragment (everything after `#`), URL-decodes it, and concatenates it into a jQuery `$( ... )` call. Two things about that line make it exploitable.

## Trap 1: `$()` is secretly an HTML parser

The sink everyone watches for is `.html()` or `innerHTML`. But `$()` *itself* is just as dangerous in jQuery before version 3. If the string you pass it contains a tag like `<img>`, jQuery stops treating it as a CSS selector and **builds the element** instead (internally via `innerHTML`).

So even though our input is wedged inside a `:contains(...)` selector, jQuery sees the `<img>` substring and constructs it:

```
<img src=x onerror=print()>
```

`src=x` isn't a real image, so the browser fires the `onerror` handler, which runs `print()`.

## Trap 2: `hashchange` only fires when the fragment *changes*

The handler is bound to the `hashchange` event, which fires **only when the fragment changes after the page has loaded** — not on the initial load. So a plain link with the payload already in the `#` does nothing: the page loads, the handler registers, but no change ever happens.

The trick is to load the page first and change the hash afterwards. An iframe does exactly that:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/#"
        onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

Step by step:

1. The iframe loads `…/#`, registering the page's `hashchange` handler.
2. The iframe's `onload` fires and **appends** the payload to its own `src`, making the URL `…/#<img src=x onerror=print()>`.
3. Only the fragment changed, so the page doesn't reload — but `hashchange` fires.
4. jQuery parses the `<img>`, the browser runs `onerror`, and `print()` executes.

Save that HTML on the exploit server and click **Deliver to victim**. The lab flips to **Solved**.

## Confirming it without the bot

You can prove the payload fires yourself by loading the page in headless Chromium and changing the hash by hand — which reproduces the `hashchange` trigger:

```python
d.get(base + "/#")
d.execute_script("location.hash = arguments[0];", "<img src=x onerror=print()>")
```

This is purely a sanity check that the XSS executes; the lab itself records the solve when its victim bot runs your delivered exploit.

## Why it worked

`$()` is overloaded — it is both a selector engine and an HTML builder. The instant untrusted data containing angle brackets reaches it, it becomes raw HTML injection, no different from writing to `innerHTML`. The `:contains()` wrapper is irrelevant; jQuery never evaluates it as a selector once it spots the tag.

## The fix

- **Never pass untrusted input to `$()`.** Treat the `:contains()` argument as text: read the headings into JavaScript and compare strings yourself, rather than building a selector from user data.
- **Upgrade jQuery.** Modern versions refuse to build HTML from a string passed to `$()` as a selector.
- As a rule, keep DOM *sources* — `location.hash`, `location.search`, `document.referrer` — away from DOM *sinks* that interpret HTML or JavaScript.
