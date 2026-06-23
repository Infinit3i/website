---
layout: post
title: "PortSwigger: Information Disclosure in Error Messages"
date: 2027-10-11 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, InformationDisclosure]
tags: [portswigger, information-disclosure, error-messages, stack-trace, framework-fingerprinting, struts, cwe-209]
---

This is one of the quickest labs in the series, but the lesson behind it is one of the most useful in real recon: a single badly-typed parameter can make an app hand you its exact framework version. It's a textbook case of [CWE-209](https://cwe.mitre.org/data/definitions/209.html) (Generation of Error Message Containing Sensitive Information).

## Overview

The shop loads each product by a numeric id:

```
GET /product?productId=1
```

The goal is simply to find out **what framework and version** the site runs, and submit it.

## Breaking the parser

That `productId` is parsed as an integer server-side. So give it something that isn't a number:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/product?productId=x'
```

Instead of a tidy error page, the response is `HTTP 500` with a full Java stack trace — and the very last line is the giveaway:

```
    at lab.server.s.a.t.b(Unknown Source)
    ...
    at java.base/java.lang.Thread.run(Thread.java:1583)

Apache Struts 2 2.3.31
```

There it is: **Apache Struts 2 2.3.31**.

## Solving

Submit that version string:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/submitSolution' \
  --data-urlencode 'answer=2.3.31'
# {"correct":true}
```

The lab banner flips to **Solved**.

## Why it worked

Two separate misconfigurations stack up:

1. **No type validation on input.** `productId=x` flows into `Integer.parseInt("x")`, which throws. A safe app would reject a non-numeric id with a controlled `400` before parsing anything.
2. **Debug error pages left on in production.** Struts' dev-mode handler serialises the entire exception — class names, stack frames, framework version — into the HTTP response. In production that should be a blank generic 500, with the detail logged server-side only.

On its own, a version string is low severity. But it's the bridge from passive recon to a targeted attack: `Apache Struts 2 2.3.31` is vulnerable to **CVE-2017-5638**, the infamous Content-Type OGNL remote-code-execution bug. The error page told an attacker exactly which exploit to load.

## The fix

```java
String raw = request.getParameter("productId");
if (raw == null || !raw.matches("\\d+")) { resp.sendError(400); return; }
Product p = repo.find(Integer.parseInt(raw));
```

And app-wide: turn off verbose errors in production (`struts.devMode=false`), return a generic 500 page, and log full exceptions only on the server where the client can't read them.

## Takeaway

When you map an app, probe **every typed parameter with a wrong-type value** — a non-integer where it wants an integer, an array where it wants a string. A verbose stack trace is one of the fastest ways to fingerprint a stack precisely, and precise fingerprinting is what turns "some Java app" into "Struts 2.3.31, fire CVE-2017-5638."
