---
layout: post
title: "PortSwigger: URL-Based Access Control Can Be Circumvented"
date: 2027-09-29 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, x-original-url, x-rewrite-url, reverse-proxy, header-injection, cwe-284]
---

Most broken-access-control labs are about a check that's *missing* or a check that trusts *attacker data*. This one is different: the check is there, it's correct, and it's enforced — it's just enforced by the **wrong component**. The front-end proxy blocks `/admin`; the back-end app routes by a header the proxy never looks at. ([CWE-284](https://cwe.mitre.org/data/definitions/284.html), Improper Access Control.)

## Overview

No credentials. The admin panel is unauthenticated — the only thing stopping you is a front-end rule. The goal is to reach the admin panel and delete the user `carlos`.

## The setup

There are two pieces of infrastructure here:

- a **front-end** reverse proxy that decides what outside traffic is allowed to reach
- a **back-end** application that actually builds the pages

The front-end is told "deny `/admin`". Ask for it directly and it stonewalls you:

```
$ curl -sk "$U/admin"
"Access denied"
```

That `"Access denied"` is a flat string from the proxy — you never reached the app.

## The bug

The back-end framework supports a header called `X-Original-URL` (some stacks use `X-Rewrite-URL`). When present, the app routes the request to **that** path instead of the one on the request line. The proxy doesn't read that header — it only inspects the request line. So the two disagree about which URL the request is "for".

Prove the app honours the header by pointing it somewhere bogus. If the header chose the route, you get a *different* error — `Not Found` from the app, not `Access denied` from the proxy:

```
$ curl -sk "$U/" -H "X-Original-URL: /invalid"
"Not Found"
```

That confirms it: the request line said `/` (which the proxy allows), but the app resolved `/invalid` and 404'd. The header wins on the back-end.

## Exploitation

Point the header at the blocked path. The proxy sees `/` and waves it through; the app routes to `/admin` and serves the panel:

```
$ curl -sk "$U/" -H "X-Original-URL: /admin"
... admin panel HTML with wiener / carlos delete links ...
```

Now delete `carlos`. There's one detail that trips people up: the **query string stays on the real request line** — it does *not* go inside the header. The header carries only the path:

```
$ curl -sk "$U/?username=carlos" -H "X-Original-URL: /admin/delete" -o /dev/null -w "%{http_code}\n"
302
```

The `302` redirect is the success signal. The lab flipped to **Solved**, and `carlos` was gone from the user list (only `wiener` remained).

## Why it worked

The deny rule lives on a component that can only see the literal request line — and the attacker controls that line completely. You keep it "clean" (`/`, which is allowed) while smuggling the real target into a header that the proxy ignores but the application obeys. Access control was enforced on a *different URL* than the one the app actually served.

## The fix

- Enforce access control in the **application layer**, against the *effective resolved path* — not at a proxy that only inspects the raw request line.
- **Strip or ignore** `X-Original-URL` and `X-Rewrite-URL` at the edge, unless the component that resolves routing is the same one that enforces authorization.
- Keep one single source of truth for "which path is this" so the proxy and the app can never disagree.
- Deny by default in central middleware, so the authorization check runs no matter how the path was derived.
