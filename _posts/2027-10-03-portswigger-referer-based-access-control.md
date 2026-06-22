---
layout: post
title: "PortSwigger: Referer-Based Access Control"
date: 2027-10-03 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, referer, privilege-escalation, cwe-639]
---

The earlier access-control labs broke by checking the wrong *component*, the wrong *verb*, or the wrong *step*. This one breaks by trusting the wrong *source of truth* entirely: it authorizes a privileged action from the `Referer` header — a value the attacker sets — instead of from the user's session. ([CWE-639](https://cwe.mitre.org/data/definitions/639.html), Authorization Bypass Through User-Controlled Key.)

## Overview

Two accounts: an admin (`administrator:admin`) and a low-privileged user (`wiener:peter`). The admin panel promotes users to administrator, and the goal is to escalate `wiener`.

## The admin action

Promoting a user is a simple GET request:

```
GET /admin-roles?username=carlos&action=upgrade
```

Because the admin panel is reached from the `/admin` page, the developer assumed any request to this endpoint that *came from* `/admin` must belong to an admin — and enforced that by checking the `Referer` header rather than the session role.

## The bypass

The `Referer` header is set by the client, so I can forge it. Logged in as `wiener:peter`, I send the upgrade request twice.

First with **no Referer** — correctly blocked:

```bash
curl -b "session=<wiener>" \
  "https://LAB/admin-roles?username=wiener&action=upgrade"
# → 401 Unauthorized
```

Then with a **forged admin Referer** — succeeds:

```bash
curl -b "session=<wiener>" -H "Referer: https://LAB/admin" \
  "https://LAB/admin-roles?username=wiener&action=upgrade"
# → 302 Found  (wiener is now an administrator)
```

The only difference between blocked and bypassed is one header I typed myself. That `401 → 302` flip is the whole vulnerability — and the lab is marked **Solved**.

## Why it works

Authorization must be a server-side decision about *who you are* (your authenticated session) and *what action you are taking*. Here it was outsourced to the `Referer` header, which the browser fills in to say where a request came from — and which any client can set to any value. It carries no proof of identity, so using it as a gate is the same as having no gate.

Notice this is the opposite direction from the CSRF labs that *validate* `Referer` as a defence: there the header is a (weak) brake on cross-site requests; here it *is* the access control. Both fail for the same reason — the header is attacker-controlled.

## Fix

- Authorize privileged actions from the authenticated session role, never from a request header.
- Treat `Referer`, `Origin`, and `X-Forwarded-*` as untrusted client input — they are trivially spoofed.
- Apply a default-deny access-control matrix to admin endpoints based on identity, not on where the request claims to originate.
