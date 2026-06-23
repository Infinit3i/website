---
layout: post
title: "PortSwigger: Limit Overrun Race Conditions"
date: 2027-10-22 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, RaceConditions]
tags: [portswigger, race-condition, toctou, single-packet-attack, http2, business-logic, cwe-362]
---

A shop coupon is meant to be used once per order. But "once" is enforced by checking a flag and *then* setting it in a separate step — and between those two steps there is a window. Fire enough requests into that window and a single-use 20% coupon applies a dozen times over, dropping a $1337 jacket below a $50 store credit. This is [CWE-362](https://cwe.mitre.org/data/definitions/362.html), a race condition, and the practical key to winning it is the HTTP/2 single-packet attack.

## Overview

After logging in as `wiener:peter` you have **$50.00** store credit. The target item is the "Lightweight l33t leather jacket" (`productId=1`) priced at **$1337.00**. The homepage advertises a coupon, `PROMO20`, that takes 20% off the cart total. Applying it once is allowed; applying it a second time returns *"Coupon already applied."*

One coupon only takes the jacket to $1069.60 — nowhere near $50. The whole solve is forcing that single-use coupon to apply many times at once.

## Benchmarking the limit

Add the jacket and apply the coupon once, sequentially, to confirm the rule:

```
POST /cart           productId=1&redir=PRODUCT&quantity=1     -> total $1337.00
POST /cart/coupon    csrf=<csrf>&coupon=PROMO20               -> discount $267.40, total $1069.60
POST /cart/coupon    csrf=<csrf>&coupon=PROMO20               -> "Coupon already applied"
```

So the server reads the cart, checks *"is PROMO20 already applied?"*, and only then writes the discount and marks the coupon used. Those are two separate, non-atomic steps — a textbook time-of-check / time-of-use (TOCTOU) gap.

Note the discount **compounds**: each successful application multiplies the remaining total by 0.8. To get under $50 you need `0.8ⁿ × 1337 < 50`, i.e. about **15** applications.

## Why naive concurrency fails

The obvious approach — 30 threads, each firing the request on its own TLS connection — does not work. Every request comes back `302`, but the coupon applies exactly **once**. The TLS handshakes complete at slightly different moments, so the requests arrive spread out and the server processes them serially. The race window is never actually hit.

## The single-packet attack

The reliable technique uses **one** connection and HTTP/2 multiplexing:

1. Negotiate HTTP/2 (`h2` via ALPN) on a single TLS connection.
2. Open N streams, one per request.
3. Send each stream's headers and the whole body **except its final byte**.
4. Release every stream's last byte in a **single `sendall()`** — one TCP packet.

All N requests now complete at virtually the same instant, with no per-request handshake to desynchronize them. Many of them slip through the check-then-write window together.

Each stream is identical:

```
POST /cart/coupon HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=<session>

csrf=<csrf>&coupon=PROMO20
```

A small Python helper using the `h2` library implements steps 1–4. The number of wins scales sub-linearly with N because the window is a fixed size:

| N requests | resulting total | approx. wins |
|-----------:|----------------:|-------------:|
| 25  | $280.38 | ~7  |
| 60  | $91.87  | ~12 |
| 150 | **$37.62** | ~16 |

Reset the cart between attempts with `POST /cart/coupon/remove` (same csrf, `coupon=PROMO20`).

## Cashing out

With the total at **$37.62** — comfortably under the $50 credit — place the order:

```
POST /cart/checkout    csrf=<csrf>
-> 303  /cart/order-confirmation?order-confirmed=true
```

Store credit drops from $50.00 to $12.38, and the lab is marked **Solved**.

## The fix

Never enforce a once-only or quota rule with a separate read then write. Collapse the check and the mutation into a single atomic operation:

- One conditional statement where the `WHERE` clause *is* the guard, then check the affected-row count:
  `UPDATE cart SET discount = ... WHERE id = :id AND coupon_applied = 0`.
- A `UNIQUE` constraint on `(order, coupon)` so a duplicate redemption fails at the database.
- Or wrap the check and update in a serializable transaction / `SELECT ... FOR UPDATE` row lock.

Any of these closes the window so two concurrent requests can never both pass the guard.
